package securepayload

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"unsafe"

	pb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
)

type sensitiveValue struct {
	value any
}

// MarshalJSON preserves wrapped value when the default JSON payload converter is used
// (e.g. Temporal SDK memo serialization paths that bypass custom DataConverter).
func (s sensitiveValue) MarshalJSON() ([]byte, error) {
	payload, err := json.Marshal(s.value)
	if err != nil {
		return nil, fmt.Errorf("marshal sensitiveValue: %w", err)
	}

	return payload, nil
}

var (
	errDecodedPayloadCount = errors.New("expected exactly one decoded payload")
	errNilPayloadCodec     = errors.New("payload codec is nil")
)

// Sensitive wraps a value so converter marks it as encryptable payload.
func Sensitive(v any) any {
	return sensitiveValue{value: v}
}

// NewDataConverter creates Temporal DataConverter with selective encryption codec.
func NewDataConverter(key string) (converter.DataConverter, error) {
	payloadCodec, err := NewCodec(key)
	if err != nil {
		return nil, err
	}

	return NewDataConverterWithCodec(payloadCodec), nil
}

// NewDataConverterWithCodec creates Temporal DataConverter with injected codec.
func NewDataConverterWithCodec(payloadCodec PayloadCodec) converter.DataConverter {
	base := converter.NewCompositeDataConverter(
		converter.NewNilPayloadConverter(),
		converter.NewByteSlicePayloadConverter(),
		converter.NewProtoJSONPayloadConverter(),
		converter.NewProtoPayloadConverter(),
		converter.NewJSONPayloadConverter(),
	)

	return &selectiveDataConverter{
		base:  base,
		codec: payloadCodec,
	}
}

type selectiveDataConverter struct {
	base  converter.DataConverter
	codec PayloadCodec
}

func (d *selectiveDataConverter) ToPayload(value any) (*pb.Payload, error) {
	payloadCodec, err := codecOrErr(d.codec)
	if err != nil {
		return nil, err
	}

	rawValue, isSensitive := unwrapSensitiveDeep(value)

	payload, err := d.base.ToPayload(rawValue)
	if err != nil {
		return nil, fmt.Errorf("base ToPayload: %w", err)
	}

	if isSensitive {
		markSensitivePayload(payload)
	}

	encoded, err := payloadCodec.Encode([]*pb.Payload{payload})
	if err != nil {
		return nil, fmt.Errorf("codec Encode single payload: %w", err)
	}

	if len(encoded) != 1 {
		return nil, fmt.Errorf("%w: got %d", errDecodedPayloadCount, len(encoded))
	}

	return encoded[0], nil
}

func (d *selectiveDataConverter) FromPayload(payload *pb.Payload, valuePtr any) error {
	payloadCodec, err := codecOrErr(d.codec)
	if err != nil {
		return err
	}

	decoded, err := payloadCodec.Decode([]*pb.Payload{payload})
	if err != nil {
		return fmt.Errorf("codec Decode single payload: %w", err)
	}

	if len(decoded) != 1 {
		return fmt.Errorf("%w: got %d", errDecodedPayloadCount, len(decoded))
	}

	if err := d.base.FromPayload(decoded[0], valuePtr); err != nil {
		return fmt.Errorf("base FromPayload: %w", err)
	}

	return nil
}

func (d *selectiveDataConverter) ToPayloads(values ...any) (*pb.Payloads, error) {
	payloadCodec, err := codecOrErr(d.codec)
	if err != nil {
		return nil, err
	}

	rawValues := make([]any, len(values))

	sensitiveFlags := make([]bool, len(values))
	for i, value := range values {
		rawValue, isSensitive := unwrapSensitiveDeep(value)
		rawValues[i] = rawValue
		sensitiveFlags[i] = isSensitive
	}

	payloads, err := d.base.ToPayloads(rawValues...)
	if err != nil {
		return nil, fmt.Errorf("base ToPayloads: %w", err)
	}

	if payloads == nil {
		return payloads, nil
	}

	for i := range payloads.GetPayloads() {
		if i < len(sensitiveFlags) && sensitiveFlags[i] {
			markSensitivePayload(payloads.GetPayloads()[i])
		}
	}

	encoded, err := payloadCodec.Encode(payloads.GetPayloads())
	if err != nil {
		return nil, fmt.Errorf("codec Encode payloads: %w", err)
	}

	return &pb.Payloads{Payloads: encoded}, nil
}

func (d *selectiveDataConverter) FromPayloads(payloads *pb.Payloads, valuePtrs ...any) error {
	payloadCodec, err := codecOrErr(d.codec)
	if err != nil {
		return err
	}

	if payloads == nil {
		if err := d.base.FromPayloads(payloads, valuePtrs...); err != nil {
			return fmt.Errorf("base FromPayloads nil payloads: %w", err)
		}

		return nil
	}

	decoded, err := payloadCodec.Decode(payloads.GetPayloads())
	if err != nil {
		return fmt.Errorf("codec Decode payloads: %w", err)
	}

	if err := d.base.FromPayloads(&pb.Payloads{Payloads: decoded}, valuePtrs...); err != nil {
		return fmt.Errorf("base FromPayloads: %w", err)
	}

	return nil
}

func (d *selectiveDataConverter) ToString(payload *pb.Payload) string {
	if payload == nil {
		return ""
	}

	payloadCodec, err := codecOrErr(d.codec)
	if err != nil {
		return err.Error()
	}

	decodedPayloads, err := payloadCodec.Decode([]*pb.Payload{payload})
	if err != nil {
		return err.Error()
	}

	if len(decodedPayloads) != 1 {
		return fmt.Errorf("%w: got %d", errDecodedPayloadCount, len(decodedPayloads)).Error()
	}

	return d.base.ToString(decodedPayloads[0])
}

func (d *selectiveDataConverter) ToStrings(payloads *pb.Payloads) []string {
	if payloads == nil {
		return nil
	}

	result := make([]string, len(payloads.GetPayloads()))
	for i, payload := range payloads.GetPayloads() {
		result[i] = d.ToString(payload)
	}

	return result
}

func markSensitivePayload(payload *pb.Payload) {
	metadata := payload.GetMetadata()
	if metadata == nil {
		metadata = make(map[string][]byte)
	}

	metadata[MetadataSensitive] = []byte("1")
	payload.Metadata = metadata
}

func unwrapSensitive(value any) (any, bool) {
	switch typed := value.(type) {
	case sensitiveValue:
		return typed.value, true
	case *sensitiveValue:
		if typed == nil {
			return nil, false
		}

		return typed.value, true
	default:
		return value, false
	}
}

func unwrapSensitiveDeep(value any) (any, bool) {
	state := &unwrapState{
		active: make(map[unwrapVisitKey]int),
	}

	return unwrapSensitiveValue(reflect.ValueOf(value), state)
}

func unwrapSensitiveValue(value reflect.Value, state *unwrapState) (any, bool) {
	if !value.IsValid() {
		return nil, false
	}

	if unwrapped, found := unwrapSensitiveByType(value, state); found {
		return unwrapped, true
	}

	if unwrapped, ok := unwrapSensitiveViaInterface(value, state); ok {
		return unwrapped, true
	}

	kind := value.Kind()
	if kind == reflect.Interface {
		return unwrapSensitiveInInterface(value, state)
	}

	if kind == reflect.Pointer {
		return unwrapSensitiveInPointer(value, state)
	}

	if kind == reflect.Map {
		return unwrapSensitiveInMap(value, state)
	}

	if kind == reflect.Slice {
		return unwrapSensitiveInSlice(value, state)
	}

	if kind == reflect.Array {
		return unwrapSensitiveInArray(value, state)
	}

	if kind == reflect.Struct {
		return unwrapSensitiveInStruct(value, state)
	}

	return originalOrZero(value), false
}

func unwrapSensitiveByType(value reflect.Value, state *unwrapState) (any, bool) {
	if value.Type() != sensitiveValueReflectType() {
		return nil, false
	}

	wrappedAny, ok := valueAsAny(value)
	if !ok {
		return nil, true
	}

	unwrapped, found := unwrapSensitive(wrappedAny)
	if !found {
		return nil, false
	}

	if unwrapped == nil {
		return nil, true
	}

	nested, _ := unwrapSensitiveValue(reflect.ValueOf(unwrapped), state)

	return nested, true
}

func sensitiveValueReflectType() reflect.Type {
	return reflect.TypeFor[sensitiveValue]()
}

func unwrapSensitiveViaInterface(value reflect.Value, state *unwrapState) (any, bool) {
	if !value.CanInterface() {
		return nil, false
	}

	unwrapped, found := unwrapSensitive(value.Interface())
	if !found {
		return nil, false
	}

	// Continue recursively to remove nested Sensitive(...) wrappers as well.
	nestedUnwrapped, _ := unwrapSensitiveValue(reflect.ValueOf(unwrapped), state)

	return nestedUnwrapped, true
}

func unwrapSensitiveInInterface(value reflect.Value, state *unwrapState) (any, bool) {
	if value.IsNil() {
		return value.Interface(), false
	}

	if interfaceValue, ok := valueAsAny(value); ok {
		unwrapped, found := unwrapSensitiveValue(reflect.ValueOf(interfaceValue), state)
		if found {
			return unwrapped, true
		}
	}

	unwrapped, found := unwrapSensitiveValue(value.Elem(), state)
	if !found {
		return originalOrZero(value), false
	}

	return unwrapped, true
}

func unwrapSensitiveInPointer(value reflect.Value, state *unwrapState) (any, bool) {
	if value.IsNil() {
		return value.Interface(), false
	}

	if !state.enter(value) {
		return value.Interface(), false
	}
	defer state.leave(value)

	unwrapped, found := unwrapSensitiveValue(value.Elem(), state)
	if !found {
		return value.Interface(), false
	}

	pointerCopy := reflect.New(value.Type().Elem())
	setReflectValue(pointerCopy.Elem(), reflect.ValueOf(unwrapped))

	return pointerCopy.Interface(), true
}

func unwrapSensitiveInMap(value reflect.Value, state *unwrapState) (any, bool) {
	if value.IsNil() {
		return value.Interface(), false
	}

	if !state.enter(value) {
		return value.Interface(), false
	}
	defer state.leave(value)

	mapCopy := reflect.MakeMapWithSize(value.Type(), value.Len())
	foundAny := false

	iter := value.MapRange()
	for iter.Next() {
		mapKey := iter.Key()
		mapValue := iter.Value()

		unwrapped, found := unwrapSensitiveValue(mapValue, state)
		if found {
			foundAny = true
		}

		setMapValue(mapCopy, mapKey, reflect.ValueOf(unwrapped))
	}

	if !foundAny {
		return value.Interface(), false
	}

	return mapCopy.Interface(), true
}

func unwrapSensitiveInSlice(value reflect.Value, state *unwrapState) (any, bool) {
	if value.IsNil() {
		return value.Interface(), false
	}

	if !state.enter(value) {
		return value.Interface(), false
	}
	defer state.leave(value)

	sliceCopy := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
	foundAny := false

	for i := range value.Len() {
		unwrapped, found := unwrapSensitiveValue(value.Index(i), state)
		if found {
			foundAny = true
		}

		setReflectValue(sliceCopy.Index(i), reflect.ValueOf(unwrapped))
	}

	if !foundAny {
		return value.Interface(), false
	}

	return sliceCopy.Interface(), true
}

func unwrapSensitiveInArray(value reflect.Value, state *unwrapState) (any, bool) {
	arrayCopy := reflect.New(value.Type()).Elem()
	foundAny := false

	for i := range value.Len() {
		unwrapped, found := unwrapSensitiveValue(value.Index(i), state)
		if found {
			foundAny = true
		}

		setReflectValue(arrayCopy.Index(i), reflect.ValueOf(unwrapped))
	}

	if !foundAny {
		return value.Interface(), false
	}

	return arrayCopy.Interface(), true
}

func unwrapSensitiveInStruct(value reflect.Value, state *unwrapState) (any, bool) {
	structCopy := reflect.New(value.Type()).Elem()
	structCopy.Set(value)

	foundAny := false

	for i := range value.NumField() {
		originalField := value.Field(i)
		targetField := structCopy.Field(i)

		if !targetField.CanSet() {
			unwrapped, found := unwrapSensitiveValue(targetField, state)
			if found {
				foundAny = true

				forceSetReflectValue(targetField, reflect.ValueOf(unwrapped))
			}

			continue
		}

		unwrapped, found := unwrapSensitiveValue(originalField, state)
		if found {
			foundAny = true
		}

		setReflectValue(targetField, reflect.ValueOf(unwrapped))
	}

	if !foundAny {
		return value.Interface(), false
	}

	return structCopy.Interface(), true
}

func forceSetReflectValue(target, value reflect.Value) bool {
	if !target.CanAddr() {
		return false
	}

	writable := reflect.NewAt(target.Type(), unsafe.Pointer(target.UnsafeAddr())).Elem()
	setReflectValue(writable, value)

	return true
}

func originalOrZero(value reflect.Value) any {
	if anyValue, ok := valueAsAny(value); ok {
		return anyValue
	}

	return reflect.Zero(value.Type()).Interface()
}

type unwrapState struct {
	active map[unwrapVisitKey]int
}

type unwrapVisitKey struct {
	typ reflect.Type
	ptr uintptr
}

func (s *unwrapState) enter(value reflect.Value) bool {
	key, ok := visitKey(value)
	if !ok {
		return true
	}

	if s.active[key] > 0 {
		return false
	}

	s.active[key] = 1

	return true
}

func (s *unwrapState) leave(value reflect.Value) {
	key, ok := visitKey(value)
	if !ok {
		return
	}

	delete(s.active, key)
}

func visitKey(value reflect.Value) (unwrapVisitKey, bool) {
	kind := value.Kind()
	if kind != reflect.Pointer && kind != reflect.Map && kind != reflect.Slice {
		return unwrapVisitKey{}, false
	}

	if value.IsNil() {
		return unwrapVisitKey{}, false
	}

	if kind == reflect.Slice && value.Len() == 0 {
		return unwrapVisitKey{}, false
	}

	ptr := value.Pointer()
	if ptr == 0 {
		return unwrapVisitKey{}, false
	}

	return unwrapVisitKey{
		typ: value.Type(),
		ptr: ptr,
	}, true
}

func setMapValue(targetMap, key, value reflect.Value) {
	mapValueType := targetMap.Type().Elem()
	if converted, ok := convertAssignableValue(value, mapValueType); ok {
		targetMap.SetMapIndex(key, converted)
		return
	}

	targetMap.SetMapIndex(key, reflect.Zero(mapValueType))
}

func setReflectValue(target, value reflect.Value) {
	if converted, ok := convertAssignableValue(value, target.Type()); ok {
		target.Set(converted)
		return
	}

	target.Set(reflect.Zero(target.Type()))
}

func convertAssignableValue(value reflect.Value, targetType reflect.Type) (reflect.Value, bool) {
	if !value.IsValid() {
		return reflect.Zero(targetType), true
	}

	if anyValue, ok := valueAsAny(value); ok {
		value = reflect.ValueOf(anyValue)
	}

	if value.Type().AssignableTo(targetType) {
		return value, true
	}

	if value.Type().ConvertibleTo(targetType) {
		return value.Convert(targetType), true
	}

	return reflect.Value{}, false
}

func valueAsAny(value reflect.Value) (any, bool) {
	if !value.IsValid() {
		return nil, true
	}

	if value.CanInterface() {
		return value.Interface(), true
	}

	if !value.CanAddr() {
		return nil, false
	}

	return reflect.NewAt(value.Type(), unsafe.Pointer(value.UnsafeAddr())).Elem().Interface(), true
}

func codecOrErr(payloadCodec PayloadCodec) (PayloadCodec, error) {
	if isNilPayloadCodec(payloadCodec) {
		return nil, errNilPayloadCodec
	}

	return payloadCodec, nil
}

func isNilPayloadCodec(payloadCodec PayloadCodec) bool {
	if payloadCodec == nil {
		return true
	}

	value := reflect.ValueOf(payloadCodec)
	kind := value.Kind()
	nilable := kind == reflect.Chan ||
		kind == reflect.Func ||
		kind == reflect.Interface ||
		kind == reflect.Map ||
		kind == reflect.Pointer ||
		kind == reflect.Slice

	return nilable && value.IsNil()
}
