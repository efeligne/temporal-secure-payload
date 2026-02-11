package securepayload_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	pb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"

	securepayload "github.com/efeligne/temporal-secure-payload"
)

const testKey = "0123456789abcdef0123456789abcdef"

const (
	errNewDataConverterFmt = "new data converter: %v"
	expectedTwoStrings     = 2
	jsonPlainEncoding      = "json/plain"
	jwtToken               = "token"
	jwtField               = "jwt"
	tokenField             = "token"
	authField              = "auth"
	errJWTMismatchFmt      = "jwt value: got %q, want %q"
	errMissingAuthField    = "missing auth field after decode"
	errAuthTypeFmt         = "auth type: got %T, want map[string]any"
	errMissingJWTField     = "missing jwt field after decode"
	errJWTTypeFmt          = "jwt type: got %T, want string"
	batchSizeMetadataKey   = "batch-size"
)

var errBatchSizeMismatch = errors.New("batch-size mismatch")

type (
	nilPayloadCodec struct{}
	batchSizeCodec  struct{}
)

type requestWithAuth struct {
	Auth any `json:"auth"`
}

type requestWithMixedFields struct {
	Auth  any    `json:"auth"`
	Name  string `json:"name"`
	inner string
}

type cyclicNode struct {
	Auth any
	Next *cyclicNode
}

type requestWithCustomMarshal struct {
	Auth  any
	token string
}

type requestWithPrivateSensitiveField struct {
	auth any
}

func (r requestWithCustomMarshal) MarshalJSON() ([]byte, error) {
	payload, err := json.Marshal(map[string]any{
		"auth":     r.Auth,
		tokenField: r.token,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal requestWithCustomMarshal: %w", err)
	}

	return payload, nil
}

func (r requestWithPrivateSensitiveField) MarshalJSON() ([]byte, error) {
	payload, err := json.Marshal(map[string]any{
		"auth": r.auth,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal requestWithPrivateSensitiveField: %w", err)
	}

	return payload, nil
}

func (*nilPayloadCodec) Encode(payloads []*pb.Payload) ([]*pb.Payload, error) {
	return payloads, nil
}

func (*nilPayloadCodec) Decode(payloads []*pb.Payload) ([]*pb.Payload, error) {
	return payloads, nil
}

func (*batchSizeCodec) Encode(payloads []*pb.Payload) ([]*pb.Payload, error) {
	batchSize := strconv.Itoa(len(payloads))
	for _, payload := range payloads {
		metadata := payload.GetMetadata()
		if metadata == nil {
			metadata = make(map[string][]byte)
		}

		metadata[batchSizeMetadataKey] = []byte(batchSize)
		payload.Metadata = metadata
	}

	return payloads, nil
}

func (*batchSizeCodec) Decode(payloads []*pb.Payload) ([]*pb.Payload, error) {
	batchSize := strconv.Itoa(len(payloads))
	for i, payload := range payloads {
		got := string(payload.GetMetadata()[batchSizeMetadataKey])
		if got != batchSize {
			return nil, fmt.Errorf(
				"%w for payload %d: got %q, want %q",
				errBatchSizeMismatch,
				i,
				got,
				batchSize,
			)
		}
	}

	return payloads, nil
}

func TestParseKey(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		value string
	}{
		{name: "raw", value: testKey},
		{name: "base64", value: base64.StdEncoding.EncodeToString([]byte(testKey))},
		{name: "hex", value: hex.EncodeToString([]byte(testKey))},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key, err := securepayload.ParseKey(testCase.value)
			if err != nil {
				t.Fatalf("parse key: %v", err)
			}

			if len(key) != 32 {
				t.Fatalf("key size: got %d, want 32", len(key))
			}
		})
	}
}

func TestCodec_LeavesPlainPayloadAsIs(t *testing.T) {
	t.Parallel()

	codec, err := securepayload.NewCodec(testKey)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	jsonConverter := converter.NewJSONPayloadConverter()

	plainPayload, err := jsonConverter.ToPayload(map[string]string{"a": "plain"})
	if err != nil {
		t.Fatalf("plain payload: %v", err)
	}

	encoded, err := codec.Encode([]*pb.Payload{plainPayload})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}

	gotEncoding := string(encoded[0].GetMetadata()[converter.MetadataEncoding])
	if gotEncoding != jsonPlainEncoding {
		t.Fatalf("plain payload encoding changed unexpectedly: %s", gotEncoding)
	}
}

func TestCodec_EncryptsAndDecryptsSensitivePayload(t *testing.T) {
	t.Parallel()

	codec, err := securepayload.NewCodec(testKey)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	jsonConverter := converter.NewJSONPayloadConverter()
	sensitivePayload := newSensitivePayload(t, jsonConverter)

	encoded, err := codec.Encode([]*pb.Payload{sensitivePayload})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}

	gotEncoding := string(encoded[0].GetMetadata()[converter.MetadataEncoding])
	if gotEncoding != securepayload.EncryptedEncoding {
		t.Fatal("sensitive payload was not encrypted")
	}

	decoded, err := codec.Decode(encoded)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var out map[string]string
	if err := jsonConverter.FromPayload(decoded[0], &out); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if out["a"] != "secret" {
		t.Fatalf("sensitive value: got %q, want %q", out["a"], "secret")
	}
}

func TestNewDataConverter_SensitiveWrapper(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	payload, err := dataConverter.ToPayload(
		securepayload.Sensitive(map[string]string{"jwt": "token"}),
	)
	if err != nil {
		t.Fatalf("to payload sensitive: %v", err)
	}

	if string(
		payload.GetMetadata()[converter.MetadataEncoding],
	) != securepayload.EncryptedEncoding {
		t.Fatal("sensitive wrapper should produce encrypted payload")
	}

	var out map[string]string
	if err := dataConverter.FromPayload(payload, &out); err != nil {
		t.Fatalf("from payload sensitive: %v", err)
	}

	if out["jwt"] != "token" {
		t.Fatalf("decoded payload mismatch: got %q", out["jwt"])
	}
}

func TestNewDataConverter_LeavesNonSensitiveValuesUnchanged(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	payload, err := dataConverter.ToPayload(map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("to payload plain: %v", err)
	}

	gotEncoding := string(payload.GetMetadata()[converter.MetadataEncoding])
	if gotEncoding != jsonPlainEncoding {
		t.Fatalf("plain payload encoding changed unexpectedly: %s", gotEncoding)
	}

	var out map[string]string
	if err := dataConverter.FromPayload(payload, &out); err != nil {
		t.Fatalf("from payload plain: %v", err)
	}

	if out["k"] != "v" {
		t.Fatalf("decoded plain payload mismatch: got %q", out["k"])
	}
}

func TestNewDataConverter_ToString_DecodesEncryptedPayload(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	payload, err := dataConverter.ToPayload(
		securepayload.Sensitive(map[string]string{"jwt": "token"}),
	)
	if err != nil {
		t.Fatalf("to payload sensitive: %v", err)
	}

	str := dataConverter.ToString(payload)
	if !strings.Contains(str, "token") {
		t.Fatalf("expected decoded string to contain token, got %q", str)
	}
}

func TestNewDataConverter_ToStrings_DecodesEncryptedPayloads(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	sensitivePayload, err := dataConverter.ToPayload(
		securepayload.Sensitive(map[string]string{"jwt": "token"}),
	)
	if err != nil {
		t.Fatalf("to payload sensitive: %v", err)
	}

	plainPayload, err := dataConverter.ToPayload(map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("to payload plain: %v", err)
	}

	strs := dataConverter.ToStrings(
		&pb.Payloads{Payloads: []*pb.Payload{sensitivePayload, plainPayload}},
	)
	if len(strs) != expectedTwoStrings {
		t.Fatalf("strings length: got %d, want %d", len(strs), expectedTwoStrings)
	}

	if !strings.Contains(strs[0], "token") {
		t.Fatalf("expected first payload string to contain token, got %q", strs[0])
	}

	if !strings.Contains(strs[1], "\"k\":\"v\"") {
		t.Fatalf("expected second payload string to contain plain JSON, got %q", strs[1])
	}
}

func TestNewDataConverter_NestedSensitiveValue_IsPreservedAndEncrypted(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	payload, err := dataConverter.ToPayload(map[string]any{
		"requestId": "abc-123",
		authField: securepayload.Sensitive(map[string]string{
			"jwt": jwtToken,
		}),
	})
	if err != nil {
		t.Fatalf("to payload nested sensitive: %v", err)
	}

	gotEncoding := string(payload.GetMetadata()[converter.MetadataEncoding])
	if gotEncoding != securepayload.EncryptedEncoding {
		t.Fatalf("nested sensitive payload should be encrypted, got %s", gotEncoding)
	}

	var out map[string]any
	if err := dataConverter.FromPayload(payload, &out); err != nil {
		t.Fatalf("from payload nested sensitive: %v", err)
	}

	authRaw, ok := out[authField]
	if !ok {
		t.Fatal(errMissingAuthField)
	}

	auth, ok := authRaw.(map[string]any)
	if !ok {
		t.Fatalf(errAuthTypeFmt, authRaw)
	}

	jwtRaw, ok := auth["jwt"]
	if !ok {
		t.Fatal(errMissingJWTField)
	}

	jwt, ok := jwtRaw.(string)
	if !ok {
		t.Fatalf(errJWTTypeFmt, jwtRaw)
	}

	if jwt != jwtToken {
		t.Fatalf("jwt value: got %q, want %q", jwt, jwtToken)
	}
}

func TestNewDataConverter_StructFieldSensitive_IsPreservedAndEncrypted(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	payload, err := dataConverter.ToPayload(requestWithAuth{
		Auth: securepayload.Sensitive(map[string]string{"jwt": jwtToken}),
	})
	if err != nil {
		t.Fatalf("to payload struct sensitive: %v", err)
	}

	gotEncoding := string(payload.GetMetadata()[converter.MetadataEncoding])
	if gotEncoding != securepayload.EncryptedEncoding {
		t.Fatalf("struct sensitive payload should be encrypted, got %s", gotEncoding)
	}

	var out map[string]any
	if err := dataConverter.FromPayload(payload, &out); err != nil {
		t.Fatalf("from payload struct sensitive: %v", err)
	}

	authRaw, ok := out[authField]
	if !ok {
		t.Fatal(errMissingAuthField)
	}

	auth, ok := authRaw.(map[string]any)
	if !ok {
		t.Fatalf(errAuthTypeFmt, authRaw)
	}

	jwtRaw, ok := auth["jwt"]
	if !ok {
		t.Fatal(errMissingJWTField)
	}

	jwt, ok := jwtRaw.(string)
	if !ok {
		t.Fatalf(errJWTTypeFmt, jwtRaw)
	}

	if jwt != jwtToken {
		t.Fatalf("jwt value: got %q, want %q", jwt, jwtToken)
	}
}

func TestNewDataConverter_StructWithUnexportedField_StaysSensitive(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	payload, err := dataConverter.ToPayload(requestWithMixedFields{
		Auth:  securepayload.Sensitive(map[string]string{"jwt": jwtToken}),
		Name:  "req",
		inner: "private",
	})
	if err != nil {
		t.Fatalf("to payload mixed struct sensitive: %v", err)
	}

	gotEncoding := string(payload.GetMetadata()[converter.MetadataEncoding])
	if gotEncoding != securepayload.EncryptedEncoding {
		t.Fatalf("mixed struct sensitive payload should be encrypted, got %s", gotEncoding)
	}
}

func TestNewDataConverter_CustomMarshalWithUnexportedField_IsPreserved(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	payload, err := dataConverter.ToPayload(requestWithCustomMarshal{
		Auth:  securepayload.Sensitive(map[string]string{"jwt": jwtToken}),
		token: jwtToken,
	})
	if err != nil {
		t.Fatalf("to payload custom marshal sensitive: %v", err)
	}

	gotEncoding := string(payload.GetMetadata()[converter.MetadataEncoding])
	if gotEncoding != securepayload.EncryptedEncoding {
		t.Fatalf("custom marshal payload should be encrypted, got %s", gotEncoding)
	}

	var out map[string]any
	if err := dataConverter.FromPayload(payload, &out); err != nil {
		t.Fatalf("from payload custom marshal sensitive: %v", err)
	}

	privateRaw, ok := out[tokenField]
	if !ok {
		t.Fatal("missing token field after decode")
	}

	privateToken, ok := privateRaw.(string)
	if !ok {
		t.Fatalf("token type: got %T, want string", privateRaw)
	}

	if privateToken != jwtToken {
		t.Fatalf("token value: got %q, want %q", privateToken, jwtToken)
	}
}

func TestNewDataConverter_PrivateSensitiveField_IsDetectedAndEncrypted(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	payload, err := dataConverter.ToPayload(requestWithPrivateSensitiveField{
		auth: securepayload.Sensitive(map[string]string{jwtField: jwtToken}),
	})
	if err != nil {
		t.Fatalf("to payload private sensitive field: %v", err)
	}

	gotEncoding := string(payload.GetMetadata()[converter.MetadataEncoding])
	if gotEncoding != securepayload.EncryptedEncoding {
		t.Fatalf("private sensitive field payload should be encrypted, got %s", gotEncoding)
	}

	var out map[string]any
	if err := dataConverter.FromPayload(payload, &out); err != nil {
		t.Fatalf("from payload private sensitive field: %v", err)
	}

	authRaw, ok := out[authField]
	if !ok {
		t.Fatal(errMissingAuthField)
	}

	auth, ok := authRaw.(map[string]any)
	if !ok {
		t.Fatalf(errAuthTypeFmt, authRaw)
	}

	jwtRaw, ok := auth[jwtField]
	if !ok {
		t.Fatal(errMissingJWTField)
	}

	jwt, ok := jwtRaw.(string)
	if !ok {
		t.Fatalf(errJWTTypeFmt, jwtRaw)
	}

	if jwt != jwtToken {
		t.Fatalf(errJWTMismatchFmt, jwt, jwtToken)
	}
}

func TestNewDataConverter_CyclicValue_DoesNotPanic(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	node := &cyclicNode{
		Auth: securepayload.Sensitive(map[string]string{"jwt": jwtToken}),
	}
	node.Next = node

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("ToPayload panicked on cyclic input: %v", recovered)
		}
	}()

	_, err = dataConverter.ToPayload(node)
	if err == nil {
		t.Fatal("expected serialization error for cyclic input")
	}
}

func TestNewDataConverter_DoubleSensitiveWrapper_IsPreservedAndEncrypted(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	payload, err := dataConverter.ToPayload(
		securepayload.Sensitive(
			securepayload.Sensitive(map[string]string{"jwt": jwtToken}),
		),
	)
	if err != nil {
		t.Fatalf("to payload double sensitive: %v", err)
	}

	gotEncoding := string(payload.GetMetadata()[converter.MetadataEncoding])
	if gotEncoding != securepayload.EncryptedEncoding {
		t.Fatalf("double sensitive payload should be encrypted, got %s", gotEncoding)
	}

	var out map[string]string
	if err := dataConverter.FromPayload(payload, &out); err != nil {
		t.Fatalf("from payload double sensitive: %v", err)
	}

	if out[jwtField] != jwtToken {
		t.Fatalf(errJWTMismatchFmt, out[jwtField], jwtToken)
	}
}

func TestNewDataConverter_TopLevelSensitiveWithNestedWrapper_IsPreservedAndEncrypted(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	payload, err := dataConverter.ToPayload(
		securepayload.Sensitive(map[string]any{
			authField: securepayload.Sensitive(map[string]string{"jwt": jwtToken}),
		}),
	)
	if err != nil {
		t.Fatalf("to payload top-level sensitive with nested wrapper: %v", err)
	}

	gotEncoding := string(payload.GetMetadata()[converter.MetadataEncoding])
	if gotEncoding != securepayload.EncryptedEncoding {
		t.Fatalf("payload should be encrypted, got %s", gotEncoding)
	}

	var out map[string]any
	if err := dataConverter.FromPayload(payload, &out); err != nil {
		t.Fatalf("from payload top-level sensitive with nested wrapper: %v", err)
	}

	authRaw, ok := out[authField]
	if !ok {
		t.Fatal(errMissingAuthField)
	}

	auth, ok := authRaw.(map[string]any)
	if !ok {
		t.Fatalf(errAuthTypeFmt, authRaw)
	}

	jwtRaw, ok := auth[jwtField]
	if !ok {
		t.Fatal(errMissingJWTField)
	}

	jwt, ok := jwtRaw.(string)
	if !ok {
		t.Fatalf(errJWTTypeFmt, jwtRaw)
	}

	if jwt != jwtToken {
		t.Fatalf(errJWTMismatchFmt, jwt, jwtToken)
	}
}

func TestSensitive_DefaultConverterDoesNotSerializeToEmptyObject(t *testing.T) {
	t.Parallel()

	defaultConverter := converter.GetDefaultDataConverter()

	payload, err := defaultConverter.ToPayload(securepayload.Sensitive("Bearer token-value"))
	if err != nil {
		t.Fatalf("default converter ToPayload: %v", err)
	}

	encoding := string(payload.GetMetadata()[converter.MetadataEncoding])
	if encoding != jsonPlainEncoding {
		t.Fatalf("payload encoding: got %q, want %q", encoding, jsonPlainEncoding)
	}

	var decoded string
	if err := defaultConverter.FromPayload(payload, &decoded); err != nil {
		t.Fatalf("default converter FromPayload: %v", err)
	}

	if decoded != "Bearer token-value" {
		t.Fatalf("decoded value: got %q, want %q", decoded, "Bearer token-value")
	}
}

func TestNewDataConverterWithCodec_NilCodec_ReturnsError(t *testing.T) {
	t.Parallel()

	dataConverter := securepayload.NewDataConverterWithCodec(nil)

	_, err := dataConverter.ToPayload("plain")
	if err == nil {
		t.Fatal("expected error for nil payload codec")
	}
}

func TestNewDataConverterWithCodec_TypedNilCodec_ReturnsError(t *testing.T) {
	t.Parallel()

	var typedNilCodec *nilPayloadCodec

	dataConverter := securepayload.NewDataConverterWithCodec(typedNilCodec)

	_, err := dataConverter.ToPayload("plain")
	if err == nil {
		t.Fatal("expected error for typed-nil payload codec")
	}
}

func TestNewDataConverterWithCodec_ToPayloads_UsesBatchEncoding(t *testing.T) {
	t.Parallel()

	dataConverter := securepayload.NewDataConverterWithCodec(&batchSizeCodec{})

	payloads, err := dataConverter.ToPayloads("first", "second")
	if err != nil {
		t.Fatalf("ToPayloads failed: %v", err)
	}

	if payloads == nil || len(payloads.GetPayloads()) != expectedTwoStrings {
		t.Fatalf("payloads len: got %d, want %d", len(payloads.GetPayloads()), expectedTwoStrings)
	}

	var first, second string
	if err := dataConverter.FromPayloads(payloads, &first, &second); err != nil {
		t.Fatalf("FromPayloads failed: %v", err)
	}

	if first != "first" || second != "second" {
		t.Fatalf("decoded values: got (%q, %q)", first, second)
	}
}

func TestNewDataConverter_ToPayloads_ZeroArgsReturnsNilPayloads(t *testing.T) {
	t.Parallel()

	dataConverter, err := securepayload.NewDataConverter(testKey)
	if err != nil {
		t.Fatalf(errNewDataConverterFmt, err)
	}

	payloads, err := dataConverter.ToPayloads()
	if err != nil {
		t.Fatalf("ToPayloads zero args failed: %v", err)
	}

	if payloads != nil {
		t.Fatalf("expected nil payloads for zero args, got %#v", payloads)
	}
}

func newSensitivePayload(
	t *testing.T,
	jsonConverter converter.PayloadConverter,
) *pb.Payload {
	t.Helper()

	payload, err := jsonConverter.ToPayload(map[string]string{"a": "secret"})
	if err != nil {
		t.Fatalf("sensitive payload: %v", err)
	}

	if payload.Metadata == nil {
		payload.Metadata = map[string][]byte{}
	}

	payload.Metadata[securepayload.MetadataSensitive] = []byte("1")

	return payload
}
