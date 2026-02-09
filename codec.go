package securepayload

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	pb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"google.golang.org/protobuf/proto"
)

const (
	// MetadataSensitive marks payloads that should be encrypted by the codec.
	MetadataSensitive = "temporal-sensitive"

	// EncryptedEncoding is used as payload encoding for encrypted blobs.
	EncryptedEncoding = "binary/temporal-secure-payload-encrypted"

	encryptionKeySize = 32
)

var (
	errMissingKey        = errors.New("encryption key is required")
	errInvalidKey        = errors.New("encryption key must be 32-byte raw, base64, or hex")
	errPayloadTooShort   = errors.New("encrypted payload is too short")
	errPayloadMarshal    = errors.New("marshal payload")
	errPayloadUnmarshal  = errors.New("unmarshal payload")
	errDecryptPayload    = errors.New("decrypt payload")
	errBuildAES          = errors.New("build aes cipher")
	errBuildAESGCM       = errors.New("build aes-gcm")
	errReadEncryptNonce  = errors.New("read encryption nonce")
	errCreateKeyMaterial = errors.New("parse encryption key")
)

// PayloadCodec describes selective payload encryption/decryption behavior.
type PayloadCodec interface {
	Encode(payloads []*pb.Payload) ([]*pb.Payload, error)
	Decode(payloads []*pb.Payload) ([]*pb.Payload, error)
}

type codec struct {
	aead cipher.AEAD
}

// NewCodec creates selective payload codec.
func NewCodec(key string) (PayloadCodec, error) {
	keyBytes, err := ParseKey(key)
	if err != nil {
		return nil, errors.Join(errCreateKeyMaterial, err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, errors.Join(errBuildAES, err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Join(errBuildAESGCM, err)
	}

	return &codec{aead: aead}, nil
}

// Encode encrypts marked payloads.
func (c *codec) Encode(payloads []*pb.Payload) ([]*pb.Payload, error) {
	result := make([]*pb.Payload, len(payloads))
	for i, payload := range payloads {
		encrypted, err := c.encodeOne(payload)
		if err != nil {
			return payloads, err
		}

		result[i] = encrypted
	}

	return result, nil
}

// Decode decrypts payloads encoded with EncryptedEncoding.
func (c *codec) Decode(payloads []*pb.Payload) ([]*pb.Payload, error) {
	result := make([]*pb.Payload, len(payloads))
	for i, payload := range payloads {
		decrypted, err := c.decodeOne(payload)
		if err != nil {
			return payloads, err
		}

		result[i] = decrypted
	}

	return result, nil
}

func (c *codec) encodeOne(payload *pb.Payload) (*pb.Payload, error) {
	if payload == nil || !isSensitive(payload) {
		return payload, nil
	}

	raw, err := proto.Marshal(payload)
	if err != nil {
		return nil, errors.Join(errPayloadMarshal, err)
	}

	sealed, err := c.encrypt(raw)
	if err != nil {
		return nil, err
	}

	return &pb.Payload{
		Metadata: map[string][]byte{
			converter.MetadataEncoding: []byte(EncryptedEncoding),
		},
		Data: sealed,
	}, nil
}

func (c *codec) decodeOne(payload *pb.Payload) (*pb.Payload, error) {
	if payload == nil ||
		string(payload.GetMetadata()[converter.MetadataEncoding]) != EncryptedEncoding {
		return payload, nil
	}

	opened, err := c.decrypt(payload.GetData())
	if err != nil {
		return nil, err
	}

	original := &pb.Payload{}
	if err := proto.Unmarshal(opened, original); err != nil {
		return nil, errors.Join(errPayloadUnmarshal, err)
	}

	return original, nil
}

func (c *codec) encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Join(errReadEncryptNonce, err)
	}

	sealed := c.aead.Seal(nil, nonce, data, nil)

	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)

	return out, nil
}

func (c *codec) decrypt(payload []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(payload) < nonceSize {
		return nil, errPayloadTooShort
	}

	nonce := payload[:nonceSize]
	cipherText := payload[nonceSize:]

	opened, err := c.aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, errors.Join(errDecryptPayload, err)
	}

	return opened, nil
}

func isSensitive(payload *pb.Payload) bool {
	flag := bytes.TrimSpace(payload.GetMetadata()[MetadataSensitive])
	return bytes.Equal(flag, []byte("1")) || bytes.Equal(bytes.ToLower(flag), []byte("true"))
}

// ParseKey supports 32-byte raw, base64 and hex key formats.
func ParseKey(key string) ([]byte, error) {
	if key == "" {
		return nil, errMissingKey
	}

	if len(key) == encryptionKeySize {
		return []byte(key), nil
	}

	if decoded, err := base64.StdEncoding.DecodeString(
		key,
	); err == nil &&
		len(decoded) == encryptionKeySize {
		return decoded, nil
	}

	if decoded, err := base64.RawStdEncoding.DecodeString(
		key,
	); err == nil &&
		len(decoded) == encryptionKeySize {
		return decoded, nil
	}

	if decoded, err := hex.DecodeString(key); err == nil && len(decoded) == encryptionKeySize {
		return decoded, nil
	}

	return nil, fmt.Errorf("%w: got length=%d", errInvalidKey, len(key))
}
