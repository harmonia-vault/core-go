package cryptox

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	idPattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	namePattern         = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	ErrInvalidWire      = errors.New("invalid Harmonia v1 wire value")
	ErrInvalidSignature = errors.New("invalid Ed25519 signature")
)

const MaxValueBytes = 65536

// Mutation 的签名字节独立于其传输 JSON 对象的序列化。
type Mutation struct {
	AccountID         string `json:"accountId"`
	AccountGeneration string `json:"accountGeneration"`
	DeviceID          string `json:"deviceId"`
	EnvironmentID     string `json:"environmentId"`
	KeyVersion        string `json:"keyVersion"`
	GrantGeneration   string `json:"grantGeneration"`
	Operation         string `json:"operation"`
	IdempotencyKey    string `json:"idempotencyKey"`
	Name              string `json:"name"`
	Payload           string `json:"payload"`
}

type SignedMutation struct {
	Mutation
	Signature string `json:"signature"`
}

// Grant 固定两种独立设备公钥和完整 HPKE 封套。
// none 撤销访问；ExpiresAt 为 Unix 秒，0 表示直到撤销。
type Grant struct {
	AccountID                 string `json:"accountId"`
	AccountGeneration         string `json:"accountGeneration"`
	IssuerDeviceID            string `json:"issuerDeviceId"`
	SubjectDeviceID           string `json:"subjectDeviceId"`
	SubjectSigningPublicKey   string `json:"subjectSigningPublicKey"`
	SubjectReceivingPublicKey string `json:"subjectReceivingPublicKey"`
	EnvironmentID             string `json:"environmentId"`
	KeyVersion                string `json:"keyVersion"`
	GrantGeneration           string `json:"grantGeneration"`
	Role                      string `json:"role"`
	ExpiresAt                 string `json:"expiresAt"`
	IdempotencyKey            string `json:"idempotencyKey"`
	Envelope                  string `json:"envelope"`
}

type SignedGrant struct {
	Grant
	Signature string `json:"signature"`
}

func validName(value string) bool {
	return namePattern.MatchString(value) && !strings.HasPrefix(strings.ToUpper(value), "__HARMONIA_")
}

func validID(value string) error {
	if !idPattern.MatchString(value) {
		return ErrInvalidWire
	}
	return nil
}

func validDecimal(value string, positive bool) error {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != value || (positive && n == 0) {
		return ErrInvalidWire
	}
	return nil
}

// DecodeBase64 拒绝非规范别名、padding 和非零尾位。
func DecodeBase64(value string, min, max int) ([]byte, error) {
	if len(value) > (max*4+2)/3 {
		return nil, ErrInvalidWire
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(b) < min || len(b) > max || base64.RawURLEncoding.EncodeToString(b) != value {
		return nil, ErrInvalidWire
	}
	return b, nil
}

func EncodeBase64(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func canonical(fields ...string) []byte {
	// 仅经验证的 ASCII 字符串进入编码器，Go 与 JSON.stringify
	// 生成相同紧凑字节和转义形式。
	b, _ := json.Marshal(fields)
	return b
}

func (m Mutation) SigningBytes() ([]byte, error) {
	for _, value := range []string{m.AccountID, m.DeviceID, m.EnvironmentID, m.IdempotencyKey} {
		if err := validID(value); err != nil {
			return nil, err
		}
	}
	for _, value := range []string{m.AccountGeneration, m.KeyVersion, m.GrantGeneration} {
		if err := validDecimal(value, true); err != nil {
			return nil, err
		}
	}
	if !validName(m.Name) {
		return nil, ErrInvalidWire
	}
	switch m.Operation {
	case "put":
		if _, err := DecodeBase64(m.Payload, 40, MaxValueBytes+40); err != nil {
			return nil, err
		}
	case "delete":
		if m.Payload != "" {
			return nil, ErrInvalidWire
		}
	default:
		return nil, ErrInvalidWire
	}
	return canonical("harmonia/mutation/v1", m.AccountID, m.AccountGeneration, m.DeviceID, m.EnvironmentID, m.KeyVersion, m.GrantGeneration, m.Operation, m.IdempotencyKey, m.Name, m.Payload), nil
}

func (g Grant) SigningBytes() ([]byte, error) {
	for _, value := range []string{g.AccountID, g.IssuerDeviceID, g.SubjectDeviceID, g.EnvironmentID, g.IdempotencyKey} {
		if err := validID(value); err != nil {
			return nil, err
		}
	}
	for _, value := range []string{g.AccountGeneration, g.KeyVersion, g.GrantGeneration} {
		if err := validDecimal(value, true); err != nil {
			return nil, err
		}
	}
	if err := validDecimal(g.ExpiresAt, false); err != nil {
		return nil, err
	}
	for _, value := range []string{g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey} {
		if _, err := DecodeBase64(value, 32, 32); err != nil {
			return nil, err
		}
	}
	switch g.Role {
	case "ro", "rw", "admin":
		if _, err := DecodeBase64(g.Envelope, 80, 80); err != nil {
			return nil, err
		}
	case "none":
		if g.Envelope != "" {
			return nil, ErrInvalidWire
		}
	default:
		return nil, ErrInvalidWire
	}
	return canonical("harmonia/grant/v1", g.AccountID, g.AccountGeneration, g.IssuerDeviceID, g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey, g.EnvironmentID, g.KeyVersion, g.GrantGeneration, g.Role, g.ExpiresAt, g.IdempotencyKey, g.Envelope), nil
}

func sign(key ed25519.PrivateKey, message []byte) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("private key: %w", ErrInvalidWire)
	}
	return EncodeBase64(ed25519.Sign(key, message)), nil
}

func verify(key ed25519.PublicKey, message []byte, signature string) error {
	if len(key) != ed25519.PublicKeySize {
		return ErrInvalidWire
	}
	sig, err := DecodeBase64(signature, ed25519.SignatureSize, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, message, sig) {
		return ErrInvalidSignature
	}
	return nil
}

func SignMutation(m Mutation, key ed25519.PrivateKey) (SignedMutation, error) {
	b, err := m.SigningBytes()
	if err != nil {
		return SignedMutation{}, err
	}
	sig, err := sign(key, b)
	return SignedMutation{m, sig}, err
}

func VerifyMutation(m SignedMutation, trustedDeviceKey ed25519.PublicKey) error {
	b, err := m.Mutation.SigningBytes()
	if err != nil {
		return err
	}
	return verify(trustedDeviceKey, b, m.Signature)
}

func SignGrant(g Grant, key ed25519.PrivateKey) (SignedGrant, error) {
	b, err := g.SigningBytes()
	if err != nil {
		return SignedGrant{}, err
	}
	sig, err := sign(key, b)
	return SignedGrant{g, sig}, err
}

func VerifyGrant(g SignedGrant, trustedIssuerKey ed25519.PublicKey) error {
	b, err := g.Grant.SigningBytes()
	if err != nil {
		return err
	}
	return verify(trustedIssuerKey, b, g.Signature)
}
