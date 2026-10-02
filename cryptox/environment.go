package cryptox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"golang.org/x/crypto/chacha20poly1305"
	"sort"
	"strconv"
)

// 环境对象操作绑定当前管理授权、账号检查点、全部封套与重加密清单。
// LabelPayload 是端到端密文；不得放明文环境名称。
type EnvironmentChange struct {
	AccountID                string               `json:"accountId"`
	AccountGeneration        string               `json:"accountGeneration"`
	DeviceID                 string               `json:"deviceId"`
	EnvironmentID            string               `json:"environmentId"`
	Operation                string               `json:"operation"`
	AuthorityEnvironmentID   string               `json:"authorityEnvironmentId"`
	AuthorityKeyVersion      string               `json:"authorityKeyVersion"`
	AuthorityGrantGeneration string               `json:"authorityGrantGeneration"`
	PreviousKeyVersion       string               `json:"previousKeyVersion"`
	KeyVersion               string               `json:"keyVersion"`
	ExpectedSequence         string               `json:"expectedSequence"`
	IdempotencyKey           string               `json:"idempotencyKey"`
	LabelPayload             string               `json:"labelPayload"`
	RecoveryGeneration       string               `json:"recoveryGeneration"`
	RecoveryEnvelope         string               `json:"recoveryEnvelope"`
	Grants                   []SignedGrantWire    `json:"grants"`
	Mutations                []SignedMutationWire `json:"mutations"`
}

type SignedMutationWire struct {
	Mutation  Mutation `json:"mutation"`
	Signature string   `json:"signature"`
}

func MutationToWire(m SignedMutation) SignedMutationWire {
	return SignedMutationWire{m.Mutation, m.Signature}
}
func (m SignedMutationWire) SignedMutation() SignedMutation {
	return SignedMutation{m.Mutation, m.Signature}
}

type SignedEnvironmentChange struct {
	Change    EnvironmentChange `json:"change"`
	Signature string            `json:"signature"`
}

func EnvironmentGrantsHash(grants []SignedGrantWire) (string, error) {
	if len(grants) > 256 {
		return "", ErrInvalidWire
	}
	ordered := append([]SignedGrantWire(nil), grants...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Grant.SubjectDeviceID < ordered[j].Grant.SubjectDeviceID })
	items := make([][]string, 0, len(ordered))
	for i, g := range ordered {
		if i > 0 && ordered[i-1].Grant.SubjectDeviceID == g.Grant.SubjectDeviceID {
			return "", ErrInvalidWire
		}
		encoded, err := g.Grant.SigningBytes()
		if err != nil {
			return "", err
		}
		if _, err := DecodeBase64(g.Signature, 64, 64); err != nil {
			return "", err
		}
		items = append(items, []string{g.Grant.SubjectDeviceID, EncodeBase64(encoded), g.Signature})
	}
	return hashCanonical(items)
}
func EnvironmentMutationsHash(mutations []SignedMutationWire) (string, error) {
	if len(mutations) > 1024 {
		return "", ErrInvalidWire
	}
	ordered := append([]SignedMutationWire(nil), mutations...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Mutation.Name < ordered[j].Mutation.Name })
	items := make([][]string, 0, len(ordered))
	for i, m := range ordered {
		if i > 0 && ordered[i-1].Mutation.Name == m.Mutation.Name {
			return "", ErrInvalidWire
		}
		encoded, err := m.Mutation.SigningBytes()
		if err != nil {
			return "", err
		}
		if _, err := DecodeBase64(m.Signature, 64, 64); err != nil {
			return "", err
		}
		items = append(items, []string{m.Mutation.Name, EncodeBase64(encoded), m.Signature})
	}
	return hashCanonical(items)
}
func (c EnvironmentChange) SigningBytes() ([]byte, error) {
	for _, id := range []string{c.AccountID, c.DeviceID, c.EnvironmentID, c.AuthorityEnvironmentID, c.IdempotencyKey} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	for _, n := range []string{c.AccountGeneration, c.AuthorityKeyVersion, c.AuthorityGrantGeneration, c.KeyVersion, c.RecoveryGeneration} {
		if validDecimal(n, true) != nil {
			return nil, ErrInvalidWire
		}
	}
	if validDecimal(c.PreviousKeyVersion, false) != nil || validDecimal(c.ExpectedSequence, false) != nil {
		return nil, ErrInvalidWire
	}
	checkpoint, _ := strconv.ParseUint(c.ExpectedSequence, 10, 64)
	if checkpoint > 9007199254740991 {
		return nil, ErrInvalidWire
	}
	minimum := 40
	switch c.Operation {
	case "create", "rename":
	case "delete", "rotate":
		if c.LabelPayload == "" {
			minimum = 0
		}
	default:
		return nil, ErrInvalidWire
	}
	if _, err := DecodeBase64(c.LabelPayload, minimum, MaxValueBytes+40); err != nil {
		return nil, err
	}
	if c.Operation == "create" || c.Operation == "rotate" {
		if _, err := DecodeBase64(c.RecoveryEnvelope, 80, 80); err != nil {
			return nil, err
		}
	} else if c.RecoveryEnvelope != "" {
		return nil, ErrInvalidWire
	}
	if (c.Operation == "rename" || c.Operation == "delete") && (len(c.Grants) > 0 || len(c.Mutations) > 0) {
		return nil, ErrInvalidWire
	}
	grantsHash, err := EnvironmentGrantsHash(c.Grants)
	if err != nil {
		return nil, err
	}
	mutationsHash, err := EnvironmentMutationsHash(c.Mutations)
	if err != nil {
		return nil, err
	}
	return canonical("harmonia/environment-change/v1", c.AccountID, c.AccountGeneration, c.DeviceID, c.EnvironmentID, c.Operation, c.AuthorityEnvironmentID, c.AuthorityKeyVersion, c.AuthorityGrantGeneration, c.PreviousKeyVersion, c.KeyVersion, c.ExpectedSequence, c.IdempotencyKey, c.LabelPayload, c.RecoveryGeneration, c.RecoveryEnvelope, grantsHash, mutationsHash), nil
}
func SignEnvironmentChange(c EnvironmentChange, key ed25519.PrivateKey) (SignedEnvironmentChange, error) {
	b, err := c.SigningBytes()
	if err != nil {
		return SignedEnvironmentChange{}, err
	}
	signature, err := sign(key, b)
	return SignedEnvironmentChange{c, signature}, err
}
func VerifyEnvironmentChange(c SignedEnvironmentChange, key ed25519.PublicKey) error {
	b, err := c.Change.SigningBytes()
	if err != nil {
		return err
	}
	return verify(key, b, c.Signature)
}

type RevocationAuthority struct {
	EnvironmentID   string `json:"environmentId"`
	KeyVersion      string `json:"keyVersion"`
	GrantGeneration string `json:"grantGeneration"`
}
type DeviceRevocation struct {
	AccountID                 string                `json:"accountId"`
	AccountGeneration         string                `json:"accountGeneration"`
	DeviceID                  string                `json:"deviceId"`
	SubjectDeviceID           string                `json:"subjectDeviceId"`
	SubjectSigningPublicKey   string                `json:"subjectSigningPublicKey"`
	SubjectReceivingPublicKey string                `json:"subjectReceivingPublicKey"`
	IdempotencyKey            string                `json:"idempotencyKey"`
	ChallengeID               string                `json:"challengeId"`
	SessionHash               string                `json:"sessionHash"`
	Nonce                     string                `json:"nonce"`
	ExpiresAt                 string                `json:"expiresAt"`
	Authorities               []RevocationAuthority `json:"authorities"`
}
type SignedDeviceRevocation struct {
	Revocation DeviceRevocation `json:"revocation"`
	Signature  string           `json:"signature"`
}

func RevocationAuthorityHash(authorities []RevocationAuthority) (string, error) {
	if len(authorities) == 0 || len(authorities) > 256 {
		return "", ErrInvalidWire
	}
	ordered := append([]RevocationAuthority(nil), authorities...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].EnvironmentID < ordered[j].EnvironmentID })
	items := make([][]string, 0, len(ordered))
	for i, a := range ordered {
		if validID(a.EnvironmentID) != nil || validDecimal(a.KeyVersion, true) != nil || validDecimal(a.GrantGeneration, true) != nil || (i > 0 && ordered[i-1].EnvironmentID == a.EnvironmentID) {
			return "", ErrInvalidWire
		}
		items = append(items, []string{a.EnvironmentID, a.KeyVersion, a.GrantGeneration})
	}
	return hashCanonical(items)
}
func (r DeviceRevocation) SigningBytes() ([]byte, error) {
	for _, id := range []string{r.AccountID, r.DeviceID, r.SubjectDeviceID, r.IdempotencyKey, r.ChallengeID} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	if validDecimal(r.AccountGeneration, true) != nil || validDecimal(r.ExpiresAt, true) != nil || !tokenHashPattern.MatchString(r.SessionHash) {
		return nil, ErrInvalidWire
	}
	for _, v := range []string{r.SubjectSigningPublicKey, r.SubjectReceivingPublicKey, r.Nonce} {
		if _, err := DecodeBase64(v, 32, 32); err != nil {
			return nil, err
		}
	}
	hash, err := RevocationAuthorityHash(r.Authorities)
	if err != nil {
		return nil, err
	}
	return canonical("harmonia/device-revocation/v1", r.AccountID, r.AccountGeneration, r.DeviceID, r.SubjectDeviceID, r.SubjectSigningPublicKey, r.SubjectReceivingPublicKey, r.IdempotencyKey, r.ChallengeID, r.SessionHash, r.Nonce, r.ExpiresAt, hash), nil
}
func SignDeviceRevocation(r DeviceRevocation, key ed25519.PrivateKey) (SignedDeviceRevocation, error) {
	b, err := r.SigningBytes()
	if err != nil {
		return SignedDeviceRevocation{}, err
	}
	signature, err := sign(key, b)
	return SignedDeviceRevocation{r, signature}, err
}
func VerifyDeviceRevocation(r SignedDeviceRevocation, key ed25519.PublicKey) error {
	b, err := r.Revocation.SigningBytes()
	if err != nil {
		return err
	}
	return verify(key, b, r.Signature)
}

// HTTP 清单始终为数组；空清单不编码为 JSON null。
func (c EnvironmentChange) MarshalJSON() ([]byte, error) {
	type plain EnvironmentChange
	if c.Grants == nil {
		c.Grants = []SignedGrantWire{}
	}
	if c.Mutations == nil {
		c.Mutations = []SignedMutationWire{}
	}
	return json.Marshal(plain(c))
}

type EnvironmentLabelContext struct{ AccountID, AccountGeneration, EnvironmentID, KeyVersion string }

func (c EnvironmentLabelContext) AssociatedData() ([]byte, error) {
	if validID(c.AccountID) != nil || validID(c.EnvironmentID) != nil || validDecimal(c.AccountGeneration, true) != nil || validDecimal(c.KeyVersion, true) != nil {
		return nil, ErrInvalidWire
	}
	return canonical("harmonia/environment-label/v1", c.AccountID, c.AccountGeneration, c.EnvironmentID, c.KeyVersion), nil
}

// 环境名称与变量值使用不同的附加数据域，避免把一类密文换入另一类。
func EncryptEnvironmentLabel(key []byte, c EnvironmentLabelContext, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxValueBytes {
		return nil, ErrInvalidWire
	}
	ad, err := c.AssociatedData()
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	packet := append([]byte(nil), nonce...)
	return aead.Seal(packet, nonce, plaintext, ad), nil
}
func DecryptEnvironmentLabel(key []byte, c EnvironmentLabelContext, packet []byte) ([]byte, error) {
	if len(packet) < 40 || len(packet) > MaxValueBytes+40 {
		return nil, ErrInvalidWire
	}
	ad, err := c.AssociatedData()
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, packet[:24], packet[24:], ad)
}
