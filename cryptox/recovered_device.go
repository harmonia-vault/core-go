package cryptox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"strconv"
	"time"
)

// RecoveredDeviceEnrollment 仅绑定用户明确选择的环境权限，不替换原 Root。
type RecoveredDeviceEnrollment struct {
	AccountID                string `json:"accountId"`
	AccountGeneration        string `json:"accountGeneration"`
	RecoveryGeneration       string `json:"recoveryGeneration"`
	RecoveryTransitionHash   string `json:"recoveryTransitionHash"`
	OperationID              string `json:"operationId"`
	ChallengeID              string `json:"challengeId"`
	Nonce                    string `json:"nonce"`
	ExpiresAt                string `json:"expiresAt"`
	RestrictedSessionHash    string `json:"restrictedSessionHash"`
	ExpectedSequence         string `json:"expectedSequence"`
	DeviceID                 string `json:"deviceId"`
	DeviceSigningPublicKey   string `json:"deviceSigningPublicKey"`
	DeviceReceivingPublicKey string `json:"deviceReceivingPublicKey"`
	SelectedRightsHash       string `json:"selectedRightsHash"`
	GrantsHash               string `json:"grantsHash"`
	IssuerEvidenceHash       string `json:"issuerEvidenceHash"`
	EnvelopesHash            string `json:"envelopesHash"`
}
type RecoveredDeviceRight struct {
	EnvironmentID string `json:"environmentId"`
	KeyVersion    string `json:"keyVersion"`
	Role          string `json:"role"`
	ExpiresAt     string `json:"expiresAt"`
}
type RecoveredDeviceSubmission struct {
	CertificateVersion string                    `json:"certificateVersion"`
	Capabilities       []string                  `json:"capabilities"`
	Enrollment         RecoveredDeviceEnrollment `json:"enrollment"`
	SelectedRights     []RecoveredDeviceRight    `json:"selectedRights"`
	Grants             []SignedGrantWire         `json:"grants"`
	IssuerEvidence     IssuerProofV2             `json:"issuerEvidence"`
	Envelopes          []RecoveryEnvelope        `json:"envelopes"`
	RecoverySignature  string                    `json:"recoverySignature"`
	DeviceSignature    string                    `json:"deviceSignature"`
}
type AcceptedRecoveredDevice struct {
	Submission RecoveredDeviceSubmission `json:"submission"`
	Sequence   uint64                    `json:"sequence"`
}

func (c RecoveredDeviceEnrollment) SigningBytes() ([]byte, error) {
	for _, id := range []string{c.AccountID, c.OperationID, c.ChallengeID, c.DeviceID} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	for _, n := range []string{c.AccountGeneration, c.RecoveryGeneration, c.ExpiresAt} {
		if validDecimal(n, true) != nil {
			return nil, ErrInvalidWire
		}
	}
	if validDecimal(c.ExpectedSequence, false) != nil {
		return nil, ErrInvalidWire
	}
	n, _ := strconv.ParseUint(c.ExpectedSequence, 10, 64)
	expiry, _ := strconv.ParseUint(c.ExpiresAt, 10, 64)
	if n >= 9007199254740991 || expiry > math.MaxInt64 {
		return nil, ErrInvalidWire
	}
	if validatePublicPair(c.DeviceSigningPublicKey, c.DeviceReceivingPublicKey) != nil {
		return nil, ErrInvalidWire
	}
	if _, err := DecodeBase64(c.Nonce, 32, 32); err != nil {
		return nil, err
	}
	for _, h := range []string{c.RecoveryTransitionHash, c.RestrictedSessionHash, c.SelectedRightsHash, c.GrantsHash, c.IssuerEvidenceHash, c.EnvelopesHash} {
		if !tokenHashPattern.MatchString(h) {
			return nil, ErrInvalidWire
		}
	}
	return canonical("harmonia/recovered-device-enrollment/v1", c.AccountID, c.AccountGeneration, c.RecoveryGeneration, c.RecoveryTransitionHash, c.OperationID, c.ChallengeID, c.Nonce, c.ExpiresAt, c.RestrictedSessionHash, c.ExpectedSequence, c.DeviceID, c.DeviceSigningPublicKey, c.DeviceReceivingPublicKey, c.SelectedRightsHash, c.GrantsHash, c.IssuerEvidenceHash, c.EnvelopesHash), nil
}
func RecoveredDeviceRightsHash(rows []RecoveredDeviceRight) (string, error) {
	if rows == nil || len(rows) < 1 || len(rows) > 256 {
		return "", ErrInvalidWire
	}
	items := make([][]string, 0, len(rows))
	for i, r := range rows {
		n, e := strconv.ParseUint(r.ExpiresAt, 10, 64)
		if validID(r.EnvironmentID) != nil || validDecimal(r.KeyVersion, true) != nil || validDecimal(r.ExpiresAt, false) != nil || e != nil || n > math.MaxInt64 || i > 0 && rows[i-1].EnvironmentID >= r.EnvironmentID || r.Role != "ro" && r.Role != "rw" && r.Role != "admin" {
			return "", ErrInvalidWire
		}
		items = append(items, []string{r.EnvironmentID, r.KeyVersion, r.Role, r.ExpiresAt})
	}
	return hashCanonical([]any{"harmonia/recovered-device-rights/v1", items})
}
func RecoveredDeviceGrantsHash(rows []SignedGrantWire) (string, error) {
	if rows == nil || len(rows) < 1 || len(rows) > 256 {
		return "", ErrInvalidWire
	}
	items := make([][]string, 0, len(rows))
	for i, r := range rows {
		if i > 0 && rows[i-1].Grant.EnvironmentID >= r.Grant.EnvironmentID {
			return "", ErrInvalidWire
		}
		b, e := r.Grant.SigningBytes()
		if e != nil {
			return "", e
		}
		if _, e = DecodeBase64(r.Signature, 64, 64); e != nil {
			return "", e
		}
		items = append(items, []string{r.Grant.EnvironmentID, EncodeBase64(b), r.Signature})
	}
	return hashCanonical([]any{"harmonia/recovered-device-grants/v1", items})
}
func RecoveredDeviceEnvelopesHash(rows []RecoveryEnvelope) (string, error) {
	if _, e := RecoveryTransitionEnvelopesHash(rows); e != nil {
		return "", e
	}
	items := make([][]string, 0, len(rows))
	for _, r := range rows {
		items = append(items, []string{r.EnvironmentID, r.KeyVersion, r.Envelope})
	}
	return hashCanonical([]any{"harmonia/recovered-device-envelopes/v1", items})
}
func RecoveredDeviceReferenceHash(s RecoveredDeviceSubmission) (string, error) {
	b, e := s.Enrollment.SigningBytes()
	if e != nil {
		return "", e
	}
	for _, sig := range []string{s.RecoverySignature, s.DeviceSignature} {
		if _, e = DecodeBase64(sig, 64, 64); e != nil {
			return "", e
		}
	}
	return hashCanonical([]string{"harmonia/recovered-device-enrollment-ref/v1", EncodeBase64(b), s.RecoverySignature, s.DeviceSignature})
}
func (v *VerifiedRecoveryAuthority) validateRecoveredDevice(s RecoveredDeviceSubmission, now *time.Time) (*VerifiedIssuerProofV2, error) {
	if v == nil || len(v.operations) == 0 || s.CertificateVersion != "4" || len(s.Capabilities) != 1 || s.Capabilities[0] != RecoveryAuthorityCapability {
		return nil, ErrInvalidWire
	}
	c := s.Enrollment
	if _, e := c.SigningBytes(); e != nil {
		return nil, e
	}
	if c.AccountID != v.pin.AccountID || c.AccountGeneration != v.pin.AccountGeneration || c.RecoveryGeneration != v.recoveryGeneration || c.RecoveryTransitionHash != v.head {
		return nil, ErrInvalidSignature
	}
	expected, _ := strconv.ParseUint(c.ExpectedSequence, 10, 64)
	if expected < v.sequence {
		return nil, ErrInvalidWire
	}
	if now != nil {
		if e := ValidateRecoveryChallenge(c.ExpiresAt, *now); e != nil {
			return nil, e
		}
	}
	h, e := RecoveredDeviceRightsHash(s.SelectedRights)
	if e != nil || h != c.SelectedRightsHash {
		return nil, ErrInvalidSignature
	}
	h, e = RecoveredDeviceGrantsHash(s.Grants)
	if e != nil || h != c.GrantsHash {
		return nil, ErrInvalidSignature
	}
	h, e = RecoveredDeviceEnvelopesHash(s.Envelopes)
	if e != nil || h != c.EnvelopesHash || len(s.SelectedRights) != len(s.Grants) || len(s.Envelopes) != len(s.Grants) {
		return nil, ErrInvalidSignature
	}
	h, e = RecoveryIssuerEvidenceHash(s.IssuerEvidence)
	if e != nil || h != c.IssuerEvidenceHash {
		return nil, ErrInvalidSignature
	}
	r := s.IssuerEvidence.TrustRoot
	if r.RecoveryGeneration != v.recoveryGeneration || r.RecoverySigningPublicKey != v.signingPublic || r.RecoveryReceivingPublicKey != v.receivingPublic {
		return nil, ErrInvalidSignature
	}
	p, e := VerifyIssuerEvidenceV2(v.pin, s.IssuerEvidence, v.initial...)
	if e != nil {
		return nil, e
	}
	if _, known := p.identities[c.DeviceID]; known {
		return nil, ErrInvalidSignature
	}
	for _, identity := range p.identities {
		for _, pub := range []string{c.DeviceSigningPublicKey, c.DeviceReceivingPublicKey} {
			if pub == identity.signing || pub == identity.receiving {
				return nil, ErrInvalidSignature
			}
		}
	}
	for _, pub := range []string{c.DeviceSigningPublicKey, c.DeviceReceivingPublicKey} {
		if pub == v.signingPublic || pub == v.receivingPublic {
			return nil, ErrInvalidSignature
		}
	}
	key, e := DecodeBase64(c.DeviceSigningPublicKey, 32, 32)
	if e != nil {
		return nil, e
	}
	for i, row := range s.SelectedRights {
		g := s.Grants[i].Grant
		envelope := s.Envelopes[i]
		if g.AccountID != c.AccountID || g.AccountGeneration != c.AccountGeneration || g.IssuerDeviceID != c.DeviceID || g.SubjectDeviceID != c.DeviceID || g.SubjectSigningPublicKey != c.DeviceSigningPublicKey || g.SubjectReceivingPublicKey != c.DeviceReceivingPublicKey || g.EnvironmentID != row.EnvironmentID || g.KeyVersion != row.KeyVersion || g.Role != row.Role || g.ExpiresAt != row.ExpiresAt || g.GrantGeneration != "1" || envelope.EnvironmentID != row.EnvironmentID || envelope.KeyVersion != row.KeyVersion || envelope.Envelope != g.Envelope {
			return nil, ErrInvalidSignature
		}
		if e = VerifyGrant(s.Grants[i].SignedGrant(), key); e != nil {
			return nil, e
		}
		target, exists := p.targets[row.EnvironmentID]
		source, known := p.Authority(target)
		if !exists || !known || source.Grant.EnvironmentID != row.EnvironmentID || source.Grant.KeyVersion != row.KeyVersion {
			return nil, ErrInvalidSignature
		}
		expiry, _ := strconv.ParseInt(row.ExpiresAt, 10, 64)
		if now != nil && expiry != 0 && expiry <= now.Unix() {
			return nil, ErrInvalidSignature
		}
	}
	encoded, e := json.Marshal(s)
	if e != nil || len(encoded) > MaxRecoveryAuthorityBytes {
		return nil, ErrInvalidWire
	}
	return p, nil
}
func SignRecoveredDeviceByRecovery(v *VerifiedRecoveryAuthority, s RecoveredDeviceSubmission, key ed25519.PrivateKey, now time.Time) (string, error) {
	if _, e := v.validateRecoveredDevice(s, &now); e != nil {
		return "", e
	}
	b, e := s.Enrollment.SigningBytes()
	if e != nil {
		return "", e
	}
	return signRecoveryPurpose(key, v.signingPublic, b)
}

// SignRecoveredDeviceAfterHPKE 验证全部选定封套后才用独立设备签名钥签名。
// 环境钥只为确认而临时解开并尽力清除，不返回、不写入缓存或改变设备信任。
func SignRecoveredDeviceAfterHPKE(v *VerifiedRecoveryAuthority, s RecoveredDeviceSubmission, key ed25519.PrivateKey, receivingPrivate []byte, now time.Time) (string, error) {
	if _, e := v.validateRecoveredDevice(s, &now); e != nil {
		return "", e
	}
	c := s.Enrollment
	receiving, e := ecdh.X25519().NewPrivateKey(receivingPrivate)
	if e != nil || EncodeBase64(receiving.PublicKey().Bytes()) != c.DeviceReceivingPublicKey {
		return "", ErrInvalidSignature
	}
	b, e := c.SigningBytes()
	if e != nil {
		return "", e
	}
	// 设备先验证已授权恢复方签名，再作 HPKE 持钥确认和自己的 countersign。
	recoveryPublic, e := DecodeBase64(v.signingPublic, 32, 32)
	if e != nil {
		return "", e
	}
	if e = verify(recoveryPublic, b, s.RecoverySignature); e != nil {
		return "", e
	}
	for _, signed := range s.Grants {
		g := signed.Grant
		packet, e := DecodeBase64(g.Envelope, 80, 80)
		if e != nil {
			return "", e
		}
		environmentKey, e := UnwrapEnvironmentKey(receivingPrivate, EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey}, packet)
		if e != nil {
			return "", e
		}
		clear(environmentKey)
	}
	return signRecoveryPurpose(key, c.DeviceSigningPublicKey, b)
}

// VerifiedRecoveredDevice 提供对应环境的历史授权来源，不包含 Active 或全局 Root。
type VerifiedRecoveredDevice struct {
	deviceID, signingPublic, receivingPublic, referenceHash string
	grants                                                  map[string]SignedGrantWire
}

func VerifyAcceptedRecoveredDevice(v *VerifiedRecoveryAuthority, r AcceptedRecoveredDevice) (*VerifiedRecoveredDevice, error) {
	s := r.Submission
	if _, e := v.validateRecoveredDevice(s, nil); e != nil {
		return nil, e
	}
	c := s.Enrollment
	expected, _ := strconv.ParseUint(c.ExpectedSequence, 10, 64)
	if r.Sequence != expected+1 {
		return nil, ErrInvalidWire
	}
	b, e := c.SigningBytes()
	if e != nil {
		return nil, e
	}
	for _, pair := range []struct{ public, signature string }{{v.signingPublic, s.RecoverySignature}, {c.DeviceSigningPublicKey, s.DeviceSignature}} {
		pub, e := DecodeBase64(pair.public, 32, 32)
		if e != nil {
			return nil, e
		}
		if e = verify(pub, b, pair.signature); e != nil {
			return nil, e
		}
	}
	h, e := RecoveredDeviceReferenceHash(s)
	if e != nil {
		return nil, e
	}
	grants := map[string]SignedGrantWire{}
	for _, g := range s.Grants {
		gh, e := IssuerAuthorityHash(g)
		if e != nil {
			return nil, e
		}
		grants[gh] = g
	}
	return &VerifiedRecoveredDevice{deviceID: c.DeviceID, signingPublic: c.DeviceSigningPublicKey, receivingPublic: c.DeviceReceivingPublicKey, referenceHash: h, grants: grants}, nil
}
func (v *VerifiedRecoveredDevice) ReferenceHash() string {
	if v == nil {
		return ""
	}
	return v.referenceHash
}
func (v *VerifiedRecoveredDevice) VerifySourceGrant(s SignedGrantWire) error {
	if v == nil {
		return ErrInvalidWire
	}
	h, e := IssuerAuthorityHash(s)
	if e != nil {
		return e
	}
	if _, ok := v.grants[h]; !ok {
		return ErrInvalidSignature
	}
	return nil
}
func DecodeRecoveredDeviceSubmission(data []byte) (RecoveredDeviceSubmission, error) {
	var s RecoveredDeviceSubmission
	if e := validateRecoveryJSONShape(data, reflect.TypeOf(s), nil); e != nil {
		return s, e
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(&s); e != nil {
		return s, e
	}
	var rest any
	if e := d.Decode(&rest); e != io.EOF {
		return s, ErrInvalidWire
	}
	if s.CertificateVersion != "4" || len(s.Capabilities) != 1 || s.Capabilities[0] != RecoveryAuthorityCapability || s.SelectedRights == nil || s.Grants == nil || s.Envelopes == nil {
		return s, ErrInvalidWire
	}
	_, e := s.Enrollment.SigningBytes()
	return s, e
}
