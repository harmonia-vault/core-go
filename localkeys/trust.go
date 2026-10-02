package localkeys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const EnrollmentPairingProfile = "boringssl-spake2-edwards25519-draft02-v1"
const maxEnrollmentCertificate = 64 << 10
const maxEnrollmentCertificateV2 = (256 << 10) + 512

var identityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// TrustContext 是经过入网控制器验证后保存的绑定资料，不包含私钥。
// Accepted 只记录服务器完成状态；本包不验配对/证书签名，不授予设备信任。
type TrustContext struct {
	Endpoint              string            `json:"endpoint"`
	AccountID             string            `json:"accountId"`
	AccountGeneration     uint64            `json:"accountGeneration"`
	DeviceID              string            `json:"deviceId"`
	SigningPublic         []byte            `json:"signingPublic"`
	ReceivingPublic       []byte            `json:"receivingPublic"`
	Managers              map[string][]byte `json:"managers"`
	CertificateVersion    string            `json:"certificateVersion,omitempty"`
	PairingProfile        string            `json:"pairingProfile"`
	EnrollmentCertificate json.RawMessage   `json:"enrollmentCertificate"`
	EnrollmentKey         string            `json:"enrollmentKey"`
	Accepted              bool              `json:"accepted"`
}

func validEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.ContainsAny(endpoint, "\x00\r\n")
}
func (t TrustContext) validate() error {
	if !validEndpoint(t.Endpoint) || !identityPattern.MatchString(t.AccountID) || t.AccountGeneration == 0 || !identityPattern.MatchString(t.DeviceID) || !identityPattern.MatchString(t.EnrollmentKey) || len(t.SigningPublic) != ed25519.PublicKeySize || len(t.ReceivingPublic) != 32 || t.PairingProfile != EnrollmentPairingProfile || len(t.EnrollmentCertificate) == 0 || !json.Valid(t.EnrollmentCertificate) {
		return ErrCorrupt
	}
	switch t.CertificateVersion {
	case "", "1":
		if len(t.Managers) < 1 || len(t.Managers) > 64 || len(t.EnrollmentCertificate) > maxEnrollmentCertificate {
			return ErrCorrupt
		}
	case "2":
		if len(t.Managers) != 0 || len(t.EnrollmentCertificate) > maxEnrollmentCertificateV2 {
			return ErrCorrupt
		}
	default:
		return ErrCorrupt
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(t.EnrollmentCertificate, &object) != nil || len(object) == 0 {
		return ErrCorrupt
	}
	for id, key := range t.Managers {
		if !identityPattern.MatchString(id) || len(key) != ed25519.PublicKeySize {
			return ErrCorrupt
		}
	}
	return nil
}
func trustVersion(t TrustContext) string {
	if t.CertificateVersion == "" {
		return "1"
	}
	return t.CertificateVersion
}

// 回执和信任集合冻结；仅 Accepted 可以由 false 变为 true，不能替换 proof。
func sameTrustEvidence(a, b TrustContext) bool {
	if trustVersion(a) != trustVersion(b) || a.PairingProfile != b.PairingProfile || len(a.Managers) != len(b.Managers) {
		return false
	}
	for id, key := range a.Managers {
		if !bytes.Equal(key, b.Managers[id]) {
			return false
		}
	}
	var x, y bytes.Buffer
	if json.Compact(&x, a.EnrollmentCertificate) != nil || json.Compact(&y, b.EnrollmentCertificate) != nil {
		return false
	}
	return bytes.Equal(x.Bytes(), y.Bytes())
}
func sameTrustIdentity(a, b TrustContext) bool {
	return a.Endpoint == b.Endpoint && a.AccountID == b.AccountID && a.AccountGeneration == b.AccountGeneration && a.DeviceID == b.DeviceID && a.EnrollmentKey == b.EnrollmentKey && bytes.Equal(a.SigningPublic, b.SigningPublic) && bytes.Equal(a.ReceivingPublic, b.ReceivingPublic)
}
func sameSessionIdentity(s LoginSession, t TrustContext) bool {
	return s.Endpoint == t.Endpoint && s.AccountID == t.AccountID && s.AccountGeneration == t.AccountGeneration
}
func sameDeviceIdentity(k DeviceKeys, t TrustContext) bool {
	return k.DeviceID == t.DeviceID && bytes.Equal(k.SigningPublic, t.SigningPublic) && bytes.Equal(k.ReceivingPublic, t.ReceivingPublic)
}
func (v *Vault) loadTrustRecordLocked() (TrustContext, error) {
	data, err := v.loadLocked("trust-v1")
	if err != nil {
		return TrustContext{}, err
	}
	defer clear(data)
	var trust TrustContext
	if err := strictJSON(data, &trust); err != nil {
		return TrustContext{}, err
	}
	if err := trust.validate(); err != nil {
		return TrustContext{}, err
	}
	return trust, nil
}
func (v *Vault) trustBindingsLocked(trust TrustContext) error {
	data, err := v.loadLocked("device-v1")
	if err != nil {
		return err
	}
	defer clear(data)
	var keys DeviceKeys
	if strictJSON(data, &keys) != nil {
		return ErrCorrupt
	}
	defer clear(keys.SigningSeed)
	defer clear(keys.ReceivingPrivate)
	if err := keys.validate(); err != nil {
		return err
	}
	if !sameDeviceIdentity(keys, trust) {
		return ErrIdentity
	}
	data, err = v.loadLocked("session-v1")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer clear(data)
	var session LoginSession
	if strictJSON(data, &session) != nil {
		return ErrCorrupt
	}
	if err := session.validate(); err != nil {
		return err
	}
	if !sameSessionIdentity(session, trust) {
		return ErrIdentity
	}
	return nil
}
func (v *Vault) SaveTrustContext(trust TrustContext) error {
	if err := trust.validate(); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.trustBindingsLocked(trust); err != nil {
		return err
	}
	previous, err := v.loadTrustRecordLocked()
	if err == nil && (!sameTrustIdentity(previous, trust) || !sameTrustEvidence(previous, trust) || previous.Accepted && !trust.Accepted) {
		return ErrIdentity
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.Marshal(trust)
	if err != nil {
		return err
	}
	defer clear(data)
	return v.saveLocked("trust-v1", data)
}
func (v *Vault) LoadTrustContext() (TrustContext, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	trust, err := v.loadTrustRecordLocked()
	if err != nil {
		return TrustContext{}, err
	}
	if err := v.trustBindingsLocked(trust); err != nil {
		return TrustContext{}, err
	}
	return trust, nil
}
