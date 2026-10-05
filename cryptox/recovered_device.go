package cryptox

import (
	"math"
	"strconv"
)

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

func (c RecoveredDeviceEnrollment) signingBytes() ([]byte, error) {
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
	return canonical("harmonia/recovered-device-enrollment/v2", c.AccountID, c.AccountGeneration, c.RecoveryGeneration, c.RecoveryTransitionHash, c.OperationID, c.ChallengeID, c.Nonce, c.ExpiresAt, c.RestrictedSessionHash, c.ExpectedSequence, c.DeviceID, c.DeviceSigningPublicKey, c.DeviceReceivingPublicKey, c.SelectedRightsHash, c.GrantsHash, c.IssuerEvidenceHash, c.EnvelopesHash), nil
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

type VerifiedRecoveredDevice struct {
	deviceID, signingPublic, receivingPublic, referenceHash string
	grants                                                  map[string]SignedGrantWire
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
