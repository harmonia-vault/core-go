package cryptox

import (
	"strconv"
)

const MaxIssuerProofPath = 32

type IssuerEnrollment struct {
	CertificateVersion string             `json:"certificateVersion"`
	IssuerProofHash    string             `json:"issuerProofHash"`
	Approval           EnrollmentApproval `json:"approval"`
}

type IssuerTarget struct {
	EnvironmentID string `json:"environmentId"`
	AuthorityHash string `json:"authorityHash"`
}

type ConfirmedEnrollmentAnchor struct {
	Context        EnrollmentContext
	TranscriptHash string
}

func IssuerAuthorityHash(g SignedGrantWire) (string, error) {
	b, err := g.Grant.SigningBytes()
	if err != nil {
		return "", err
	}
	if _, err := DecodeBase64(g.Signature, 64, 64); err != nil {
		return "", err
	}
	return hashCanonical([]string{"harmonia/issuer-authority/v1", EncodeBase64(b), g.Signature})
}

type IssuerBinding struct {
	EnvironmentID      string
	KeyVersion         string
	DeviceID           string
	SigningPublicKey   string
	ReceivingPublicKey string
	AuthorityHash      string
}
type issuerIdentity struct{ id, signing, receiving string }

func issuerExpiryWithin(child, parent string) bool {
	c, e := strconv.ParseUint(child, 10, 64)
	if e != nil || c > 253402300799 {
		return false
	}
	p, e := strconv.ParseUint(parent, 10, 64)
	if e != nil || p > 253402300799 {
		return false
	}
	return p == 0 || (c != 0 && c <= p)
}
func issuerIdentityMatches(i issuerIdentity, id, signing, receiving string) bool {
	return i.id == id && i.signing == signing && i.receiving == receiving
}
func issuerHistoricalContext(c EnrollmentContext) error {
	expires, err := strconv.ParseUint(c.ExpiresAt, 10, 64)
	if c.Purpose != "enroll-device" || err != nil || expires > 253402300799 {
		return ErrInvalidWire
	}
	return nil
}

type PinnedIssuerRoot struct {
	AccountID          string
	AccountGeneration  string
	DeviceID           string
	SigningPublicKey   string
	ReceivingPublicKey string
}
