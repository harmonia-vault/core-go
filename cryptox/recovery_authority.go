package cryptox

import (
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"strconv"
	"time"
)

const MaxRecoveryAuthorityBytes = 2 << 20
const MaxRecoveryTransitions = 128

type OriginalInitialization struct {
	Proposal          InitializationProposal `json:"proposal"`
	Proof             InitializationProof    `json:"proof"`
	DeviceSignature   string                 `json:"deviceSignature"`
	RecoverySignature string                 `json:"recoverySignature"`
	Sequence          uint64                 `json:"sequence"`
}

func (o OriginalInitialization) proposalBytes() ([]byte, error) {
	if _, err := o.Proposal.Hash(o.Proof.AccountID, o.Proof.AccountGeneration); err != nil {
		return nil, err
	}
	p := o.Proposal
	envs := append([]InitializationEnvironment(nil), p.Environments...)
	sort.Slice(envs, func(i, j int) bool { return envs[i].EnvironmentID < envs[j].EnvironmentID })
	rows := make([][]string, 0, len(envs))
	for _, e := range envs {
		b, err := e.Grant.Grant.SigningBytes()
		if err != nil {
			return nil, err
		}
		rows = append(rows, []string{e.EnvironmentID, e.KeyVersion, e.RecoveryEnvelope, EncodeBase64(b), e.Grant.Signature})
	}
	return json.Marshal([]any{"harmonia/vault-initialization-proposal/v1", p.IdempotencyKey, p.Device.ID, p.Device.SigningPublicKey, p.Device.ReceivingPublicKey, p.RecoveryGeneration, p.RecoverySigningPublicKey, p.RecoveryReceivingPublicKey, p.TrustRootSignature, rows})
}
func (o OriginalInitialization) Hash() (string, error) {
	if o.Sequence != 1 {
		return "", ErrInvalidWire
	}
	p, err := o.proposalBytes()
	if err != nil {
		return "", err
	}
	b, err := o.Proof.SigningBytes()
	if err != nil {
		return "", err
	}
	for _, s := range []string{o.DeviceSignature, o.RecoverySignature} {
		if _, err = DecodeBase64(s, 64, 64); err != nil {
			return "", err
		}
	}
	return hashCanonical([]string{"harmonia/recovery-initialization-anchor/v1", EncodeBase64(p), EncodeBase64(b), o.DeviceSignature, o.RecoverySignature, "1"})
}

type RecoveryEnvironmentVersion struct {
	EnvironmentID string `json:"environmentId"`
	KeyVersion    string `json:"keyVersion"`
}
type RecoveryAdminAuthority struct {
	EnvironmentID   string `json:"environmentId"`
	KeyVersion      string `json:"keyVersion"`
	GrantGeneration string `json:"grantGeneration"`
	ExpiresAt       string `json:"expiresAt"`
	AuthorityHash   string `json:"authorityHash"`
}

func RecoveryManifestHash(rows []RecoveryEnvironmentVersion) (string, error) {
	if rows == nil || len(rows) < 1 || len(rows) > 256 {
		return "", ErrInvalidWire
	}
	items := make([][]string, 0, len(rows))
	for i, r := range rows {
		if validID(r.EnvironmentID) != nil || validDecimal(r.KeyVersion, true) != nil || i > 0 && rows[i-1].EnvironmentID >= r.EnvironmentID {
			return "", ErrInvalidWire
		}
		items = append(items, []string{r.EnvironmentID, r.KeyVersion})
	}
	return hashCanonical([]any{"harmonia/recovery-environment-manifest/v1", items})
}
func RecoveryAdminAuthoritiesHash(rows []RecoveryAdminAuthority) (string, error) {
	if rows == nil || len(rows) < 1 || len(rows) > 256 {
		return "", ErrInvalidWire
	}
	items := make([][]string, 0, len(rows))
	for i, r := range rows {
		if validID(r.EnvironmentID) != nil || validDecimal(r.KeyVersion, true) != nil || validDecimal(r.GrantGeneration, true) != nil || validDecimal(r.ExpiresAt, false) != nil || !tokenHashPattern.MatchString(r.AuthorityHash) || i > 0 && rows[i-1].EnvironmentID >= r.EnvironmentID {
			return "", ErrInvalidWire
		}
		items = append(items, []string{r.EnvironmentID, r.KeyVersion, r.GrantGeneration, r.ExpiresAt, r.AuthorityHash})
	}
	return hashCanonical([]any{"harmonia/recovery-admin-authorities/v1", items})
}
func RecoveryTransitionEnvelopesHash(rows []RecoveryEnvelope) (string, error) {
	if rows == nil || len(rows) < 1 || len(rows) > 256 {
		return "", ErrInvalidWire
	}
	items := make([][]string, 0, len(rows))
	for i, r := range rows {
		if validID(r.EnvironmentID) != nil || validDecimal(r.KeyVersion, true) != nil || i > 0 && rows[i-1].EnvironmentID >= r.EnvironmentID {
			return "", ErrInvalidWire
		}
		if _, err := DecodeBase64(r.Envelope, 80, 80); err != nil {
			return "", err
		}
		items = append(items, []string{r.EnvironmentID, r.KeyVersion, r.Envelope})
	}
	return hashCanonical([]any{"harmonia/recovery-envelopes/v1", items})
}
func RecoveryTrustRootReferenceHash(account, gen string, r TrustRoot) (string, error) {
	b, err := r.SigningBytes(account, gen)
	if err != nil {
		return "", err
	}
	pub, err := DecodeBase64(r.RecoverySigningPublicKey, 32, 32)
	if err != nil {
		return "", err
	}
	if err = VerifyTrustRoot(account, gen, r, pub); err != nil {
		return "", err
	}
	return hashCanonical([]string{"harmonia/recovery-trust-root-ref/v1", EncodeBase64(b), r.Signature})
}

type VerifiedRecoveryAuthority struct {
	pin                                                      PinnedIssuerRoot
	initial                                                  []SignedGrantWire
	recoveryGeneration, signingPublic, receivingPublic, head string
	sequence                                                 uint64
	operations                                               map[string]string
	usedRecoveryKeys                                         map[string]bool
}

func VerifyRecoveryInitialization(pin PinnedIssuerRoot, o OriginalInitialization) (*VerifiedRecoveryAuthority, error) {
	p, d := o.Proof, o.Proposal.Device
	if o.Sequence != 1 || p.AccountID != pin.AccountID || p.AccountGeneration != pin.AccountGeneration || d.ID != pin.DeviceID || d.SigningPublicKey != pin.SigningPublicKey || d.ReceivingPublicKey != pin.ReceivingPublicKey {
		return nil, ErrInvalidSignature
	}
	h, err := o.Proposal.Hash(p.AccountID, p.AccountGeneration)
	if err != nil || h != p.ProposalHash {
		return nil, ErrInvalidSignature
	}
	pub, err := DecodeBase64(pin.SigningPublicKey, 32, 32)
	if err != nil {
		return nil, err
	}
	if err = VerifyInitializationProof(p, o.DeviceSignature, pub); err != nil {
		return nil, err
	}
	recoverPub, err := DecodeBase64(o.Proposal.RecoverySigningPublicKey, 32, 32)
	if err != nil {
		return nil, err
	}
	if err = VerifyInitializationProof(p, o.RecoverySignature, recoverPub); err != nil {
		return nil, err
	}
	head, err := o.Hash()
	if err != nil {
		return nil, err
	}
	initial := make([]SignedGrantWire, 0, len(o.Proposal.Environments))
	for _, e := range o.Proposal.Environments {
		initial = append(initial, e.Grant)
	}
	return &VerifiedRecoveryAuthority{pin: pin, initial: initial, recoveryGeneration: o.Proposal.RecoveryGeneration, signingPublic: o.Proposal.RecoverySigningPublicKey, receivingPublic: o.Proposal.RecoveryReceivingPublicKey, head: head, sequence: 1, operations: map[string]string{}, usedRecoveryKeys: map[string]bool{o.Proposal.RecoverySigningPublicKey: true, o.Proposal.RecoveryReceivingPublicKey: true}}, nil
}
func (v *VerifiedRecoveryAuthority) InitialAuthorities() []SignedGrantWire {
	if v == nil {
		return nil
	}
	return append([]SignedGrantWire(nil), v.initial...)
}
func (v *VerifiedRecoveryAuthority) HeadHash() string {
	if v == nil {
		return ""
	}
	return v.head
}
func (v *VerifiedRecoveryAuthority) Generation() string {
	if v == nil {
		return ""
	}
	return v.recoveryGeneration
}
func (v *VerifiedRecoveryAuthority) SigningPublicKey() string {
	if v == nil {
		return ""
	}
	return v.signingPublic
}
func (v *VerifiedRecoveryAuthority) ReceivingPublicKey() string {
	if v == nil {
		return ""
	}
	return v.receivingPublic
}

func ValidateRecoveryChallenge(expires string, now time.Time) error {
	n, err := strconv.ParseInt(expires, 10, 64)
	if err != nil || n <= now.Unix() || n > now.Unix()+120 {
		return ErrInvalidWire
	}
	return nil
}

func signRecoveryPurpose(key ed25519.PrivateKey, expectedPublic string, wire []byte) (string, error) {
	if len(key) != ed25519.PrivateKeySize || EncodeBase64(key.Public().(ed25519.PublicKey)) != expectedPublic {
		return "", ErrInvalidSignature
	}
	return sign(key, wire)
}

func recoveryRootMatches(p PinnedIssuerRoot, r TrustRoot) bool {
	return r.RootDeviceID == p.DeviceID && r.RootSigningPublicKey == p.SigningPublicKey && r.RootReceivingPublicKey == p.ReceivingPublicKey
}
