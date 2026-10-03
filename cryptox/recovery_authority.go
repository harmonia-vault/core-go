package cryptox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"time"
)

const (
	RecoveryAuthorityCapability = "issuer-recovery-v1"
	MaxRecoveryAuthorityBytes   = 2 << 20
	MaxRecoveryTransitions      = 128
)

// OriginalInitialization 是唯一已接受原初始化；根 pin 必须独立来自保护回执。
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
type RecoveryLegacyRotation struct {
	IdempotencyKey string `json:"idempotencyKey"`
	SigningBytes   string `json:"signingBytes"`
	Signature      string `json:"signature"`
	Sequence       uint64 `json:"sequence"`
}
type RecoveryLegacyState struct {
	RecoveryGeneration         string                   `json:"recoveryGeneration"`
	RecoverySigningPublicKey   string                   `json:"recoverySigningPublicKey"`
	RecoveryReceivingPublicKey string                   `json:"recoveryReceivingPublicKey"`
	TrustRoot                  TrustRoot                `json:"trustRoot"`
	Rotations                  []RecoveryLegacyRotation `json:"rotations"`
}
type RecoveryAuthorityTransition struct {
	AccountID                     string `json:"accountId"`
	AccountGeneration             string `json:"accountGeneration"`
	OperationID                   string `json:"operationId"`
	ChallengeID                   string `json:"challengeId"`
	Nonce                         string `json:"nonce"`
	ExpiresAt                     string `json:"expiresAt"`
	SessionHash                   string `json:"sessionHash"`
	ExpectedSequence              string `json:"expectedSequence"`
	PreviousTransitionHash        string `json:"previousTransitionHash"`
	OldRecoveryGeneration         string `json:"oldRecoveryGeneration"`
	OldRecoverySigningPublicKey   string `json:"oldRecoverySigningPublicKey"`
	OldRecoveryReceivingPublicKey string `json:"oldRecoveryReceivingPublicKey"`
	NewRecoveryGeneration         string `json:"newRecoveryGeneration"`
	NewRecoverySigningPublicKey   string `json:"newRecoverySigningPublicKey"`
	NewRecoveryReceivingPublicKey string `json:"newRecoveryReceivingPublicKey"`
	AuthorizationKind             string `json:"authorizationKind"`
	AuthorizerDeviceID            string `json:"authorizerDeviceId"`
	EnvironmentManifestHash       string `json:"environmentManifestHash"`
	AuthoritySetHash              string `json:"authoritySetHash"`
	IssuerEvidenceHash            string `json:"issuerEvidenceHash"`
	EnvelopesHash                 string `json:"envelopesHash"`
	NewTrustRootHash              string `json:"newTrustRootHash"`
	ChainMode                     string `json:"chainMode"`
	LegacyStateHash               string `json:"legacyStateHash"`
}
type RecoveryTransitionSubmission struct {
	Transition             RecoveryAuthorityTransition  `json:"transition"`
	EnvironmentManifest    []RecoveryEnvironmentVersion `json:"environmentManifest"`
	AuthoritySet           []RecoveryAdminAuthority     `json:"authoritySet"`
	IssuerEvidence         *IssuerProofV2               `json:"issuerEvidence"`
	Envelopes              []RecoveryEnvelope           `json:"envelopes"`
	NewTrustRoot           TrustRoot                    `json:"newTrustRoot"`
	LegacyState            *RecoveryLegacyState         `json:"legacyState"`
	AuthorizationSignature string                       `json:"authorizationSignature"`
	NewRecoverySignature   string                       `json:"newRecoverySignature"`
}
type AcceptedRecoveryTransition struct {
	Submission RecoveryTransitionSubmission `json:"submission"`
	Sequence   uint64                       `json:"sequence"`
}

func (t RecoveryAuthorityTransition) SigningBytes() ([]byte, error) {
	for _, id := range []string{t.AccountID, t.OperationID, t.ChallengeID} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	for _, n := range []string{t.AccountGeneration, t.OldRecoveryGeneration, t.NewRecoveryGeneration, t.ExpiresAt} {
		if validDecimal(n, true) != nil {
			return nil, ErrInvalidWire
		}
	}
	if validDecimal(t.ExpectedSequence, false) != nil {
		return nil, ErrInvalidWire
	}
	expected, _ := strconv.ParseUint(t.ExpectedSequence, 10, 64)
	expiry, _ := strconv.ParseUint(t.ExpiresAt, 10, 64)
	if expiry > math.MaxInt64 {
		return nil, ErrInvalidWire
	}
	old, _ := strconv.ParseUint(t.OldRecoveryGeneration, 10, 64)
	next, _ := strconv.ParseUint(t.NewRecoveryGeneration, 10, 64)
	if expected >= 9007199254740991 || old == math.MaxUint64 || next != old+1 || validatePublicPair(t.OldRecoverySigningPublicKey, t.OldRecoveryReceivingPublicKey) != nil || validatePublicPair(t.NewRecoverySigningPublicKey, t.NewRecoveryReceivingPublicKey) != nil || t.NewRecoverySigningPublicKey == t.OldRecoverySigningPublicKey || t.NewRecoveryReceivingPublicKey == t.OldRecoveryReceivingPublicKey || t.NewRecoverySigningPublicKey == t.OldRecoveryReceivingPublicKey || t.NewRecoveryReceivingPublicKey == t.OldRecoverySigningPublicKey {
		return nil, ErrInvalidWire
	}
	if _, err := DecodeBase64(t.Nonce, 32, 32); err != nil {
		return nil, err
	}
	for _, h := range []string{t.SessionHash, t.PreviousTransitionHash, t.EnvironmentManifestHash, t.EnvelopesHash, t.NewTrustRootHash} {
		if !tokenHashPattern.MatchString(h) {
			return nil, ErrInvalidWire
		}
	}
	switch t.AuthorizationKind {
	case "old-recovery":
		if t.AuthorizerDeviceID != "" || t.AuthoritySetHash != "" || t.IssuerEvidenceHash != "" || t.ChainMode != "continuous" {
			return nil, ErrInvalidWire
		}
	case "all-environments-admin":
		if validID(t.AuthorizerDeviceID) != nil || !tokenHashPattern.MatchString(t.AuthoritySetHash) || !tokenHashPattern.MatchString(t.IssuerEvidenceHash) {
			return nil, ErrInvalidWire
		}
	default:
		return nil, ErrInvalidWire
	}
	if t.ChainMode == "continuous" {
		if t.LegacyStateHash != "" {
			return nil, ErrInvalidWire
		}
	} else if t.ChainMode != "manager-reanchor" || t.AuthorizationKind != "all-environments-admin" || !tokenHashPattern.MatchString(t.LegacyStateHash) {
		return nil, ErrInvalidWire
	}
	return canonical("harmonia/recovery-authority-transition/v1", t.AccountID, t.AccountGeneration, t.OperationID, t.ChallengeID, t.Nonce, t.ExpiresAt, t.SessionHash, t.ExpectedSequence, t.PreviousTransitionHash, t.OldRecoveryGeneration, t.OldRecoverySigningPublicKey, t.OldRecoveryReceivingPublicKey, t.NewRecoveryGeneration, t.NewRecoverySigningPublicKey, t.NewRecoveryReceivingPublicKey, t.AuthorizationKind, t.AuthorizerDeviceID, t.EnvironmentManifestHash, t.AuthoritySetHash, t.IssuerEvidenceHash, t.EnvelopesHash, t.NewTrustRootHash, t.ChainMode, t.LegacyStateHash), nil
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
func RecoveryIssuerEvidenceHash(p IssuerProofV2) (string, error) {
	b, err := p.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return hashCanonical([]string{"harmonia/recovery-issuer-evidence-ref/v1", p.Profile, EncodeBase64(b)})
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
func RecoveryTransitionHash(s RecoveryTransitionSubmission) (string, error) {
	b, err := s.Transition.SigningBytes()
	if err != nil {
		return "", err
	}
	for _, sig := range []string{s.AuthorizationSignature, s.NewRecoverySignature} {
		if _, err = DecodeBase64(sig, 64, 64); err != nil {
			return "", err
		}
	}
	return hashCanonical([]string{"harmonia/recovery-authority-transition-ref/v1", EncodeBase64(b), s.AuthorizationSignature, s.NewRecoverySignature})
}

// VerifiedRecoveryAuthority 不接受服务器裸公钥为根，也不赋予设备当前管理权。
// 它只保存公开来源和历史链尾，不持有任何恢复私钥。
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

// ValidateRecoveryChallenge 只用于当前签名操作；历史已接受签名不因后来过期失效。
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

func (l RecoveryLegacyState) Hash(account, gen string) (string, error) {
	if l.Rotations == nil || len(l.Rotations) < 1 || len(l.Rotations) > MaxRecoveryTransitions || validDecimal(l.RecoveryGeneration, true) != nil || validatePublicPair(l.RecoverySigningPublicKey, l.RecoveryReceivingPublicKey) != nil {
		return "", ErrInvalidWire
	}
	r := l.TrustRoot
	if r.RecoveryGeneration != l.RecoveryGeneration || r.RecoverySigningPublicKey != l.RecoverySigningPublicKey || r.RecoveryReceivingPublicKey != l.RecoveryReceivingPublicKey {
		return "", ErrInvalidWire
	}
	b, err := r.SigningBytes(account, gen)
	if err != nil {
		return "", err
	}
	pub, err := DecodeBase64(l.RecoverySigningPublicKey, 32, 32)
	if err != nil {
		return "", err
	}
	if err = VerifyTrustRoot(account, gen, r, pub); err != nil {
		return "", err
	}
	rows := make([][]string, 0, len(l.Rotations))
	seen := map[string]bool{}
	previousGeneration := ""
	for i, row := range l.Rotations {
		if validID(row.IdempotencyKey) != nil || seen[row.IdempotencyKey] || row.Sequence < 2 || row.Sequence > 9007199254740991 || i > 0 && l.Rotations[i-1].Sequence >= row.Sequence {
			return "", ErrInvalidWire
		}
		seen[row.IdempotencyKey] = true
		encoded, err := DecodeBase64(row.SigningBytes, 1, 4096)
		if err != nil {
			return "", err
		}
		if err = ValidateStrictJSON(encoded, 4096); err != nil {
			return "", err
		}
		var f []string
		if json.Unmarshal(encoded, &f) != nil || len(f) != 13 || f[0] != "harmonia/recovery-rotation/v1" {
			return "", ErrInvalidWire
		}
		p := RecoveryRotationProof{AccountID: f[1], AccountGeneration: f[2], SessionHash: f[3], RecoveryGeneration: f[4], ChallengeID: f[5], Nonce: f[6], ExpiresAt: f[7], NewRecoveryGeneration: f[8], NewRecoverySigningPublicKey: f[9], NewRecoveryReceivingPublicKey: f[10], EnvelopesHash: f[11], TrustRootHash: f[12]}
		canonicalBytes, err := p.SigningBytes()
		if err != nil || string(encoded) != string(canonicalBytes) || p.AccountID != account || p.AccountGeneration != gen || i > 0 && p.RecoveryGeneration != previousGeneration {
			return "", ErrInvalidWire
		}
		key, err := DecodeBase64(p.NewRecoverySigningPublicKey, 32, 32)
		if err != nil {
			return "", err
		}
		if err = VerifyRecoveryRotationProof(p, row.Signature, key); err != nil {
			return "", err
		}
		previousGeneration = p.NewRecoveryGeneration
		rootHash, err := r.Hash(account, gen)
		if err != nil {
			return "", err
		}
		if i == len(l.Rotations)-1 && (p.NewRecoveryGeneration != l.RecoveryGeneration || p.NewRecoverySigningPublicKey != l.RecoverySigningPublicKey || p.NewRecoveryReceivingPublicKey != l.RecoveryReceivingPublicKey || p.TrustRootHash != rootHash) {
			return "", ErrInvalidWire
		}
		rows = append(rows, []string{row.IdempotencyKey, row.SigningBytes, row.Signature, strconv.FormatUint(row.Sequence, 10)})
	}
	return hashCanonical([]any{"harmonia/recovery-legacy-state/v1", l.RecoveryGeneration, l.RecoverySigningPublicKey, l.RecoveryReceivingPublicKey, EncodeBase64(b), r.Signature, rows})
}

func (v *VerifiedRecoveryAuthority) validateTransition(s RecoveryTransitionSubmission, now *time.Time) (*VerifiedIssuerProofV2, string, error) {
	if v == nil {
		return nil, "", ErrInvalidWire
	}
	t := s.Transition
	if _, used := v.operations[t.OperationID]; used {
		return nil, "", ErrInvalidWire
	}
	if _, err := t.SigningBytes(); err != nil {
		return nil, "", err
	}
	if t.AccountID != v.pin.AccountID || t.AccountGeneration != v.pin.AccountGeneration || t.PreviousTransitionHash != v.head {
		return nil, "", ErrInvalidSignature
	}
	expected, _ := strconv.ParseUint(t.ExpectedSequence, 10, 64)
	if expected < v.sequence {
		return nil, "", ErrInvalidWire
	}
	if now != nil {
		if err := ValidateRecoveryChallenge(t.ExpiresAt, *now); err != nil {
			return nil, "", err
		}
	}
	if t.ChainMode == "continuous" {
		if s.LegacyState != nil || t.OldRecoveryGeneration != v.recoveryGeneration || t.OldRecoverySigningPublicKey != v.signingPublic || t.OldRecoveryReceivingPublicKey != v.receivingPublic {
			return nil, "", ErrInvalidSignature
		}
	} else {
		if s.LegacyState == nil || s.LegacyState.RecoveryGeneration != t.OldRecoveryGeneration || s.LegacyState.RecoverySigningPublicKey != t.OldRecoverySigningPublicKey || s.LegacyState.RecoveryReceivingPublicKey != t.OldRecoveryReceivingPublicKey || !recoveryRootMatches(v.pin, s.LegacyState.TrustRoot) {
			return nil, "", ErrInvalidSignature
		}
		h, err := s.LegacyState.Hash(t.AccountID, t.AccountGeneration)
		if err != nil || h != t.LegacyStateHash {
			return nil, "", ErrInvalidSignature
		}
		first := s.LegacyState.Rotations[0]
		last := s.LegacyState.Rotations[len(s.LegacyState.Rotations)-1]
		bytes, err := DecodeBase64(first.SigningBytes, 1, 4096)
		if err != nil {
			return nil, "", err
		}
		var f []string
		if json.Unmarshal(bytes, &f) != nil || f[4] != v.recoveryGeneration || first.Sequence <= v.sequence || last.Sequence > expected {
			return nil, "", ErrInvalidSignature
		}
	}
	r := s.NewTrustRoot
	if !recoveryRootMatches(v.pin, r) || r.RecoveryGeneration != t.NewRecoveryGeneration || r.RecoverySigningPublicKey != t.NewRecoverySigningPublicKey || r.RecoveryReceivingPublicKey != t.NewRecoveryReceivingPublicKey {
		return nil, "", ErrInvalidSignature
	}
	for _, pub := range []string{t.NewRecoverySigningPublicKey, t.NewRecoveryReceivingPublicKey} {
		if v.usedRecoveryKeys[pub] || pub == v.pin.SigningPublicKey || pub == v.pin.ReceivingPublicKey {
			return nil, "", ErrInvalidSignature
		}
	}
	h, err := RecoveryTrustRootReferenceHash(t.AccountID, t.AccountGeneration, r)
	if err != nil || h != t.NewTrustRootHash {
		return nil, "", ErrInvalidSignature
	}
	h, err = RecoveryManifestHash(s.EnvironmentManifest)
	if err != nil || h != t.EnvironmentManifestHash {
		return nil, "", ErrInvalidSignature
	}
	h, err = RecoveryTransitionEnvelopesHash(s.Envelopes)
	if err != nil || h != t.EnvelopesHash || len(s.Envelopes) != len(s.EnvironmentManifest) {
		return nil, "", ErrInvalidSignature
	}
	for i, e := range s.Envelopes {
		if e.EnvironmentID != s.EnvironmentManifest[i].EnvironmentID || e.KeyVersion != s.EnvironmentManifest[i].KeyVersion {
			return nil, "", ErrInvalidSignature
		}
	}
	encoded, err := json.Marshal(s)
	if err != nil || len(encoded) > MaxRecoveryAuthorityBytes {
		return nil, "", ErrInvalidWire
	}
	if t.AuthorizationKind == "old-recovery" {
		if s.AuthoritySet == nil || len(s.AuthoritySet) != 0 || s.IssuerEvidence != nil {
			return nil, "", ErrInvalidWire
		}
		return nil, v.signingPublic, nil
	}
	if s.IssuerEvidence == nil || len(s.AuthoritySet) != len(s.EnvironmentManifest) {
		return nil, "", ErrInvalidWire
	}
	h, err = RecoveryAdminAuthoritiesHash(s.AuthoritySet)
	if err != nil || h != t.AuthoritySetHash {
		return nil, "", ErrInvalidSignature
	}
	h, err = RecoveryIssuerEvidenceHash(*s.IssuerEvidence)
	if err != nil || h != t.IssuerEvidenceHash {
		return nil, "", ErrInvalidSignature
	}
	p, err := VerifyIssuerEvidenceV2(v.pin, *s.IssuerEvidence, v.initial...)
	if err != nil {
		return nil, "", err
	}
	if len(s.IssuerEvidence.Targets) != len(s.EnvironmentManifest) {
		return nil, "", ErrInvalidSignature
	}
	actor, ok := p.identities[t.AuthorizerDeviceID]
	if !ok {
		return nil, "", ErrInvalidSignature
	}
	for i, row := range s.AuthoritySet {
		manifest := s.EnvironmentManifest[i]
		g, ok := p.Authority(row.AuthorityHash)
		a := g.Grant
		if !ok || row.EnvironmentID != manifest.EnvironmentID || row.KeyVersion != manifest.KeyVersion || a.AccountID != t.AccountID || a.AccountGeneration != t.AccountGeneration || a.EnvironmentID != row.EnvironmentID || a.KeyVersion != row.KeyVersion || a.GrantGeneration != row.GrantGeneration || a.ExpiresAt != row.ExpiresAt || a.Role != "admin" || p.VerifyTarget(g, t.AuthorizerDeviceID, actor.signing, actor.receiving) != nil {
			return nil, "", ErrInvalidSignature
		}
		expiry, err := strconv.ParseInt(a.ExpiresAt, 10, 64)
		if err != nil || expiry < 0 || now != nil && expiry != 0 && expiry <= now.Unix() {
			return nil, "", ErrInvalidSignature
		}
	}
	for _, identity := range p.identities {
		for _, pub := range []string{t.NewRecoverySigningPublicKey, t.NewRecoveryReceivingPublicKey} {
			if pub == identity.signing || pub == identity.receiving {
				return nil, "", ErrInvalidSignature
			}
		}
	}
	return p, actor.signing, nil
}
func recoveryRootMatches(p PinnedIssuerRoot, r TrustRoot) bool {
	return p.DeviceID == r.RootDeviceID && p.SigningPublicKey == r.RootSigningPublicKey && p.ReceivingPublicKey == r.RootReceivingPublicKey
}

// 这些入口只签完整、已验证的用途包；不会暴露通用任意字节签名服务。
func SignOldRecoveryTransition(v *VerifiedRecoveryAuthority, s RecoveryTransitionSubmission, key ed25519.PrivateKey, now time.Time) (string, error) {
	if s.Transition.AuthorizationKind != "old-recovery" {
		return "", ErrInvalidWire
	}
	_, pub, err := v.validateTransition(s, &now)
	if err != nil {
		return "", err
	}
	b, err := s.Transition.SigningBytes()
	if err != nil {
		return "", err
	}
	return signRecoveryPurpose(key, pub, b)
}
func SignAllAdminRecoveryTransition(v *VerifiedRecoveryAuthority, s RecoveryTransitionSubmission, key ed25519.PrivateKey, now time.Time) (string, error) {
	if s.Transition.AuthorizationKind != "all-environments-admin" {
		return "", ErrInvalidWire
	}
	_, pub, err := v.validateTransition(s, &now)
	if err != nil {
		return "", err
	}
	b, err := s.Transition.SigningBytes()
	if err != nil {
		return "", err
	}
	return signRecoveryPurpose(key, pub, b)
}
func SignNewRecoveryTransition(v *VerifiedRecoveryAuthority, s RecoveryTransitionSubmission, key ed25519.PrivateKey, now time.Time) (string, error) {
	_, authorizer, err := v.validateTransition(s, &now)
	if err != nil {
		return "", err
	}
	b, err := s.Transition.SigningBytes()
	if err != nil {
		return "", err
	}
	pub, err := DecodeBase64(authorizer, 32, 32)
	if err != nil {
		return "", err
	}
	if err = verify(pub, b, s.AuthorizationSignature); err != nil {
		return "", err
	}
	return signRecoveryPurpose(key, s.Transition.NewRecoverySigningPublicKey, b)
}

// VerifyAcceptedRecoveryTransition 只认原可信链尾或全环境管理者授权；历史
// 验签不授当前设备权限，也不以现在的期限否定过去已接受的同一原包。
func VerifyAcceptedRecoveryTransition(v *VerifiedRecoveryAuthority, record AcceptedRecoveryTransition) (*VerifiedRecoveryAuthority, error) {
	s := record.Submission
	_, authorizer, err := v.validateTransition(s, nil)
	if err != nil {
		return nil, err
	}
	expected, _ := strconv.ParseUint(s.Transition.ExpectedSequence, 10, 64)
	if record.Sequence != expected+1 || record.Sequence <= v.sequence || len(v.operations) >= MaxRecoveryTransitions {
		return nil, ErrInvalidWire
	}
	b, err := s.Transition.SigningBytes()
	if err != nil {
		return nil, err
	}
	for _, pair := range []struct{ public, signature string }{{authorizer, s.AuthorizationSignature}, {s.Transition.NewRecoverySigningPublicKey, s.NewRecoverySignature}} {
		pub, err := DecodeBase64(pair.public, 32, 32)
		if err != nil {
			return nil, err
		}
		if err = verify(pub, b, pair.signature); err != nil {
			return nil, err
		}
	}
	h, err := RecoveryTransitionHash(s)
	if err != nil {
		return nil, err
	}
	if _, exists := v.operations[s.Transition.OperationID]; exists {
		return nil, ErrInvalidWire
	}
	ops := make(map[string]string, len(v.operations)+1)
	for k, x := range v.operations {
		ops[k] = x
	}
	ops[s.Transition.OperationID] = h
	keys := make(map[string]bool, len(v.usedRecoveryKeys)+2)
	for k, x := range v.usedRecoveryKeys {
		keys[k] = x
	}
	keys[s.Transition.OldRecoverySigningPublicKey] = true
	keys[s.Transition.OldRecoveryReceivingPublicKey] = true
	if s.LegacyState != nil {
		for _, r := range s.LegacyState.Rotations {
			b, _ := DecodeBase64(r.SigningBytes, 1, 4096)
			var f []string
			_ = json.Unmarshal(b, &f)
			keys[f[9]] = true
			keys[f[10]] = true
		}
	}
	keys[s.Transition.NewRecoverySigningPublicKey] = true
	keys[s.Transition.NewRecoveryReceivingPublicKey] = true
	return &VerifiedRecoveryAuthority{pin: v.pin, initial: v.InitialAuthorities(), recoveryGeneration: s.Transition.NewRecoveryGeneration, signingPublic: s.Transition.NewRecoverySigningPublicKey, receivingPublic: s.Transition.NewRecoveryReceivingPublicKey, head: h, sequence: record.Sequence, operations: ops, usedRecoveryKeys: keys}, nil
}

func DecodeRecoveryTransitionSubmission(data []byte) (RecoveryTransitionSubmission, error) {
	var s RecoveryTransitionSubmission
	if err := validateRecoveryJSONShape(data, reflect.TypeOf(s), map[string]bool{"$.issuerEvidence": true, "$.legacyState": true}); err != nil {
		return s, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return s, err
	}
	var rest any
	if err := d.Decode(&rest); err != io.EOF {
		return s, ErrInvalidWire
	}
	if s.EnvironmentManifest == nil || s.AuthoritySet == nil || s.Envelopes == nil {
		return s, ErrInvalidWire
	}
	_, err := s.Transition.SigningBytes()
	if err != nil {
		return s, err
	}
	if s.Transition.AuthorizationKind == "old-recovery" && (len(s.AuthoritySet) != 0 || s.IssuerEvidence != nil) || s.Transition.AuthorizationKind == "all-environments-admin" && (len(s.AuthoritySet) == 0 || s.IssuerEvidence == nil) {
		return s, ErrInvalidWire
	}
	if s.Transition.ChainMode == "continuous" && s.LegacyState != nil || s.Transition.ChainMode == "manager-reanchor" && s.LegacyState == nil {
		return s, ErrInvalidWire
	}
	return s, nil
}
