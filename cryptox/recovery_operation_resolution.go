package cryptox

import (
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strconv"
)

const RecoveryOperationClosureCapability = "recovery-operation-closure-v1"
const RecoveryOperationResolutionProfile = "harmonia-recovery-operation-resolution-v1"

type RecoveryOperationBasis struct {
	InitializationHash         string `json:"initializationHash"`
	ExpectedSequence           string `json:"expectedSequence"`
	RecoveryGeneration         string `json:"recoveryGeneration"`
	RecoveryHeadHash           string `json:"recoveryHeadHash"`
	RecoverySigningPublicKey   string `json:"recoverySigningPublicKey"`
	RecoveryReceivingPublicKey string `json:"recoveryReceivingPublicKey"`
	DependencyBundleHash       string `json:"dependencyBundleHash"`
	EnvironmentManifestHash    string `json:"environmentManifestHash"`
}
type RecoveryOperationTarget struct {
	Profile                  string                 `json:"profile"`
	Kind                     string                 `json:"kind"`
	AccountID                string                 `json:"accountId"`
	AccountGeneration        string                 `json:"accountGeneration"`
	OperationID              string                 `json:"operationId"`
	OriginalSessionHash      string                 `json:"originalSessionHash"`
	AuthorizationKind        string                 `json:"authorizationKind"`
	DeviceID                 string                 `json:"deviceId"`
	DeviceSigningPublicKey   string                 `json:"deviceSigningPublicKey"`
	DeviceReceivingPublicKey string                 `json:"deviceReceivingPublicKey"`
	Stage                    string                 `json:"stage"`
	Basis                    RecoveryOperationBasis `json:"basis"`
	DeclaredIntentHash       string                 `json:"declaredIntentHash"`
	KnownChallengeHash       string                 `json:"knownChallengeHash"`
	DeclaredContentHash      string                 `json:"declaredContentHash"`
}

func (t RecoveryOperationTarget) CanonicalBytes() ([]byte, error) {
	b := t.Basis
	if t.Profile != RecoveryDAGCapability || t.Kind != "transition-v2" && t.Kind != "recovered-v2" || t.AuthorizationKind != "old-recovery" && t.AuthorizationKind != "all-environments-admin" || t.Kind == "recovered-v2" && t.AuthorizationKind != "old-recovery" {
		return nil, ErrInvalidWire
	}
	for _, id := range []string{t.AccountID, t.OperationID, t.DeviceID} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	for _, g := range []string{t.AccountGeneration, b.ExpectedSequence, b.RecoveryGeneration} {
		if validDecimal(g, true) != nil {
			return nil, ErrInvalidWire
		}
	}
	n, _ := strconv.ParseUint(b.ExpectedSequence, 10, 64)
	if n > 9007199254740991 {
		return nil, ErrInvalidWire
	}
	for _, h := range []string{t.OriginalSessionHash, t.DeclaredIntentHash, b.InitializationHash, b.RecoveryHeadHash, b.DependencyBundleHash, b.EnvironmentManifestHash} {
		if !tokenHashPattern.MatchString(h) {
			return nil, ErrInvalidWire
		}
	}
	if validatePublicPair(t.DeviceSigningPublicKey, t.DeviceReceivingPublicKey) != nil || validatePublicPair(b.RecoverySigningPublicKey, b.RecoveryReceivingPublicKey) != nil {
		return nil, ErrInvalidWire
	}
	switch t.Stage {
	case "intent":
		if t.KnownChallengeHash != "" || t.DeclaredContentHash != "" {
			return nil, ErrInvalidWire
		}
	case "challenged":
		if !tokenHashPattern.MatchString(t.KnownChallengeHash) || t.DeclaredContentHash != "" {
			return nil, ErrInvalidWire
		}
	case "sealed":
		if !tokenHashPattern.MatchString(t.KnownChallengeHash) || !tokenHashPattern.MatchString(t.DeclaredContentHash) {
			return nil, ErrInvalidWire
		}
	default:
		return nil, ErrInvalidWire
	}
	return canonical("harmonia/recovery-operation-target/v1", "1", t.Profile, t.Kind, t.AccountID, t.AccountGeneration, t.OperationID, t.OriginalSessionHash, t.AuthorizationKind, t.DeviceID, t.DeviceSigningPublicKey, t.DeviceReceivingPublicKey, t.Stage, b.InitializationHash, b.ExpectedSequence, b.RecoveryGeneration, b.RecoveryHeadHash, b.RecoverySigningPublicKey, b.RecoveryReceivingPublicKey, b.DependencyBundleHash, b.EnvironmentManifestHash, t.DeclaredIntentHash, t.KnownChallengeHash, t.DeclaredContentHash), nil
}
func (t RecoveryOperationTarget) Hash() (string, error) {
	b, e := t.CanonicalBytes()
	if e != nil {
		return "", e
	}
	return hashCanonical(json.RawMessage(b))
}
func (t *RecoveryOperationTarget) UnmarshalJSON(raw []byte) error {
	type plain RecoveryOperationTarget
	var p plain
	if validateRecoveryJSONShape(raw, reflect.TypeOf(p), nil) != nil || strictDAGDecode(raw, &p) != nil {
		return ErrInvalidWire
	}
	*t = RecoveryOperationTarget(p)
	_, e := t.CanonicalBytes()
	return e
}

type RecoveryOperationResolutionRequest struct {
	Version         int                     `json:"version"`
	Mode            string                  `json:"mode"`
	Target          RecoveryOperationTarget `json:"target"`
	DeviceSignature string                  `json:"deviceSignature"`
}

func RecoveryOperationResolutionSigningBytes(t RecoveryOperationTarget, mode, currentSessionHash string) ([]byte, error) {
	if mode != "query" && mode != "resolve-or-close" || !tokenHashPattern.MatchString(currentSessionHash) {
		return nil, ErrInvalidWire
	}
	h, e := t.Hash()
	if e != nil {
		return nil, e
	}
	return canonical("harmonia/recovery-operation-resolution/v1", mode, currentSessionHash, h), nil
}
func SignRecoveryOperationResolution(t RecoveryOperationTarget, mode, currentSessionHash string, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize || EncodeBase64(key.Public().(ed25519.PublicKey)) != t.DeviceSigningPublicKey {
		return "", ErrInvalidWire
	}
	b, e := RecoveryOperationResolutionSigningBytes(t, mode, currentSessionHash)
	if e != nil {
		return "", e
	}
	return sign(key, b)
}
func VerifyRecoveryOperationResolution(r RecoveryOperationResolutionRequest, currentSessionHash string) error {
	if r.Version != 1 {
		return ErrInvalidWire
	}
	b, e := RecoveryOperationResolutionSigningBytes(r.Target, r.Mode, currentSessionHash)
	if e != nil {
		return e
	}
	key, e := DecodeBase64(r.Target.DeviceSigningPublicKey, 32, 32)
	if e != nil {
		return e
	}
	return verify(ed25519.PublicKey(key), b, r.DeviceSignature)
}
func RecoveryOperationDependencyBasisHash(b RecoveryDependencyBundle) (string, error) {
	i, e := initializationDAGRow(b.Initialization)
	if e != nil {
		return "", e
	}
	r, e := recordRows(b.Records)
	if e != nil {
		return "", e
	}
	ib, e := json.Marshal(i)
	if e != nil {
		return "", e
	}
	rb, e := json.Marshal(r)
	if e != nil {
		return "", e
	}
	return hashCanonical([]string{"harmonia/recovery-operation-basis/v1", EncodeBase64(ib), EncodeBase64(rb)})
}

// 原挑战仍按旧已签包/domain验证；此函数只编码公开closure合同的概括摘要。
type RecoveryOperationTransitionChallenge struct {
	AccountID, AccountGeneration, OperationID, ChallengeID, Nonce, ExpiresAt, SessionHash string
	AuthorizationKind, AuthorizerDeviceID, ExpectedSequence, PreviousTransitionHash       string
	OldRecoveryGeneration, OldRecoverySigningPublicKey, OldRecoveryReceivingPublicKey     string
	EnvironmentManifest                                                                   []RecoveryEnvironmentVersion
	AuthoritySet                                                                          []RecoveryAdminAuthority
	IssuerEvidence                                                                        *RecoverySource
	DependencyBundle                                                                      RecoveryDependencyBundle
}

func RecoveryOperationTransitionChallengeHash(c RecoveryOperationTransitionChallenge) (string, error) {
	for _, id := range []string{c.AccountID, c.OperationID, c.ChallengeID} {
		if validID(id) != nil {
			return "", ErrInvalidWire
		}
	}
	for _, g := range []string{c.AccountGeneration, c.ExpiresAt, c.ExpectedSequence, c.OldRecoveryGeneration} {
		if validDecimal(g, true) != nil {
			return "", ErrInvalidWire
		}
	}
	if _, e := DecodeBase64(c.Nonce, 32, 32); e != nil {
		return "", e
	}
	if !tokenHashPattern.MatchString(c.SessionHash) || !tokenHashPattern.MatchString(c.PreviousTransitionHash) || validatePublicPair(c.OldRecoverySigningPublicKey, c.OldRecoveryReceivingPublicKey) != nil {
		return "", ErrInvalidWire
	}
	mh, e := RecoveryManifestHash(c.EnvironmentManifest)
	if e != nil {
		return "", e
	}
	var ah, sh string
	if c.AuthorizationKind == "old-recovery" {
		if c.AuthorizerDeviceID != "" || c.IssuerEvidence != nil || c.AuthoritySet == nil || len(c.AuthoritySet) != 0 {
			return "", ErrInvalidWire
		}
		ah, e = hashCanonical([]any{"harmonia/recovery-admin-authorities/v1", [][]string{}})
	} else if c.AuthorizationKind == "all-environments-admin" {
		if validID(c.AuthorizerDeviceID) != nil || c.IssuerEvidence == nil {
			return "", ErrInvalidWire
		}
		ah, e = RecoveryAdminAuthoritiesHash(c.AuthoritySet)
		if e == nil {
			sh, e = c.IssuerEvidence.Hash()
		}
	} else {
		return "", ErrInvalidWire
	}
	if e != nil {
		return "", e
	}
	bh, e := RecoveryOperationDependencyBasisHash(c.DependencyBundle)
	if e != nil {
		return "", e
	}
	return hashCanonical([]string{"harmonia/recovery-operation-challenge/v1", "transition-v2", c.AccountID, c.AccountGeneration, c.OperationID, c.ChallengeID, c.Nonce, c.ExpiresAt, c.SessionHash, c.AuthorizationKind, c.AuthorizerDeviceID, c.ExpectedSequence, c.PreviousTransitionHash, c.OldRecoveryGeneration, c.OldRecoverySigningPublicKey, c.OldRecoveryReceivingPublicKey, mh, ah, sh, bh})
}

// 回执是HTTPS权威观察，不是设备签授权或可单独搬运的服务器签证。
type RecoveryOperationResolutionReceipt struct {
	Version               int     `json:"version"`
	Profile               string  `json:"profile"`
	AccountID             string  `json:"accountId"`
	AccountGeneration     string  `json:"accountGeneration"`
	Kind                  string  `json:"kind"`
	OperationID           string  `json:"operationId"`
	TargetHash            string  `json:"targetHash"`
	State                 string  `json:"state"`
	Sequence              uint64  `json:"sequence,omitempty"`
	ContentHash           string  `json:"contentHash,omitempty"`
	ObservedChallengeHash *string `json:"observedChallengeHash,omitempty"`
}

func (r RecoveryOperationResolutionReceipt) MarshalJSON() ([]byte, error) {
	type plain RecoveryOperationResolutionReceipt
	if r.State == "pending" && (r.Sequence != 0 || r.ContentHash != "" || r.ObservedChallengeHash != nil) || r.State == "accepted" && r.ObservedChallengeHash != nil || r.State == "closed" && r.ContentHash != "" {
		return nil, ErrInvalidWire
	}
	if r.State == "closed" {
		type closed struct {
			Version               int     `json:"version"`
			Profile               string  `json:"profile"`
			AccountID             string  `json:"accountId"`
			AccountGeneration     string  `json:"accountGeneration"`
			Kind                  string  `json:"kind"`
			OperationID           string  `json:"operationId"`
			TargetHash            string  `json:"targetHash"`
			State                 string  `json:"state"`
			Sequence              uint64  `json:"sequence"`
			ObservedChallengeHash *string `json:"observedChallengeHash"`
		}
		return json.Marshal(closed{r.Version, r.Profile, r.AccountID, r.AccountGeneration, r.Kind, r.OperationID, r.TargetHash, r.State, r.Sequence, r.ObservedChallengeHash})
	}
	return json.Marshal(plain(r))
}
func (r *RecoveryOperationResolutionReceipt) UnmarshalJSON(raw []byte) error {
	if len(raw) > 4096 || ValidateStrictJSON(raw, 4096) != nil {
		return ErrInvalidWire
	}
	var head struct {
		State string `json:"state"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return ErrInvalidWire
	}
	fields := []string{"version", "profile", "accountId", "accountGeneration", "kind", "operationId", "targetHash", "state"}
	switch head.State {
	case "pending":
	case "accepted":
		fields = append(fields, "sequence", "contentHash")
	case "closed":
		fields = append(fields, "sequence", "observedChallengeHash")
	default:
		return ErrInvalidWire
	}
	m, e := strictDAGObject(raw, fields...)
	if e != nil {
		return e
	}
	for k, v := range m {
		if k != "observedChallengeHash" && string(v) == "null" {
			return ErrInvalidWire
		}
	}
	type plain RecoveryOperationResolutionReceipt
	var p plain
	if strictDAGDecode(raw, &p) != nil {
		return ErrInvalidWire
	}
	*r = RecoveryOperationResolutionReceipt(p)
	if r.Version != 1 || r.Profile != RecoveryOperationResolutionProfile || validID(r.AccountID) != nil || validDecimal(r.AccountGeneration, true) != nil || validID(r.OperationID) != nil || r.Kind != "transition-v2" && r.Kind != "recovered-v2" || !tokenHashPattern.MatchString(r.TargetHash) {
		return ErrInvalidWire
	}
	if r.State != "pending" && (r.Sequence == 0 || r.Sequence > 9007199254740991) {
		return ErrInvalidWire
	}
	if r.State == "accepted" && !tokenHashPattern.MatchString(r.ContentHash) || r.State == "closed" && r.ObservedChallengeHash != nil && !tokenHashPattern.MatchString(*r.ObservedChallengeHash) {
		return ErrInvalidWire
	}
	return nil
}
func DecodeRecoveryOperationResolutionReceipt(raw []byte) (RecoveryOperationResolutionReceipt, error) {
	var r RecoveryOperationResolutionReceipt
	e := json.Unmarshal(raw, &r)
	return r, e
}
func (r RecoveryOperationResolutionReceipt) ValidateTarget(t RecoveryOperationTarget) error {
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if _, e = DecodeRecoveryOperationResolutionReceipt(raw); e != nil {
		return e
	}
	h, e := t.Hash()
	if e != nil {
		return e
	}
	if r.AccountID != t.AccountID || r.AccountGeneration != t.AccountGeneration || r.Kind != t.Kind || r.OperationID != t.OperationID || r.TargetHash != h {
		return ErrInvalidWire
	}
	n, _ := strconv.ParseUint(t.Basis.ExpectedSequence, 10, 64)
	if r.State == "accepted" && (r.Sequence != n+1 || t.DeclaredContentHash != "" && r.ContentHash != t.DeclaredContentHash) {
		return ErrInvalidSignature
	}
	if r.State == "closed" && (r.Sequence <= n || t.KnownChallengeHash != "" && (r.ObservedChallengeHash == nil || *r.ObservedChallengeHash != t.KnownChallengeHash)) {
		return ErrInvalidSignature
	}
	return nil
}
