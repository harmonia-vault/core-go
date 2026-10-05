package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrDAGRecoveryState = errors.New("restricted DAG recovery state unavailable")

type DAGRecoveryConfig struct {
	Preparation          DAGTransitionPreparationStore
	RecoveredPreparation DAGRecoveredPreparationStore
	Endpoint             string
	HTTPClient           *http.Client
	AccountID            string
	AccountGeneration    uint64
	PriorBundle          *cryptox.RecoveryDependencyBundle
	MinimumSequence      uint64
	ClosedOperations     []DAGClosedOperationCheckpoint
	Pin                  *cryptox.PinnedIssuerRoot
	Now                  func() time.Time
	Journal              DAGRecoveryJournal
}
type DAGRecoveryInfo struct {
	RecoveryGeneration string
	Sequence           uint64
	Environments       int
	RotationRequired   bool
	TrustedDevice      bool
	ExpiresAt          int64
}
type DAGVault struct {
	AccountID                  string                           `json:"accountId"`
	AccountGeneration          string                           `json:"accountGeneration"`
	RecoveryGeneration         string                           `json:"recoveryGeneration"`
	RecoverySigningPublicKey   string                           `json:"recoverySigningPublicKey"`
	RecoveryReceivingPublicKey string                           `json:"recoveryReceivingPublicKey"`
	RotationRequired           bool                             `json:"rotationRequired"`
	Sequence                   uint64                           `json:"sequence"`
	DependencyBundle           cryptox.RecoveryDependencyBundle `json:"dependencyBundle"`
	IssuerEvidence             cryptox.IssuerRecoveryDAG        `json:"issuerEvidence"`
	TrustRoot                  cryptox.TrustRoot                `json:"trustRoot"`
	RecoveryHeadHash           string                           `json:"recoveryHeadHash"`
	PublicDevices              []struct {
		ID                 string `json:"id"`
		SigningPublicKey   string `json:"signingPublicKey"`
		ReceivingPublicKey string `json:"receivingPublicKey"`
		Revoked            bool   `json:"revoked"`
	} `json:"publicDevices"`
	CurrentGrants []cryptox.SignedGrantWire `json:"currentGrants"`
	GrantHistory  []struct {
		Sequence               uint64                   `json:"sequence"`
		Grant                  cryptox.SignedGrantWire  `json:"grant"`
		Authorization          *cryptox.SignedGrantWire `json:"authorization"`
		OriginHash             string                   `json:"originHash,omitempty"`
		RecoveryEnrollmentHash string                   `json:"recoveryEnrollmentHash,omitempty"`
	} `json:"grantHistory"`
	Environments     []cryptox.RecoveryEnvelope `json:"environments"`
	Events           []Event                    `json:"events"`
	EnvelopeEvidence dagEnvelopeEvidence        `json:"envelopeEvidence"`
}
type dagEnvelopeEvidence struct {
	Profile            string `json:"profile"`
	EnvironmentChanges []struct {
		Sequence      uint64                           `json:"sequence"`
		Change        cryptox.SignedEnvironmentChange  `json:"change"`
		Origin        *cryptox.SignedEnvironmentOrigin `json:"origin"`
		Authorization cryptox.SignedGrantWire          `json:"authorization"`
	} `json:"environmentChanges"`
}
type DAGTransitionChallenge struct {
	OperationID                   string                               `json:"operationId"`
	ChallengeID                   string                               `json:"challengeId"`
	Nonce                         string                               `json:"nonce"`
	ExpiresAt                     int64                                `json:"expiresAt"`
	SessionHash                   string                               `json:"sessionHash"`
	AccountGeneration             string                               `json:"accountGeneration"`
	AuthorizationKind             string                               `json:"authorizationKind"`
	AuthorizerDeviceID            string                               `json:"authorizerDeviceId"`
	ExpectedSequence              string                               `json:"expectedSequence"`
	PreviousTransitionHash        string                               `json:"previousTransitionHash"`
	OldRecoveryGeneration         string                               `json:"oldRecoveryGeneration"`
	OldRecoverySigningPublicKey   string                               `json:"oldRecoverySigningPublicKey"`
	OldRecoveryReceivingPublicKey string                               `json:"oldRecoveryReceivingPublicKey"`
	EnvironmentManifest           []cryptox.RecoveryEnvironmentVersion `json:"environmentManifest"`
	AuthoritySet                  []cryptox.RecoveryAdminAuthority     `json:"authoritySet"`
	IssuerEvidence                *cryptox.RecoverySource              `json:"issuerEvidence"`
	DependencyBundle              cryptox.RecoveryDependencyBundle     `json:"dependencyBundle"`
}
type DAGDeviceChallenge struct {
	OperationID              string                           `json:"operationId"`
	ChallengeID              string                           `json:"challengeId"`
	Nonce                    string                           `json:"nonce"`
	ExpiresAt                int64                            `json:"expiresAt"`
	RestrictedSessionHash    string                           `json:"restrictedSessionHash"`
	AccountGeneration        string                           `json:"accountGeneration"`
	ExpectedSequence         string                           `json:"expectedSequence"`
	RecoveryGeneration       string                           `json:"recoveryGeneration"`
	RecoveryTransitionHash   string                           `json:"recoveryTransitionHash"`
	DeviceID                 string                           `json:"deviceId"`
	DeviceSigningPublicKey   string                           `json:"deviceSigningPublicKey"`
	DeviceReceivingPublicKey string                           `json:"deviceReceivingPublicKey"`
	IssuerEvidence           cryptox.RecoverySource           `json:"issuerEvidence"`
	DependencyBundle         cryptox.RecoveryDependencyBundle `json:"dependencyBundle"`
}
type DAGReceipt struct {
	OperationID            string `json:"operationId,omitempty"`
	Accepted               bool   `json:"accepted,omitempty"`
	Sequence               uint64 `json:"sequence,omitempty"`
	ContentHash            string `json:"contentHash,omitempty"`
	TransitionHash         string `json:"transitionHash,omitempty"`
	RecoveryEnrollmentHash string `json:"recoveryEnrollmentHash,omitempty"`
	Replayed               bool   `json:"replayed,omitempty"`
}

// 私钥/受限会话只在当前进程。String/JSON不允许暴露它们；Close尽力清除。
type DAGRecoverySession struct {
	authRecoveryGeneration                  string
	mu                                      sync.Mutex
	config                                  DAGRecoveryConfig
	endpoint                                *url.URL
	http                                    *http.Client
	token                                   string
	expires                                 int64
	lastObserved                            int64
	keys                                    cryptox.RecoveryKeys
	pin                                     cryptox.PinnedIssuerRoot
	vault                                   DAGVault
	proof                                   *cryptox.VerifiedRecoveryDAG
	environmentKeys                         map[string][]byte
	closed                                  bool
	transitionChallenge                     *DAGTransitionChallenge
	newGeneration, newSigning, newReceiving string
	pending                                 *ProtectedDAGOperation
	nextKeys                                cryptox.RecoveryKeys
}

func (*DAGRecoverySession) String() string               { return "process-only restricted DAG recovery" }
func (*DAGRecoverySession) GoString() string             { return "process-only restricted DAG recovery" }
func (*DAGRecoverySession) MarshalJSON() ([]byte, error) { return nil, ErrDAGRecoveryState }
func (*DAGRecoverySession) MarshalText() ([]byte, error) { return nil, ErrDAGRecoveryState }
func clearRecoveryKeys(k *cryptox.RecoveryKeys) {
	clear(k.SigningPrivate)
	clear(k.ReceivingPrivate)
	*k = cryptox.RecoveryKeys{}
}
func (s *DAGRecoverySession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.erase()
}
func (s *DAGRecoverySession) erase() {
	s.closed = true
	s.token = ""
	clearRecoveryKeys(&s.keys)
	clearRecoveryKeys(&s.nextKeys)
	for _, k := range s.environmentKeys {
		clear(k)
	}
	s.environmentKeys = nil
	s.proof = nil
}
func (s *DAGRecoverySession) live() error {
	now := s.config.Now().Unix()
	var ownerErr error
	if owner, ok := s.config.Journal.(interface{ OwnerAlive() error }); ok {
		ownerErr = owner.OwnerAlive()
	}
	if s.closed || ownerErr != nil || now < s.lastObserved || s.expires <= now {
		s.erase()
		return ErrDAGRecoveryState
	}
	s.lastObserved = now
	return nil
}
func (s *DAGRecoverySession) path(suffix string) *url.URL {
	u := *s.endpoint
	parts := strings.SplitN(suffix, "?", 2)
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/accounts/" + s.config.AccountID + parts[0]
	u.RawPath = ""
	if len(parts) == 2 {
		u.RawQuery = parts[1]
	}
	return &u
}
func dagPath(op string) string { return "/" + op + "?capability=" + cryptox.RecoveryDAGCapability }
func (s *DAGRecoverySession) request(ctx context.Context, method, path string, token string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return cryptox.ErrInvalidWire
		}
		reader = bytes.NewReader(b)
	}
	r, e := http.NewRequestWithContext(ctx, method, s.path(path).String(), reader)
	if e != nil {
		return cryptox.ErrInvalidWire
	}
	r.Header.Set("Harmonia-Protocol-Major", "2")
	r.Header.Set("X-Harmonia-Account-Generation", strconv.FormatUint(s.config.AccountGeneration, 10))
	r.Header.Set("Cache-Control", "no-store")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, e := s.http.Do(r)
	if e != nil {
		return ErrDAGRequestUnavailable
	}
	defer response.Body.Close()
	if response.Header.Get("Harmonia-Protocol-Major") != "2" {
		return errors.New("protocol major2 mismatch")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return parseRequestError(response)
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if e != nil || len(raw) > 8<<20 {
		return cryptox.ErrInvalidWire
	}
	if strictJSONBytes(raw, out) != nil {
		return cryptox.ErrInvalidWire
	}
	return nil
}
func OpenDAGRecoverySession(ctx context.Context, c DAGRecoveryConfig, completeCode string) (*DAGRecoverySession, error) {
	if !enrollmentID.MatchString(c.AccountID) || c.AccountGeneration == 0 || c.Journal == nil {
		return nil, cryptox.ErrInvalidWire
	}
	var e error
	c, e = freezeDAGClosedHistoryConfig(c)
	if e != nil {
		return nil, e
	}
	if e := CheckDAGCapability(ctx, c.Endpoint, c.HTTPClient); e != nil {
		return nil, e
	}
	s, e := openDAGRecoveryProof(ctx, c, completeCode)
	if e != nil {
		return nil, e
	}
	keep := false
	defer func() {
		if !keep {
			s.Close()
		}
	}()
	if e = s.refresh(ctx); e != nil {
		return nil, e
	}
	pending, err := c.Journal.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if pending.Endpoint != c.Endpoint || pending.AccountID != c.AccountID || pending.AccountGeneration != c.AccountGeneration || pending.Pin != s.pin || validateProtectedDAGOperation(pending) != nil {
			return nil, cryptox.ErrInvalidWire
		}
		s.pending = &pending
	}
	keep = true
	return s, nil
}
func openDAGRecoveryProof(ctx context.Context, c DAGRecoveryConfig, completeCode string) (*DAGRecoverySession, error) {
	u, e := url.Parse(c.Endpoint)
	if e != nil {
		return nil, e
	}
	h, e := secureHTTP(c.HTTPClient)
	if e != nil {
		return nil, e
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	seed, e := cryptox.DecodeRecoveryCode(completeCode)
	if e != nil {
		return nil, e
	}
	defer clear(seed)
	s := &DAGRecoverySession{config: c, endpoint: u, http: h, lastObserved: c.Now().Unix()}
	keep := false
	defer func() {
		if !keep {
			s.Close()
		}
	}()
	var challenge struct {
		ChallengeID        string   `json:"challengeId"`
		Nonce              string   `json:"nonce"`
		ExpiresAt          int64    `json:"expiresAt"`
		RecoveryGeneration string   `json:"recoveryGeneration"`
		SigningPayload     []string `json:"signingPayload"`
	}
	body := map[string]string{"accountGeneration": strconv.FormatUint(c.AccountGeneration, 10)}
	if e = s.request(ctx, "POST", "/recovery-challenges", "", body, &challenge); e != nil {
		return nil, e
	}
	if challenge.ExpiresAt <= s.lastObserved || challenge.ExpiresAt > s.lastObserved+125 {
		return nil, cryptox.ErrInvalidWire
	}
	s.authRecoveryGeneration = challenge.RecoveryGeneration
	s.keys, e = cryptox.DeriveRecoveryKeys(seed, c.AccountID, body["accountGeneration"], challenge.RecoveryGeneration)
	if e != nil {
		return nil, e
	}
	proof := cryptox.RecoveryProof{AccountID: c.AccountID, AccountGeneration: body["accountGeneration"], RecoveryGeneration: challenge.RecoveryGeneration, ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, ExpiresAt: strconv.FormatInt(challenge.ExpiresAt, 10)}
	canonical, e := proof.SigningBytes()
	if e != nil {
		return nil, e
	}
	var fields []string
	_ = json.Unmarshal(canonical, &fields)
	if !sameJSON(fields, challenge.SigningPayload) {
		return nil, cryptox.ErrInvalidWire
	}
	sig, e := cryptox.SignRecoveryProof(proof, s.keys.SigningPrivate)
	if e != nil {
		return nil, e
	}
	var session struct {
		Token            string `json:"token"`
		ExpiresAt        int64  `json:"expiresAt"`
		RotationRequired bool   `json:"rotationRequired"`
	}
	if e = s.request(ctx, "POST", "/recovery-sessions", "", map[string]string{"accountGeneration": body["accountGeneration"], "challengeId": challenge.ChallengeID, "signature": sig}, &session); e != nil {
		return nil, e
	}
	if _, e = cryptox.DecodeBase64(session.Token, 32, 32); e != nil || !session.RotationRequired || session.ExpiresAt <= s.lastObserved || session.ExpiresAt > s.lastObserved+905 {
		return nil, cryptox.ErrInvalidWire
	}
	s.token = session.Token
	s.expires = session.ExpiresAt
	keep = true
	return s, nil
}
func (s *DAGRecoverySession) Info() (DAGRecoveryInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(); e != nil {
		return DAGRecoveryInfo{}, e
	}
	return DAGRecoveryInfo{RecoveryGeneration: s.vault.RecoveryGeneration, Sequence: s.vault.Sequence, Environments: len(s.vault.Environments), RotationRequired: s.vault.RotationRequired, TrustedDevice: false, ExpiresAt: s.expires}, nil
}
func (s *DAGRecoverySession) refresh(ctx context.Context) error {
	if e := s.live(); e != nil {
		return e
	}
	var v DAGVault
	if e := s.request(ctx, "GET", dagPath("recovery-vault-v2"), s.token, nil, &v); e != nil {
		return e
	}
	gen := strconv.FormatUint(s.config.AccountGeneration, 10)
	if v.AccountID != s.config.AccountID || v.AccountGeneration != gen || v.Sequence < s.vault.Sequence || v.Sequence > 9007199254740991 || v.RecoverySigningPublicKey != cryptox.EncodeBase64(s.keys.SigningPublic) || v.RecoveryReceivingPublicKey != cryptox.EncodeBase64(s.keys.ReceivingPublic) || cryptox.VerifyTrustRoot(v.AccountID, gen, v.TrustRoot, s.keys.SigningPublic) != nil {
		return cryptox.ErrInvalidWire
	}
	root := v.TrustRoot
	pin := cryptox.PinnedIssuerRoot{AccountID: v.AccountID, AccountGeneration: gen, DeviceID: root.RootDeviceID, SigningPublicKey: root.RootSigningPublicKey, ReceivingPublicKey: root.RootReceivingPublicKey}
	if s.config.Pin != nil && *s.config.Pin != pin || s.pin.AccountID != "" && s.pin != pin {
		return cryptox.ErrInvalidSignature
	}
	bundle, e := cryptox.VerifyRecoveryDependencyBundle(pin, v.DependencyBundle)
	if e != nil {
		return e
	}
	proof, e := cryptox.VerifyIssuerRecoveryDAG(pin, v.IssuerEvidence)
	if e != nil {
		return e
	}
	checkpoint, e := bundle.RecoveryCheckpoint()
	if e != nil {
		return e
	}
	other, e := proof.RecoveryCheckpoint()
	if e != nil || checkpoint != other || checkpoint.RecoveryGeneration != v.RecoveryGeneration || checkpoint.SigningPublicKey != v.RecoverySigningPublicKey || checkpoint.ReceivingPublicKey != v.RecoveryReceivingPublicKey || checkpoint.TransitionHead != v.RecoveryHeadHash || checkpoint.AcceptedSequence > v.Sequence || validateDAGSequence(v.IssuerEvidence, v.Sequence) != nil {
		return cryptox.ErrInvalidWire
	}
	if e = validateDAGHistoryCheckpoint(s.config, v, proof); e != nil {
		return e
	}
	if s.proof != nil {
		if _, e = cryptox.VerifyRecoveryDAGAdvance(s.proof, v.IssuerEvidence); e != nil {
			return e
		}
	}
	if e = verifyDAGEnvelopeCommitments(v, proof); e != nil {
		return e
	}
	keys := map[string][]byte{}
	keep := false
	defer func() {
		if !keep {
			for _, k := range keys {
				clear(k)
			}
		}
	}()
	for _, row := range v.Environments {
		if _, ok := keys[row.EnvironmentID]; ok {
			return cryptox.ErrInvalidWire
		}
		packet, e := cryptox.DecodeBase64(row.Envelope, 80, 80)
		if e != nil {
			return e
		}
		key, e := cryptox.UnwrapEnvironmentKey(s.keys.ReceivingPrivate, cryptox.EnvelopeContext{AccountID: v.AccountID, AccountGeneration: gen, EnvironmentID: row.EnvironmentID, KeyVersion: row.KeyVersion, RecipientType: "recovery", RecipientID: v.AccountID, RecipientGeneration: v.RecoveryGeneration, RecipientPublicKey: v.RecoveryReceivingPublicKey}, packet)
		if e != nil {
			return e
		}
		keys[row.EnvironmentID] = key
	}
	last := uint64(0)
	ids := map[string]bool{}
	for _, event := range v.Events {
		m := event.Mutation.Mutation
		if event.Sequence <= last || event.Sequence > v.Sequence || event.Authorization == nil || ids[m.IdempotencyKey] || keys[m.EnvironmentID] == nil {
			return cryptox.ErrInvalidWire
		}
		last = event.Sequence
		ids[m.IdempotencyKey] = true
		if e = proof.VerifyHistoricalMutationSource(cryptox.SignedMutationWire{Mutation: m, Signature: event.Mutation.Signature}, cryptox.SignedGrantWire{Grant: event.Authorization.Grant, Signature: event.Authorization.Signature}); e != nil {
			return e
		}
		if m.Operation == "put" {
			packet, e := cryptox.DecodeBase64(m.Payload, 40, 1<<20)
			if e != nil {
				return e
			}
			value, e := cryptox.DecryptValue(keys[m.EnvironmentID], cryptox.ValueContext{AccountID: v.AccountID, AccountGeneration: gen, EnvironmentID: m.EnvironmentID, KeyVersion: m.KeyVersion, Name: m.Name}, packet)
			if e != nil {
				return e
			}
			clear(value)
		}
	}
	for _, k := range s.environmentKeys {
		clear(k)
	}
	s.environmentKeys = keys
	s.pin = pin
	s.vault = v
	s.proof = proof
	keep = true
	return nil
}
func verifyDAGEnvelopeCommitments(v DAGVault, proof *cryptox.VerifiedRecoveryDAG) error {
	current := map[string]cryptox.RecoveryEnvelope{}
	proven := map[string]bool{}
	for _, e := range v.Environments {
		if _, ok := current[e.EnvironmentID]; ok {
			return cryptox.ErrInvalidWire
		}
		current[e.EnvironmentID] = e
	}
	initial := v.DependencyBundle.Initialization.Proposal
	if initial.RecoveryGeneration == v.RecoveryGeneration {
		for _, e := range initial.Environments {
			if target, ok := current[e.EnvironmentID]; ok && target.KeyVersion == e.KeyVersion && target.Envelope == e.RecoveryEnvelope {
				proven[e.EnvironmentID] = true
			}
		}
	}
	for _, record := range v.DependencyBundle.Records {
		var root cryptox.TrustRoot
		var envs []cryptox.RecoveryEnvelope
		var seq uint64
		switch record.Kind {
		case "transition-v2":
			root = record.TransitionV2.Submission.NewTrustRoot
			envs = record.TransitionV2.Submission.Envelopes
			seq = record.TransitionV2.Sequence
		}
		if root == v.TrustRoot && seq <= v.Sequence {
			for _, e := range envs {
				if target, ok := current[e.EnvironmentID]; ok && target == e {
					proven[e.EnvironmentID] = true
				}
			}
		}
	}
	ev := v.EnvelopeEvidence
	if ev.Profile != "harmonia/recovery-envelope-evidence/v1" || ev.EnvironmentChanges == nil || len(ev.EnvironmentChanges) > 256 {
		return cryptox.ErrInvalidWire
	}
	seen := map[string]bool{}
	for _, e := range ev.EnvironmentChanges {
		c := e.Change.Change
		target, ok := current[c.EnvironmentID]
		base, err := strconv.ParseUint(c.ExpectedSequence, 10, 64)
		if err != nil || e.Sequence != base+1 || e.Sequence > v.Sequence || !ok || c.KeyVersion != target.KeyVersion || seen[c.EnvironmentID] || e.Origin == nil || proof.VerifyHistoricalGrant(e.Authorization) != nil || proof.VerifyEnvironmentOriginEvent(e.Change, *e.Origin, e.Authorization) != nil {
			return cryptox.ErrInvalidWire
		}
		seen[c.EnvironmentID] = true
		if c.RecoveryGeneration == v.RecoveryGeneration && c.RecoveryEnvelope == target.Envelope {
			proven[c.EnvironmentID] = true
		}
	}
	if len(current) == 0 || len(current) > 256 {
		return cryptox.ErrInvalidWire
	}
	for id := range current {
		if !proven[id] {
			return errors.New("recovery envelope lacks signed accepted commitment")
		}
	}
	return nil
}
