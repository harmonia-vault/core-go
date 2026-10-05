package syncclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func b2Preparation(t *testing.T, original ProtectedDAGOperation) DAGTransitionPreparation {
	t.Helper()
	x := original.Transition.Submission.Transition
	initial, err := original.Transition.DependencyBundle.Initialization.Hash()
	if err != nil {
		t.Fatal(err)
	}
	seq, _ := strconv.ParseUint(x.ExpectedSequence, 10, 64)
	expires, _ := strconv.ParseInt(x.ExpiresAt, 10, 64)
	challenge := DAGTransitionChallenge{OperationID: x.OperationID, ChallengeID: x.ChallengeID, Nonce: x.Nonce, ExpiresAt: expires, SessionHash: x.SessionHash, AccountGeneration: x.AccountGeneration, AuthorizationKind: x.AuthorizationKind, AuthorizerDeviceID: x.AuthorizerDeviceID, ExpectedSequence: x.ExpectedSequence, PreviousTransitionHash: x.PreviousTransitionHash, OldRecoveryGeneration: x.OldRecoveryGeneration, OldRecoverySigningPublicKey: x.OldRecoverySigningPublicKey, OldRecoveryReceivingPublicKey: x.OldRecoveryReceivingPublicKey, EnvironmentManifest: original.Transition.Submission.EnvironmentManifest, AuthoritySet: []cryptox.RecoveryAdminAuthority{}, DependencyBundle: original.Transition.DependencyBundle}
	p := DAGTransitionPreparation{Version: 1, Kind: original.Kind, AuthorizationKind: x.AuthorizationKind, Phase: "prepared", Endpoint: original.Endpoint, AccountID: original.AccountID, AccountGeneration: original.AccountGeneration, Pin: original.Pin, InitializationHash: initial, InitializationProposalHash: original.Transition.DependencyBundle.Initialization.Proof.ProposalHash, SessionHash: x.SessionHash, OperationID: x.OperationID, ExpectedSequence: seq, OldRecoveryGeneration: x.OldRecoveryGeneration, PreviousTransitionHash: x.PreviousTransitionHash, OldRecoverySigningPublicKey: x.OldRecoverySigningPublicKey, OldRecoveryReceivingPublicKey: x.OldRecoveryReceivingPublicKey, BaseBundle: original.Transition.DependencyBundle, EnvironmentManifest: original.Transition.Submission.EnvironmentManifest, Challenge: &challenge, NewRecoveryGeneration: x.NewRecoveryGeneration, NewSigningPublicKey: x.NewRecoverySigningPublicKey, NewReceivingPublicKey: x.NewRecoveryReceivingPublicKey}
	if err = ValidateDAGTransitionPreparation(p); err != nil {
		t.Fatal("valid public preparation prerequisite", err)
	}
	return p
}
func b2Intent(p DAGTransitionPreparation) DAGTransitionPreparation {
	p.Phase = "intent"
	p.Challenge = nil
	p.NewRecoveryGeneration = ""
	p.NewSigningPublicKey = ""
	p.NewReceivingPublicKey = ""
	return p
}

func clonePreparation(t *testing.T, p DAGTransitionPreparation) DAGTransitionPreparation {
	t.Helper()
	b, _ := json.Marshal(p)
	out, e := DecodeDAGTransitionPreparation(b)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestDAGPreparationStrictColdIdentityAndShape(t *testing.T) {
	p := b2Preparation(t, b2Original(t, checkedOriginal(t)))
	for _, p := range []DAGTransitionPreparation{b2Intent(p), p} {
		raw, _ := json.Marshal(p)
		if _, err := DecodeDAGTransitionPreparation(raw); err != nil {
			t.Fatal(err)
		}
	}
	edits := map[string]func(*DAGTransitionPreparation){
		"old-signing":    func(p *DAGTransitionPreparation) { p.OldRecoverySigningPublicKey = p.NewSigningPublicKey },
		"old-receiving":  func(p *DAGTransitionPreparation) { p.OldRecoveryReceivingPublicKey = p.NewReceivingPublicKey },
		"old-generation": func(p *DAGTransitionPreparation) { p.OldRecoveryGeneration = "999" },
		"old-head":       func(p *DAGTransitionPreparation) { p.PreviousTransitionHash = strings.Repeat("b", 64) },
		"init-hash":      func(p *DAGTransitionPreparation) { p.InitializationHash = strings.Repeat("b", 64) },
		"init-proposal":  func(p *DAGTransitionPreparation) { p.InitializationProposalHash = strings.Repeat("b", 64) },
		"bundle-signature": func(p *DAGTransitionPreparation) {
			p.BaseBundle.Initialization.Proof.ProposalHash = strings.Repeat("b", 64)
		},
		"session":            func(p *DAGTransitionPreparation) { p.SessionHash = strings.Repeat("b", 64) },
		"challenge-id":       func(p *DAGTransitionPreparation) { p.Challenge.OperationID = "different-id" },
		"challenge-basis":    func(p *DAGTransitionPreparation) { p.Challenge.ExpectedSequence = "999" },
		"challenge-head":     func(p *DAGTransitionPreparation) { p.Challenge.PreviousTransitionHash = strings.Repeat("b", 64) },
		"challenge-bundle":   func(p *DAGTransitionPreparation) { p.Challenge.DependencyBundle.Records = nil },
		"manifest":           func(p *DAGTransitionPreparation) { p.EnvironmentManifest = nil },
		"null-authority-set": func(p *DAGTransitionPreparation) { p.Challenge.AuthoritySet = nil },
		"zero-expiry":        func(p *DAGTransitionPreparation) { p.Challenge.ExpiresAt = 0 },
		"bad-nonce":          func(p *DAGTransitionPreparation) { p.Challenge.Nonce = "bad" },
		"new-generation":     func(p *DAGTransitionPreparation) { p.NewRecoveryGeneration = p.OldRecoveryGeneration },
		"new-key":            func(p *DAGTransitionPreparation) { p.NewSigningPublicKey = p.OldRecoverySigningPublicKey },
		"phase":              func(p *DAGTransitionPreparation) { p.Phase = "sealed" },
		"intent-mixed":       func(p *DAGTransitionPreparation) { p.Phase = "intent" },
		"prior-mixed":        func(p *DAGTransitionPreparation) { p.PriorContentHash = strings.Repeat("b", 64) },
		"prior-self": func(p *DAGTransitionPreparation) {
			p.PriorOperationID = p.OperationID
			p.PriorContentHash = strings.Repeat("b", 64)
			p.PriorAcceptedSequence = 1
		},
		"sequence-before-base": func(p *DAGTransitionPreparation) { p.ExpectedSequence = 1 },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			copy := clonePreparation(t, p)
			edit(&copy)
			raw, _ := json.Marshal(copy)
			if _, e := DecodeDAGTransitionPreparation(raw); e == nil {
				t.Fatal("cold typed validator accepted changed identity/basis")
			}
		})
	}
	raw, _ := json.Marshal(p)
	for name, edit := range map[string]func(map[string]json.RawMessage){
		"unknown":            func(m map[string]json.RawMessage) { m["trustedDevice"] = json.RawMessage(`true`) },
		"missing-zero-field": func(m map[string]json.RawMessage) { delete(m, "priorOperationId") },
		"null-zero-field":    func(m map[string]json.RawMessage) { m["priorOperationId"] = json.RawMessage(`null`) },
		"challenge-missing-field": func(m map[string]json.RawMessage) {
			var v map[string]json.RawMessage
			_ = json.Unmarshal(m["challenge"], &v)
			delete(v, "authorizerDeviceId")
			m["challenge"], _ = json.Marshal(v)
		},
		"challenge-null-field": func(m map[string]json.RawMessage) {
			var v map[string]json.RawMessage
			_ = json.Unmarshal(m["challenge"], &v)
			v["chainMode"] = json.RawMessage(`null`)
			m["challenge"], _ = json.Marshal(v)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]json.RawMessage
			_ = json.Unmarshal(raw, &m)
			edit(m)
			b, _ := json.Marshal(m)
			if _, e := DecodeDAGTransitionPreparation(b); e == nil {
				t.Fatal("ambiguous shape accepted")
			}
		})
	}
	for _, b := range [][]byte{append([]byte(`{"version":1,`), raw[1:]...), append(bytes.Clone(raw), []byte(` {}`)...), bytes.Repeat([]byte(" "), MaxDAGPreparationBytes+1)} {
		if _, e := DecodeDAGTransitionPreparation(b); e == nil {
			t.Fatal("ambiguous/oversize accepted")
		}
	}
	// A historical expiry is loadable, not inferred as authoritative closure.
	p.Challenge.ExpiresAt = 1
	if e := ValidateDAGTransitionPreparation(p); e != nil {
		t.Fatal("expired original became unloadable", e)
	}
}
func TestDAGPreparationPromotionRequiresExactPreparedPublicTuple(t *testing.T) {
	original := b2Original(t, checkedOriginal(t))
	p := b2Preparation(t, original)
	if e := validateProtectedDAGOperation(original); e != nil {
		t.Fatal("signed packet prerequisite", e)
	}
	if e := ValidateDAGPreparationPromotion(p, original); e != nil {
		t.Fatal("exact promotion", e)
	}
	for name, edit := range map[string]func(*DAGTransitionPreparation){
		"nonce": func(p *DAGTransitionPreparation) {
			p.Challenge.Nonce = cryptox.EncodeBase64(bytes.Repeat([]byte{7}, 32))
		},
		"new-key": func(p *DAGTransitionPreparation) {
			p.NewSigningPublicKey = cryptox.EncodeBase64(bytes.Repeat([]byte{8}, 32))
		},
		"session": func(p *DAGTransitionPreparation) {
			p.SessionHash = strings.Repeat("b", 64)
			p.Challenge.SessionHash = p.SessionHash
		},
		"id": func(p *DAGTransitionPreparation) {
			p.OperationID = "other-valid-id"
			p.Challenge.OperationID = p.OperationID
		},
		"sequence": func(p *DAGTransitionPreparation) {
			p.ExpectedSequence++
			p.Challenge.ExpectedSequence = strconv.FormatUint(p.ExpectedSequence, 10)
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := clonePreparation(t, p)
			edit(&copy)
			if e := ValidateDAGTransitionPreparation(copy); e != nil {
				t.Fatal("negative must reach promotion after valid preparation", e)
			}
			if e := ValidateDAGPreparationPromotion(copy, original); e == nil {
				t.Fatal("promoted different prepared tuple")
			}
		})
	}
	if !DAGPreparationSameIntent(b2Intent(p), p) {
		t.Fatal("phase promotion changed intent")
	}
	changed := clonePreparation(t, p)
	changed.ExpectedSequence++
	if DAGPreparationSameIntent(changed, p) {
		t.Fatal("new basis replaced original intent")
	}
}
func b2Original(t *testing.T, p ProtectedDAGOperation) ProtectedDAGOperation {
	t.Helper()
	raw, err := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public vector")
	}
	sub := f.Proof.Records[2].TransitionV2.Submission
	p.OperationID = sub.Transition.OperationID
	p.ContentHash, err = cryptox.RecoveryTransitionHashV2(sub)
	if err != nil {
		t.Fatal(err)
	}
	p.Transition = &cryptox.RecoveryTransitionCommandV2{Submission: sub, DependencyBundle: cryptox.RecoveryDependencyBundle{Initialization: f.Proof.Initialization, Records: f.Proof.Records[:2]}}
	return p
}

type b2MemoryPreparation struct {
	value DAGTransitionPreparation
	saves int
}

func (s *b2MemoryPreparation) LoadTransitionPreparation() (DAGTransitionPreparation, error) {
	return s.value, nil
}
func (s *b2MemoryPreparation) SaveTransitionPreparation(p DAGTransitionPreparation) error {
	s.value = p
	s.saves++
	return nil
}
func TestDAGPreparationRetryNeverRebasesOriginalIntent(t *testing.T) {
	p := b2Intent(b2Preparation(t, b2Original(t, checkedOriginal(t))))
	proof, err := cryptox.VerifyRecoveryDependencyBundle(p.Pin, p.BaseBundle)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := cryptox.DecodeBase64(p.OldRecoverySigningPublicKey, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	receiving, err := cryptox.DecodeBase64(p.OldRecoveryReceivingPublicKey, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	token := "synthetic-component-token"
	p.SessionHash = digest([]byte(token))
	store := &b2MemoryPreparation{value: p}
	now := time.Unix(100, 0)
	s := &DAGRecoverySession{config: DAGRecoveryConfig{Endpoint: p.Endpoint, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, Preparation: store, Now: func() time.Time { return now }}, token: token, expires: 400, keys: cryptox.RecoveryKeys{SigningPublic: signing, ReceivingPublic: receiving}, pin: p.Pin, proof: proof, vault: DAGVault{RecoveryGeneration: p.OldRecoveryGeneration, RecoveryHeadHash: p.PreviousTransitionHash, Sequence: p.ExpectedSequence, DependencyBundle: p.BaseBundle}}
	for _, row := range p.EnvironmentManifest {
		s.vault.Environments = append(s.vault.Environments, cryptox.RecoveryEnvelope{EnvironmentID: row.EnvironmentID, KeyVersion: row.KeyVersion})
	}
	if _, err = s.saveOriginalIntent(p.OperationID); err != nil || store.saves != 0 {
		t.Fatal("same original intent should not rewrite", err)
	}
	s.vault.Sequence++
	candidate, err := s.prepareIntent(p.OperationID)
	if err != nil || ValidateDAGTransitionPreparation(candidate) != nil {
		t.Fatal("changed sequence must be independently valid before immutable comparison", err)
	}
	if _, err = s.saveOriginalIntent(p.OperationID); !errors.Is(err, ErrDAGPreparationConflict) || store.saves != 0 || !sameJSON(store.value, p) {
		t.Fatal("refresh silently rebased original", err)
	}
}
