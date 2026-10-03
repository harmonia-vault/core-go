package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

// 使用公开且密码学有效的图核验实际Root/currentCloud分支。
// baseline只保留闭锁操作前的合法前缀；这不是完整Boot/Pull验收。
func TestDAGResolutionCurrentEvidenceRejectsContradiction(t *testing.T) {
	for _, mode := range []string{"same-operation-id", "different-id-same-global-sequence"} {
		t.Run(mode, func(t *testing.T) {
			_, w, _, p, slot := resolutionFixture(t)
			defer w.Close()
			candidate := resolutionClosedCandidate(t, w, resolutionPlanFixture(t, w, p))
			r := candidate.RecoveryDAGResolution
			if mode == "different-id-same-global-sequence" {
				entry := &r.Closed[0]
				entry.Target.OperationID = "synthetic-distinct-closed-operation"
				hashText := func(text string) string { h := sha256.Sum256([]byte(text)); return hex.EncodeToString(h[:]) }
				entry.Target.DeclaredIntentHash = hashText("synthetic other sealed original")
				entry.Target.KnownChallengeHash = hashText("synthetic other challenge")
				entry.Target.DeclaredContentHash = hashText("synthetic other content")
				entry.TargetHash, _ = entry.Target.Hash()
				entry.OriginalPublicDigest = entry.Target.DeclaredIntentHash
				entry.Receipt.OperationID = entry.Target.OperationID
				entry.Receipt.TargetHash = entry.TargetHash
				known := entry.Target.KnownChallengeHash
				entry.Receipt.ObservedChallengeHash = &known
			}
			if err := validateDAGResolutionState(candidate); err != nil {
				t.Fatal("closed baseline must be legal before attaching current evidence", err)
			}
			raw, err := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
			if err != nil {
				t.Fatal(err)
			}
			var f struct {
				Pin   cryptox.PinnedIssuerRoot  `json:"rootPin"`
				Proof cryptox.IssuerRecoveryDAG `json:"proof"`
			}
			if err = json.Unmarshal(raw, &f); err != nil {
				t.Fatal(err)
			}
			if _, err = cryptox.VerifyIssuerRecoveryDAG(f.Pin, f.Proof); err != nil {
				t.Fatal("current accepted graph must be cryptographically valid", err)
			}
			prior, err := cryptox.VerifyRecoveryDependencyBundle(r.Baseline.Pin, r.Baseline.DependencyBundle)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = cryptox.VerifyRecoveryDAGAdvance(prior, f.Proof); err != nil {
				t.Fatal("valid advance prerequisite", err)
			}
			if err = retainsResolutionRecords(r.Baseline.DependencyBundle.Records, f.Proof.Records); err != nil {
				t.Fatal("all old accepted records retained", err)
			}
			accepted := f.Proof.Records[2].TransitionV2
			if accepted.Sequence != r.Closed[0].Receipt.Sequence {
				t.Fatal("fixture does not collide on global sequence")
			}
			if mode == "same-operation-id" && accepted.Submission.Transition.OperationID != r.Closed[0].Target.OperationID {
				t.Fatal("fixture does not collide on ID")
			}
			if mode != "same-operation-id" && accepted.Submission.Transition.OperationID == r.Closed[0].Target.OperationID {
				t.Fatal("distinct-ID fixture invalid")
			}
			initial := f.Proof.Initialization.Proposal
			candidate.Root = &cryptox.TrustRoot{RootDeviceID: initial.Device.ID, RootSigningPublicKey: initial.Device.SigningPublicKey, RootReceivingPublicKey: initial.Device.ReceivingPublicKey, RecoveryGeneration: initial.RecoveryGeneration, RecoverySigningPublicKey: initial.RecoverySigningPublicKey, RecoveryReceivingPublicKey: initial.RecoveryReceivingPublicKey, Signature: initial.TrustRootSignature}
			rootKey, err := cryptox.DecodeBase64(candidate.Root.RecoverySigningPublicKey, 32, 32)
			if err != nil || cryptox.VerifyTrustRoot(candidate.AccountID, candidate.AccountGeneration, *candidate.Root, rootKey) != nil {
				t.Fatal("valid signed root prerequisite", err)
			}
			candidate.Cloud.Cloud.AccountID = candidate.AccountID
			candidate.Cloud.Cloud.AccountGeneration = p.AccountGeneration
			candidate.Cloud.Cloud.Sequence = 42
			candidate.Cloud.Cloud.AuthorizationSequence = 42
			candidate.Cloud.Cloud.IssuerEvidence, err = json.Marshal(f.Proof)
			if err != nil {
				t.Fatal(err)
			}
			if err = validateDAGResolutionState(candidate); !errors.Is(err, syncclient.ErrDAGClosedHistoryConflict) {
				t.Fatal("current accepted evidence escaped exact closed conflict gate", err)
			}
			before := slot.read()
			if err = w.saveDAGCandidateLocked(candidate); !errors.Is(err, syncclient.ErrDAGClosedHistoryConflict) || !bytes.Equal(before, slot.read()) {
				t.Fatal("conflicting candidate changed native state", err)
			}
		})
	}
}

// 以下传输仅返回公开合成向量，不提供真实服务或TLS证据。
// 完整正常 opener 仍执行实际固定域的proof握手和完整图验证。
type resolutionHistoryTransport struct {
	t                                              *testing.T
	proof                                          cryptox.RecoveryProof
	vault                                          map[string]any
	now                                            int64
	recoveryPublic                                 ed25519.PublicKey
	proofRequests, vaultRequests, originalRequests int
}

func (s *resolutionHistoryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var body any
	switch {
	case strings.HasSuffix(r.URL.Path, "/protocol-info"):
		body = map[string]any{"supportedProtocolMajors": []uint8{2}, "capabilities": map[string][]string{"2": {cryptox.RecoveryDAGCapability}}}
	case strings.HasSuffix(r.URL.Path, "/recovery-challenges"):
		s.proofRequests++
		raw, e := s.proof.SigningBytes()
		if e != nil {
			return nil, e
		}
		var fields []string
		_ = json.Unmarshal(raw, &fields)
		body = map[string]any{"challengeId": s.proof.ChallengeID, "nonce": s.proof.Nonce, "expiresAt": s.now + 60, "recoveryGeneration": s.proof.RecoveryGeneration, "signingPayload": fields}
	case strings.HasSuffix(r.URL.Path, "/recovery-sessions"):
		var submitted struct{ AccountGeneration, ChallengeID, Signature string }
		if json.NewDecoder(r.Body).Decode(&submitted) != nil || cryptox.VerifyRecoveryProof(s.proof, submitted.Signature, s.recoveryPublic) != nil {
			return nil, errors.New("synthetic proof signature rejected")
		}
		body = map[string]any{"token": cryptox.EncodeBase64(bytes.Repeat([]byte{77}, 32)), "expiresAt": s.now + 120, "rotationRequired": true}
	case strings.HasSuffix(r.URL.Path, "/recovery-vault-v2"):
		s.vaultRequests++
		body = s.vault
	default:
		s.originalRequests++
		return nil, errors.New("synthetic unexpected original request")
	}
	raw, e := json.Marshal(body)
	if e != nil {
		return nil, e
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Harmonia-Protocol-Major": []string{"2"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
}
func resolutionCurrentTransport(t *testing.T) (*resolutionHistoryTransport, []byte) {
	t.Helper()
	raw, e := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Now   int64                     `json:"syntheticNow"`
		Seeds map[string]string         `json:"syntheticSeedsHex"`
		Pin   cryptox.PinnedIssuerRoot  `json:"rootPin"`
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public synthetic fixture")
	}
	graph, e := cryptox.VerifyIssuerRecoveryDAG(f.Pin, f.Proof)
	if e != nil {
		t.Fatal(e)
	}
	point, e := graph.RecoveryCheckpoint()
	if e != nil {
		t.Fatal(e)
	}
	public, e := cryptox.DecodeBase64(point.SigningPublicKey, 32, 32)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := hex.DecodeString(f.Seeds["thirdRecovery"])
	if e != nil {
		t.Fatal(e)
	}
	defer clear(seed)
	code, e := cryptox.EncodeRecoveryCode(seed)
	if e != nil {
		t.Fatal(e)
	}
	proof := cryptox.RecoveryProof{AccountID: f.Pin.AccountID, AccountGeneration: f.Pin.AccountGeneration, RecoveryGeneration: point.RecoveryGeneration, ChallengeID: "synthetic-current-recovery-challenge", Nonce: cryptox.EncodeBase64(bytes.Repeat([]byte{66}, 32)), ExpiresAt: strconv.FormatInt(f.Now+60, 10)}
	vault := map[string]any{"accountId": f.Pin.AccountID, "accountGeneration": f.Pin.AccountGeneration, "recoveryGeneration": point.RecoveryGeneration, "recoverySigningPublicKey": point.SigningPublicKey, "recoveryReceivingPublicKey": point.ReceivingPublicKey, "rotationRequired": true, "sequence": 60, "dependencyBundle": cryptox.RecoveryDependencyBundle{Initialization: f.Proof.Initialization, Records: f.Proof.Records}, "issuerEvidence": f.Proof, "trustRoot": f.Proof.Source.View.TrustRoot, "recoveryHeadHash": point.TransitionHead, "publicDevices": []any{}, "currentGrants": []any{}, "grantHistory": []any{}, "environments": f.Proof.Records[4].TransitionV2.Submission.Envelopes, "events": []any{}, "envelopeEvidence": map[string]any{"profile": "harmonia/recovery-envelope-evidence/v1", "environmentChanges": []any{}, "recoveryRotations": []any{}}}
	return &resolutionHistoryTransport{t: t, proof: proof, vault: vault, now: f.Now, recoveryPublic: ed25519.PublicKey(public)}, []byte(code)
}

func TestDAGResolutionNewOwnerAndOriginalQueryRejectIncomingClosedHistory(t *testing.T) {
	for _, mode := range []string{"new-owner", "original-query"} {
		t.Run(mode, func(t *testing.T) {
			_, w, _, p, slot := resolutionFixture(t)
			defer w.Close()
			candidate := resolutionClosedCandidate(t, w, resolutionPlanFixture(t, w, p))
			if e := w.saveDAGCandidateLocked(candidate); e != nil {
				t.Fatal(e)
			}
			tr, code := resolutionCurrentTransport(t)
			defer clear(code)
			w.http = &http.Client{Transport: tr}
			w.now = func() time.Time { return time.Unix(tr.now, 0) }
			if mode == "original-query" {
				// 独立新ID的合法原签包before不含closed；本次返回的完整历史才引入矛盾。
				sub := clone(p.Transition.Submission)
				sub.Transition.OperationID = "synthetic-pending-after-closure"
				beforeGraph, e := cryptox.VerifyRecoveryDependencyBundle(p.Pin, p.Transition.DependencyBundle)
				if e != nil {
					t.Fatal(e)
				}
				oldKeys, e := cryptox.DeriveRecoveryKeys(bytes.Repeat([]byte{0x43}, 32), p.AccountID, p.Pin.AccountGeneration, "2")
				if e != nil {
					t.Fatal(e)
				}
				defer clear(oldKeys.SigningPrivate)
				defer clear(oldKeys.ReceivingPrivate)
				newKeys, e := cryptox.DeriveRecoveryKeys(bytes.Repeat([]byte{0x44}, 32), p.AccountID, p.Pin.AccountGeneration, "3")
				if e != nil {
					t.Fatal(e)
				}
				defer clear(newKeys.SigningPrivate)
				defer clear(newKeys.ReceivingPrivate)
				sub.AuthorizationSignature, e = cryptox.SignOldRecoveryTransitionV2(beforeGraph, sub, oldKeys.SigningPrivate, w.now())
				if e != nil {
					t.Fatal(e)
				}
				sub.NewRecoverySignature, e = cryptox.SignNewRecoveryTransitionV2(beforeGraph, sub, newKeys.SigningPrivate, w.now())
				if e != nil {
					t.Fatal(e)
				}
				next := clone(p)
				next.OperationID = sub.Transition.OperationID
				next.Transition.Submission = sub
				next.ContentHash, e = cryptox.RecoveryTransitionHashV2(sub)
				if e != nil {
					t.Fatal(e)
				}
				journal, e := w.newRecoveryDAGJournal()
				if e != nil {
					t.Fatal(e)
				}
				if e = journal.Save(next); e != nil {
					t.Fatal("legitimate unrelated pending original prerequisite", e)
				}
			}
			before := slot.read()
			var err error
			if mode == "new-owner" {
				scope := DAGOwnerScope{Namespace: "synthetic", Slot: "closed-history"}
				reg, e := NewDAGRecoveryRegistry(scope)
				if e != nil {
					t.Fatal(e)
				}
				defer reg.Close()
				info, e := w.BeginDAGRecoveryAfterClosure(context.Background(), reg, scope, code)
				err = e
				if info.TrustedDevice || !info.RotationRequired {
					t.Fatal("failed opener returned trust")
				}
				reg.mu.Lock()
				entry := reg.current
				retired := entry != nil && entry.retired.Load()
				reg.mu.Unlock()
				if !retired {
					t.Fatal("failed current owner stayed live")
				}
				select {
				case <-entry.closed:
				default:
					t.Fatal("failed current owner did not clear process material")
				}
			} else {
				info, e := w.QueryRecoveryDAGOriginal(context.Background(), code)
				err = e
				if info.TrustedDevice || info.Observation != "unknown" {
					t.Fatal("failed query guessed terminal/trust")
				}
			}
			if !errors.Is(err, syncclient.ErrDAGClosedHistoryConflict) || tr.proofRequests != 1 || tr.vaultRequests != 1 || tr.originalRequests != 0 || !bytes.Equal(before, slot.read()) {
				t.Fatal("incoming history bypassed protected closed bounds", err, tr.proofRequests, tr.vaultRequests, tr.originalRequests)
			}
		})
	}
}

func TestDAGResolutionJournalAncestorsRejectClosedWithoutNativeSave(t *testing.T) {
	_, w, _, p, slot := resolutionFixture(t)
	defer w.Close()
	candidate := resolutionClosedCandidate(t, w, resolutionPlanFixture(t, w, p))
	if e := w.saveDAGCandidateLocked(candidate); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public graph")
	}
	next := clone(p)
	sub := f.Proof.Records[4].TransitionV2.Submission
	next.OperationID = sub.Transition.OperationID
	next.ContentHash, e = cryptox.RecoveryTransitionHashV2(sub)
	if e != nil {
		t.Fatal(e)
	}
	next.Transition = &cryptox.RecoveryTransitionCommandV2{Submission: sub, DependencyBundle: cryptox.RecoveryDependencyBundle{Initialization: f.Proof.Initialization, Records: f.Proof.Records[:4]}}
	journal, e := w.newRecoveryDAGJournal()
	if e != nil {
		t.Fatal(e)
	}
	before := slot.read()
	if e = journal.Save(next); !errors.Is(e, syncclient.ErrDAGClosedHistoryConflict) || !bytes.Equal(before, slot.read()) || w.state.RecoveryDAG != nil {
		t.Fatal("new journal ancestor contradicted closure or changed durable state", e)
	}
}
