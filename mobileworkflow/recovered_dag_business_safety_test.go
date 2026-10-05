package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

// 公开合成向量构造完整密码学有效的已应用来源；不是平台认证或服务端接受证据。
func dagBusinessAppliedFixture(t *testing.T) (Config, *Workflow, *dagNativeSlot, syncclient.Pull) {
	t.Helper()
	c, w, slot := b3bConfirmedFixture(t)
	original := *w.state.RecoveryDAG
	gen, _ := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	p, e := syncclient.DecodeDAGJournal(syncclient.DAGJournalBinding{Endpoint: original.Endpoint, AccountID: original.AccountID, AccountGeneration: gen, OwnerEpoch: original.OwnerEpoch}, original.Journal)
	if e != nil {
		t.Fatal(e)
	}
	r, e := syncclient.RecoveredDAGResultFromConfirmedOperation(p)
	if e != nil {
		t.Fatal(e)
	}
	w.state.RecoveryDAG = nil
	w.state.Root = pointerRoot(recoveredDAGRoot(r))
	w.state.RecoveredDAGDevice = &recoveredDAGDeviceRecord{Version: 1, Profile: cryptox.RecoveryDAGCapability, Original: original}
	pull := syncclient.Pull{Full: true, AccountID: p.AccountID, AccountGeneration: strconv.FormatUint(gen, 10), Sequence: p.AcceptedSequence, IssuerDAGEvidence: &r.Evidence, Grants: []syncclient.SignedGrant{}}
	for _, g := range r.Accepted.Submission.Grants {
		pull.Grants = append(pull.Grants, syncclient.SignedGrant{Grant: g.Grant, Signature: g.Signature})
	}
	v, e := w.recoveredDAGVerifierLocked()
	if e != nil {
		t.Fatal(e)
	}
	snap, e := v.VerifyPull(context.Background(), pull, w.engine.State().Cloud)
	v.Close()
	if e != nil {
		t.Fatal("valid applied source", e)
	}
	if e = w.engine.AcceptDataSnapshotAtEpoch(snap, w.now(), w.engine.State().SessionEpoch); e != nil {
		t.Fatal(e)
	}
	w.state.Grants = r.Accepted.Submission.Grants
	w.state.Cloud = w.engine.State()
	if e = w.saveDAGCandidateLocked(clone(w.state)); e != nil {
		t.Fatal(e)
	}
	if e = w.validateRecoveredDAGDeviceLocked(); e != nil {
		t.Fatal(e)
	}
	return c, w, slot, pull
}
func pointerRoot(r cryptox.TrustRoot) *cryptox.TrustRoot { return &r }
func dagBusinessNone(t *testing.T, w *Workflow, p syncclient.Pull) syncclient.Pull {
	t.Helper()
	g := p.Grants[0].Grant
	g.Role, g.Envelope, g.GrantGeneration, g.IdempotencyKey = "none", "", "2", "synthetic-none"
	signed, e := cryptox.SignGrant(g, w.signing)
	if e != nil {
		t.Fatal(e)
	}
	p.Grants = []syncclient.SignedGrant{{Grant: signed.Grant, Signature: signed.Signature}}
	p.Sequence++
	return p
}
func dagBusinessResponse(w http.ResponseWriter, p syncclient.Pull) {
	_ = json.NewEncoder(w).Encode(map[string]any{"accountId": p.AccountID, "accountGeneration": p.AccountGeneration, "sequence": p.Sequence, "grants": p.Grants, "events": []any{}, "environmentEvents": []any{}, "issuerEvidence": p.IssuerDAGEvidence})
}

func TestDAGBusinessVerifiedPullPermissionDenialPersists(t *testing.T) {
	for _, changeAt := range []int32{1, 2} {
		t.Run(map[int32]string{1: "initial-pull", 2: "writer-pull"}[changeAt], func(t *testing.T) {
			c, w, slot, base := dagBusinessAppliedFixture(t)
			defer w.Close()
			revoked := dagBusinessNone(t, w, base)
			// 先证明负例来源本身可通过完整成熟验签，避免把来源拒绝误计成修复。
			probe, e := w.recoveredDAGVerifierLocked()
			if e != nil {
				t.Fatal(e)
			}
			snapshot, e := probe.VerifyPull(context.Background(), revoked, w.engine.State().Cloud)
			probe.Close()
			if e != nil || len(snapshot.Environments) != 0 {
				t.Fatal("valid signed none", e)
			}
			var pulls, posts atomic.Int32
			server := dagBusinessTLSServer(t, w, func(r *http.Request, out http.ResponseWriter) {
				if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/mutations") {
					posts.Add(1)
					out.WriteHeader(500)
					return
				}
				if pulls.Add(1) >= changeAt {
					dagBusinessResponse(out, revoked)
				} else {
					dagBusinessResponse(out, base)
				}
			})
			defer server.Close()
			dagBusinessRebindEndpoint(t, w, &c, server.URL)
			w.http = server.Client()
			if e := w.validateRecoveredDAGDeviceLocked(); e != nil {
				t.Fatal("rebound fixture", e)
			}
			result, e := w.SetDAGVariable(context.Background(), base.Grants[0].Grant.EnvironmentID, "TOKEN", "SYNTHETIC", "synthetic-denied")
			if !errors.Is(e, syncclient.ErrWritePermission) || result.View != nil || result.Write.Applied || posts.Load() != 0 {
				t.Fatalf("permission denial: %v; pullResponses=%d mutationPosts=%d", e, pulls.Load(), posts.Load())
			}
			c.ProtectedState = slot.read()
			cold, e := New(c)
			if e != nil {
				t.Fatal(e)
			}
			defer cold.Close()
			view, e := cold.RestoreDAGRecoveredDevice()
			if e != nil || len(view.View.Environments) != 0 || cold.state.Grants[0].Grant.Role != "none" {
				t.Fatal("known revocation resurrected", e)
			}
		})
	}
}

func TestDAGBusinessSavePullTrustCausePurgesOriginal(t *testing.T) {
	c, w, slot, base := dagBusinessAppliedFixture(t)
	defer w.Close()
	var pulls, posts atomic.Int32
	server := dagBusinessTLSServer(t, w, func(r *http.Request, out http.ResponseWriter) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/mutations") {
			posts.Add(1)
			out.WriteHeader(500)
			return
		}
		// initial + Writer预拉已成功；第三次恰为journal.Save的额外Pull。
		if pulls.Add(1) == 3 {
			out.WriteHeader(403)
			_, _ = out.Write([]byte(`{"error":"device_untrusted"}`))
			return
		}
		dagBusinessResponse(out, base)
	})
	defer server.Close()
	dagBusinessRebindEndpoint(t, w, &c, server.URL)
	w.http = server.Client()
	result, e := w.SetDAGVariable(context.Background(), base.Grants[0].Grant.EnvironmentID, "TOKEN", "SYNTHETIC", "synthetic-save-revoke")
	if !errors.Is(e, syncclient.ErrTrustInvalidated) || !errors.Is(e, syncclient.ErrWriteJournal) || result.View != nil || result.Write.Applied || posts.Load() != 0 || !w.closed {
		t.Fatal("terminal cause lost", e)
	}
	c.ProtectedState = slot.read()
	cold, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer cold.Close()
	if cold.state.Root != nil || cold.state.RecoveredDAGDevice != nil || cold.state.DAGWrites != nil || !cold.engine.State().AccountClosed || len(cold.engine.State().Cloud.Environments) != 0 {
		t.Fatal("terminal original survived")
	}
}

func TestDAGBusinessCancellationAfterVerificationSavesOnlySafety(t *testing.T) {
	for _, safety := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary-cancel", true: "verified-revoke-before-CAS"}[safety], func(t *testing.T) {
			_, owner, slot, p := dagBusinessAppliedFixture(t)
			defer owner.Close()
			before := slot.read()
			state := clone(owner.state)
			epoch := owner.engine.State().SessionEpoch
			candidate := &Workflow{state: state, signing: bytes.Clone(owner.signing), receiving: bytes.Clone(owner.receiving), now: owner.now}
			defer clear(candidate.signing)
			defer clear(candidate.receiving)
			candidate.store = &memoryStore{state: clone(owner.engine.State())}
			candidate.engine, _ = localstate.New(candidate.store)
			candidate.verifier, _ = owner.recoveredDAGVerifierLocked()
			defer candidate.verifier.Close()
			if safety {
				p = dagBusinessNone(t, owner, p)
			}
			snap, e := candidate.verifier.VerifyPull(context.Background(), p, candidate.engine.State().Cloud)
			if e != nil {
				t.Fatal(e)
			}
			if e = candidate.engine.AcceptDataSnapshotAtEpoch(snap, owner.now(), epoch); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			journal := &dagActiveWriteLog{owner: owner, candidate: candidate, ctx: ctx, hash: owner.protectedSHA256, epoch: epoch}
			if safety {
				oldCheck := owner.checkNativeState
				owner.checkNativeState = func(hash string) error { e := oldCheck(hash); cancel(); return e }
			} else {
				cancel()
			}
			e = journal.commitVerifiedPull(ctx, p)
			if !errors.Is(e, context.Canceled) || errors.Is(e, ErrDAGAuthorizationNotPersisted) {
				t.Fatal("cancel classification", e)
			}
			if safety {
				got := owner.engine.State().Cloud
				if len(got.Environments) != 0 || got.Sequence != state.Cloud.Cloud.Sequence || got.AuthorizationSequence != p.Sequence || bytes.Equal(before, slot.read()) {
					t.Fatal("safe projection not saved")
				}
			} else if !bytes.Equal(before, slot.read()) {
				t.Fatal("ordinary cancel changed protected source")
			}
		})
	}
}

func dagBusinessTLSServer(t *testing.T, w *Workflow, pull func(*http.Request, http.ResponseWriter)) *httptest.Server {
	t.Helper()
	gen := w.state.AccountGeneration
	nonce := cryptox.EncodeBase64(make([]byte, 32))
	expiryTime := w.now().Add(time.Minute).Unix()
	expiry := strconv.FormatInt(expiryTime, 10)
	proof, e := cryptox.NewDeviceBootProof(w.state.AccountID, gen, w.state.DeviceID, w.signing.Public().(ed25519.PublicKey), publicReceiving(t, w.receiving), "synthetic-boot", nonce, expiry)
	if e != nil {
		t.Fatal(e)
	}
	payload, e := proof.SigningBytes()
	if e != nil {
		t.Fatal(e)
	}
	var fields []string
	_ = json.Unmarshal(payload, &fields)
	return httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		out.Header().Set("Harmonia-Protocol-Major", "2")

		out.Header().Set("Harmonia-Protocol-Major", "2")
		switch {
		case strings.HasSuffix(r.URL.Path, "/boot-challenges"):
			_ = json.NewEncoder(out).Encode(map[string]any{"challengeId": "synthetic-boot", "nonce": nonce, "expiresAt": expiryTime, "signingPayload": fields})
		case strings.HasSuffix(r.URL.Path, "/boot-sessions"):
			var body struct {
				Signature         string `json:"signature"`
				DeviceID          string `json:"deviceId"`
				AccountGeneration string `json:"accountGeneration"`
				ChallengeID       string `json:"challengeId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if e = cryptox.VerifyDeviceBootProof(proof, body.Signature, w.signing.Public().(ed25519.PublicKey)); e != nil {
				out.WriteHeader(403)
				return
			}
			_ = json.NewEncoder(out).Encode(map[string]any{"token": cryptox.EncodeBase64(bytes.Repeat([]byte{1}, 32)), "expiresAt": expiryTime})
		default:
			pull(r, out)
		}
	}))
}

func publicReceiving(t *testing.T, raw []byte) []byte {
	t.Helper()
	k, e := ecdh.X25519().NewPrivateKey(raw)
	if e != nil {
		t.Fatal(e)
	}
	return k.PublicKey().Bytes()
}

// 仅公开向量夹具换到本次TLS端点，签包不绑定HTTP地址；不改变任何权源或accepted记录。
func dagBusinessRebindEndpoint(t *testing.T, w *Workflow, c *Config, url string) {
	t.Helper()
	r := &w.state.RecoveredDAGDevice.Original
	p, e := syncclient.DecodeDAGJournal(syncclient.DAGJournalBinding{Endpoint: r.Endpoint, AccountID: r.AccountID, AccountGeneration: r.AccountGeneration, OwnerEpoch: r.OwnerEpoch}, r.Journal)
	if e != nil {
		t.Fatal(e)
	}
	p.Endpoint = url
	raw, e := json.Marshal(struct {
		OwnerEpoch uint64                           `json:"ownerEpoch"`
		Operation  syncclient.ProtectedDAGOperation `json:"operation"`
	}{r.OwnerEpoch, p})
	if e != nil {
		t.Fatal(e)
	}
	r.Endpoint, r.Journal = url, raw
	w.state.Endpoint = url
	c.Endpoint = url
	if e = w.saveDAGCandidateLocked(clone(w.state)); e != nil {
		t.Fatal(e)
	}
}
