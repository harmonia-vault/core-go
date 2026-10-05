//go:build harmonia_boringssl && cgo && (darwin || linux)

package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/pairing"
	"github.com/harmonia-vault/core-go/syncclient"
)

type approvalFixture struct {
	base             *selfFixture
	mu               sync.Mutex
	status           syncclient.PairingStatusV5
	peer             *pairing.Session
	peerKey          ed25519.PrivateKey
	peerReceive      []byte
	shortCode        []byte
	posts            [][]byte
	sealed           atomic.Bool
	failSave         atomic.Bool
	savePrepared     atomic.Bool
	dropResponse     bool
	dropBeforeAccept bool
	failAttemptSeal  atomic.Bool
	invalidate       bool
	alter            string
	complete         bool
}

func newApprovalFixture(t *testing.T) *approvalFixture {
	t.Helper()
	base := newSelfFixture(t)
	base.now.Store(time.Now().Unix())
	f := &approvalFixture{base: base, shortCode: []byte("12345678")}
	public, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.peerKey = key
	rp, rk, err := cryptox.GenerateReceivingKey()
	if err != nil {
		t.Fatal(err)
	}
	f.peerReceive = rk
	c := pairing.Context{AccountID: base.account, AccountGeneration: "1", Purpose: pairing.PurposeEnrollment, SessionID: "actual-phone-CLI", ChallengeNonce: cryptox.EncodeBase64(bytes.Repeat([]byte{23}, 32)), ExpiresAt: strconv.FormatInt(time.Now().Add(110*time.Second).Unix(), 10), InitiatorDeviceID: "candidate-CLI", InitiatorSigningPublicKey: cryptox.EncodeBase64(public), InitiatorReceivingPublicKey: cryptox.EncodeBase64(rp), ApproverDeviceID: base.device, ApproverSigningPublicKey: cryptox.EncodeBase64(base.public), ApproverReceivingPublicKey: cryptox.EncodeBase64(base.receivingPublic)}
	var message []byte
	f.peer, message, err = pairing.NewInitiator(c, f.shortCode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.peer.Close)
	f.status = syncclient.PairingStatusV5{State: "pending", IdempotencyKey: "pair-native", CertificateVersion: "5", Capabilities: []string{cryptox.RecoveryDAGCapability}, PairingProfile: pairing.Profile, Context: c, Messages: map[string]string{"initiator": cryptox.EncodeBase64(message)}, Confirmations: map[string]string{}}
	var state protectedState
	if json.Unmarshal(base.config.ProtectedState, &state) != nil {
		t.Fatal("fixture context")
	}
	state.InitialAuthorities = []cryptox.SignedGrantWire{cryptox.GrantToWire(base.grant)}
	base.config.ProtectedState = mustApproval(json.Marshal(state))
	old := base.server.Config.Handler
	base.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		if !strings.Contains(r.URL.Path, "/pairings-v5/") {
			old.ServeHTTP(w, r)
			return
		}
		f.handle(w, r)
	})
	base.config.SaveProtectedState = func(data []byte) error {
		var st protectedState
		if json.Unmarshal(data, &st) != nil {
			return errors.New("invalid seal")
		}
		if st.PendingApprovalV5 != nil {
			if f.failSave.Load() {
				return errors.New("synthetic AES save failed")
			}
			if st.PendingApprovalV5.Attempted {
				if f.failAttemptSeal.Load() {
					return errors.New("attempted AES save failed")
				}
				f.sealed.Store(true)
			} else {
				f.savePrepared.Store(true)
			}
		}
		base.native = bytes.Clone(data)
		return nil
	}
	return f
}
func mustApproval[T any](v T, e error) T {
	if e != nil {
		panic(e)
	}
	return v
}
func (f *approvalFixture) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	write := func(s syncclient.PairingStatusV5) { _ = json.NewEncoder(w).Encode(s) }
	if r.Header.Get("X-Harmonia-Device-Id") != f.base.device || r.Header.Get("X-Harmonia-Account-Generation") != "1" || !f.base.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
		f.base.t.Error("not a bound manager session")
		w.WriteHeader(403)
		return
	}
	if f.invalidate {
		w.WriteHeader(403)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "admin_required"})
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, cryptox.MaxRecoveryAuthorityBytes+1))
	if bytes.Contains(body, f.shortCode) {
		f.base.t.Error("short code reached HTTP")
	}
	if r.Method == "GET" {
		s := clone(f.status)
		switch f.alter {
		case "manager-key":
			s.Context.ApproverSigningPublicKey = cryptox.EncodeBase64(bytes.Repeat([]byte{27}, 32))
		case "generation":
			s.Context.AccountGeneration = "2"
		case "capability":
			s.Capabilities = nil
		case "purpose":
			s.Context.Purpose = "recover"
		}
		write(s)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/relay") {
		var wire struct{ Side, Kind, Payload, Signature string }
		if json.Unmarshal(body, &wire) != nil {
			w.WriteHeader(400)
			return
		}
		c := f.status.Context
		relay := cryptox.PairingRelay{AccountID: c.AccountID, AccountGeneration: c.AccountGeneration, SessionID: c.SessionID, ChallengeNonce: c.ChallengeNonce, Side: wire.Side, Kind: wire.Kind, Payload: wire.Payload}
		if wire.Side != "approver" || cryptox.VerifyPairingRelay(relay, wire.Signature, f.base.public) != nil {
			f.base.t.Error("invalid manager relay")
			w.WriteHeader(403)
			return
		}
		if wire.Kind == "message" {
			f.status.Messages["approver"] = wire.Payload
			peer, _ := cryptox.DecodeBase64(wire.Payload, 32, 32)
			mac, err := f.peer.Complete(peer)
			if err != nil {
				f.base.t.Error(err)
				w.WriteHeader(500)
				return
			}
			f.status.Confirmations["initiator"] = cryptox.EncodeBase64(mac)
		} else {
			f.status.Confirmations["approver"] = wire.Payload
			mac, _ := cryptox.DecodeBase64(wire.Payload, 32, 32)
			_ = f.peer.VerifyPeerConfirmation(mac)
		}
		write(f.status)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/approve") {
		if !f.sealed.Load() {
			f.base.t.Error("POST before attempted journal actually sealed")
			w.WriteHeader(500)
			return
		}
		var input struct {
			CertificateVersion string                    `json:"certificateVersion"`
			Capabilities       []string                  `json:"capabilities"`
			Grants             []cryptox.SignedGrantWire `json:"grants"`
			TranscriptHash     string                    `json:"transcriptHash"`
			IssuerProof        cryptox.IssuerRecoveryDAG `json:"issuerProof"`
			Signature          string                    `json:"signature"`
		}
		d := json.NewDecoder(bytes.NewReader(body))
		d.DisallowUnknownFields()
		if d.Decode(&input) != nil || input.CertificateVersion != "5" || len(input.Capabilities) != 1 || input.Capabilities[0] != cryptox.RecoveryDAGCapability {
			f.base.t.Error("invalid approve schema")
			w.WriteHeader(400)
			return
		}
		transcript, err := f.peer.TranscriptHash()
		if err != nil || transcript != input.TranscriptHash {
			f.base.t.Error("not confirmed peer transcript")
			w.WriteHeader(403)
			return
		}
		a := cryptox.EnrollmentApprovalV5{CertificateVersion: "5", Capabilities: []string{cryptox.RecoveryDAGCapability}, Context: cryptox.EnrollmentContext(f.status.Context), PairingProfile: pairing.Profile, TranscriptHash: input.TranscriptHash, Grants: input.Grants, IssuerProof: input.IssuerProof, ApproverSignature: input.Signature}
		anchor := cryptox.ConfirmedEnrollmentAnchor{Context: a.Context, TranscriptHash: transcript}
		if _, err = cryptox.VerifyEnrollmentApprovalV5(anchor, a); err != nil {
			f.base.t.Error(err)
			w.WriteHeader(403)
			return
		}
		g := a.Grants[0].Grant
		packet := mustApproval(cryptox.DecodeBase64(g.Envelope, 80, 80))
		key, err := cryptox.UnwrapEnvironmentKey(f.peerReceive, cryptox.EnvelopeContext{AccountID: f.base.account, AccountGeneration: "1", EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey}, packet)
		if err != nil || len(key) != 32 {
			f.base.t.Error("actual CLI HPKE failed", err)
			w.WriteHeader(403)
			return
		}
		clear(key)
		f.posts = append(f.posts, bytes.Clone(body))
		if f.dropBeforeAccept {
			w.WriteHeader(504)
			return
		}
		f.status.State = "approved"
		f.status.Approval = &a
		if f.complete {
			cert := mustApproval(a.Certificate())
			a.InitiatorSignature = mustApproval(cryptox.SignEnrollmentCertificateV5(cert, f.peerKey))
			f.status.Approval = &a
			seq := uint64(3)
			f.status.Sequence = &seq
			f.status.State = "complete"
		}
		if f.dropResponse {
			w.WriteHeader(504)
			return
		}
		write(f.status)
		return
	}
	w.WriteHeader(404)
}
func approvalInput() ApprovalInput {
	return ApprovalInput{PairingID: "pair-native", ShortCode: []byte("12345678"), Selections: []ApprovalSelection{{EnvironmentID: "env", Role: "ro", ExpiresAt: "0"}}}
}
func TestNativeApprovalRealPAKEHPKEAndOriginalJournalRecovery(t *testing.T) {
	f := newApprovalFixture(t)
	w, err := New(f.base.config)
	if err != nil {
		t.Fatal(err)
	}
	f.dropResponse = true
	result, err := w.ApprovePairingV5(context.Background(), approvalInput())
	if !errors.Is(err, ErrApprovalPending) || result.State != "unknown" || len(f.posts) != 1 || !f.savePrepared.Load() || !f.sealed.Load() {
		t.Fatal("lost reply not pending", result, err)
	}
	if _, err = w.View(); !errors.Is(err, ErrApprovalPending) {
		t.Fatal("unknown approval allowed ordinary vault view")
	}
	if err = w.CancelApprovalV5("pair-native"); !errors.Is(err, ErrApprovalPending) {
		t.Fatal("inflight approval canceled without terminal server proof")
	}
	if _, err = w.RevokeSelf(context.Background(), "revoke-while-approval"); !errors.Is(err, ErrApprovalPending) {
		t.Fatal("self revoke bypassed pending approval")
	}
	original := clone(w.state.PendingApprovalV5)
	if bytes.Contains(f.base.native, []byte("12345678")) || bytes.Contains(f.base.native, []byte("sessionToken")) {
		t.Fatal("journal stored PAKE code/token")
	}
	w.Close()
	f.base.config.ProtectedState = bytes.Clone(f.base.native)
	w, err = New(f.base.config)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	result, err = w.RetryApprovalV5(context.Background(), "pair-native")
	if err != nil || result.State != "approved" || result.Sequence != 0 || len(f.posts) != 1 || !sameJSONValue(original.Approval, w.state.PendingApprovalV5.Approval) {
		t.Fatal("retry rewrote original package or falsely trusted CLI", result, err)
	}
	if input := approvalInput(); true {
		input.Selections[0].Role = "admin"
		if _, err = w.ApprovePairingV5(context.Background(), input); !errors.Is(err, syncclient.ErrWriteConflict) {
			t.Fatal("unknown result changed role")
		}
	}
	f.mu.Lock()
	a := *f.status.Approval
	cert := mustApproval(a.Certificate())
	a.InitiatorSignature = mustApproval(cryptox.SignEnrollmentCertificateV5(cert, f.peerKey))
	f.status.Approval = &a
	f.status.State = "complete"
	seq := uint64(3)
	f.status.Sequence = &seq
	f.mu.Unlock()
	result, err = w.RetryApprovalV5(context.Background(), "pair-native")
	if err != nil || result.State != "complete" || result.Sequence != 3 {
		t.Fatal("real CLI dual-sign completion not observed", result, err)
	}
	if _, err = w.View(); err != nil {
		t.Fatal("complete record kept ordinary view blocked", err)
	}
}
func TestNativeApprovalRefusesWrongCodeContextAndAuthority(t *testing.T) {
	for _, bad := range []string{"wrong-code", "manager-key", "generation", "purpose", "capability", "missing-initial", "other-env", "invalid-role", "expired", "changed-source"} {
		t.Run(bad, func(t *testing.T) {
			f := newApprovalFixture(t)
			input := approvalInput()
			switch bad {
			case "wrong-code":
				input.ShortCode = []byte("87654321")
			case "manager-key", "generation", "purpose", "capability":
				f.alter = bad
			case "missing-initial":
				var s protectedState
				_ = json.Unmarshal(f.base.config.ProtectedState, &s)
				s.Initialization = nil
				f.base.config.ProtectedState = mustApproval(json.Marshal(s))
			case "other-env":
				input.Selections[0].EnvironmentID = "unproven"
			case "invalid-role":
				input.Selections[0].Role = "owner"
			case "expired":
				input.Selections[0].ExpiresAt = strconv.FormatInt(time.Now().Add(-time.Second).Unix(), 10)
			case "changed-source":
				g := f.base.grant.Grant
				g.GrantGeneration = "2"
				g.IdempotencyKey = "new-current"
				f.base.grant = mustApproval(cryptox.SignGrant(g, f.base.config.SigningKey))
			}
			w, err := New(f.base.config)
			if bad == "missing-initial" {
				if err == nil {
					w.Close()
					t.Fatal("cached origin ledger reopened without protected genesis")
				}
				if len(f.posts) != 0 {
					t.Fatal("unproved genesis uploaded approval")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if _, err = w.ApprovePairingV5(context.Background(), input); err == nil || len(f.posts) != 0 {
				t.Fatal("invalid approval uploaded", err)
			}
		})
	}
}
func TestNativeApprovalAESFailurePreparedCancelAndAuthorityLoss(t *testing.T) {
	for _, mode := range []string{"save-failure", "authority-loss", "expired-pending"} {
		t.Run(mode, func(t *testing.T) {
			f := newApprovalFixture(t)
			w, err := New(f.base.config)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if mode == "save-failure" {
				f.failSave.Store(true)
				if _, err = w.ApprovePairingV5(context.Background(), approvalInput()); err == nil || len(f.posts) != 0 || w.state.PendingApprovalV5 == nil || w.state.PendingApprovalV5.Attempted {
					t.Fatal("AES failure uploaded")
				}
				f.failSave.Store(false)
				if err = w.CancelApprovalV5("pair-native"); err != nil || w.state.PendingApprovalV5 != nil {
					t.Fatal("unsent prepared cancel failed", err)
				}
				return
			}
			f.dropResponse = true
			if _, err = w.ApprovePairingV5(context.Background(), approvalInput()); !errors.Is(err, ErrApprovalPending) {
				t.Fatal(err)
			}
			f.mu.Lock()
			if mode == "authority-loss" {
				f.invalidate = true
			} else {
				f.base.now.Add(121)
				f.status.State = "pending"
				f.status.Approval = nil
			}
			f.mu.Unlock()
			if _, err = w.RetryApprovalV5(context.Background(), "pair-native"); err == nil || len(f.posts) != 1 || w.state.PendingApprovalV5 == nil {
				t.Fatal("lost authority/expired challenge replaced approval", err)
			}
			if _, err = w.View(); !errors.Is(err, ErrApprovalPending) {
				t.Fatal("unresolved approval gate cleared")
			}
		})
	}
}

func TestNativeApprovalUnacceptedRetryReusesBytesAndPreparedSeal(t *testing.T) {
	for _, mode := range []string{"unaccepted", "attempt-seal-fails"} {
		t.Run(mode, func(t *testing.T) {
			f := newApprovalFixture(t)
			f.dropBeforeAccept = mode == "unaccepted"
			f.failAttemptSeal.Store(mode == "attempt-seal-fails")
			w, err := New(f.base.config)
			if err != nil {
				t.Fatal(err)
			}
			_, err = w.ApprovePairingV5(context.Background(), approvalInput())
			if err == nil {
				t.Fatal("expected unknown/seal failure")
			}
			if mode == "attempt-seal-fails" && len(f.posts) != 0 {
				t.Fatal("POST before attempted flag durably sealed")
			}
			saved := bytes.Clone(f.base.native)
			w.Close()
			f.base.config.ProtectedState = saved
			w, err = New(f.base.config)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if mode == "attempt-seal-fails" {
				if w.state.PendingApprovalV5.Attempted {
					t.Fatal("failed attempted seal appeared committed")
				}
				if err = w.CancelApprovalV5("pair-native"); err != nil {
					t.Fatal("persisted unsent record could not cancel", err)
				}
				return
			}
			original := bytes.Clone(f.posts[0])
			f.dropBeforeAccept = false
			result, err := w.RetryApprovalV5(context.Background(), "pair-native")
			if err != nil || result.State != "approved" || len(f.posts) != 2 || !bytes.Equal(original, f.posts[1]) {
				t.Fatal("retry minted ciphertext/signature/roles", result, err)
			}
		})
	}
}
func TestNativeApprovalProtectedJournalRejectsTamperingAndCoexistingSelfGate(t *testing.T) {
	f := newApprovalFixture(t)
	f.dropResponse = true
	w, err := New(f.base.config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.ApprovePairingV5(context.Background(), approvalInput())
	if !errors.Is(err, ErrApprovalPending) {
		t.Fatal(err)
	}
	original := bytes.Clone(f.base.native)
	w.Close()
	for _, field := range []string{"epoch", "choices", "signature", "initial-authority", "time", "completed", "self-revoke"} {
		t.Run(field, func(t *testing.T) {
			var state protectedState
			if json.Unmarshal(original, &state) != nil {
				t.Fatal("native state")
			}
			switch field {
			case "epoch":
				state.PendingApprovalV5.SessionEpoch++
			case "choices":
				state.PendingApprovalV5.ChoicesHash = strings.Repeat("0", 64)
			case "signature":
				state.PendingApprovalV5.Approval.ApproverSignature = cryptox.EncodeBase64(make([]byte, 64))
			case "initial-authority":
				state.Initialization = nil
			case "time":
				state.PendingApprovalV5.CreatedAt += 200
			case "completed":
				state.PendingApprovalV5.Sequence = 3
			case "self-revoke":
				state.SelfRevocation = []byte(`{}`)
			}
			cfg := f.base.config
			cfg.ProtectedState = mustApproval(json.Marshal(state))
			if restored, e := New(cfg); e == nil {
				restored.Close()
				t.Fatal("malformed protected approval restored")
			}
		})
	}
}
