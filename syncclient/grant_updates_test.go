package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/internal/dagfixture"
	"github.com/harmonia-vault/core-go/localstate"
)

type managementFixture struct {
	c               *Client
	key             ed25519.PrivateKey
	control         ManagementControl
	grant           cryptox.SignedGrantWire
	initial         cryptox.SignedGrantWire
	proof           cryptox.IssuerRecoveryDAG
	status          GrantStatus
	lose, wrongHash bool
	posts           int
}

func newManagementFixture(t *testing.T) *managementFixture {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	check(t, e)
	pub, private, e := cryptox.GenerateReceivingKey()
	check(t, e)
	_, recovery, e := ed25519.GenerateKey(rand.Reader)
	check(t, e)
	recoverPub, _, e := cryptox.GenerateReceivingKey()
	check(t, e)
	root, e := cryptox.SignTrustRoot("management-account", "1", cryptox.TrustRoot{RootDeviceID: "management-root", RootSigningPublicKey: cryptox.EncodeBase64(key.Public().(ed25519.PublicKey)), RootReceivingPublicKey: cryptox.EncodeBase64(pub), RecoveryGeneration: "1", RecoverySigningPublicKey: cryptox.EncodeBase64(recovery.Public().(ed25519.PublicKey)), RecoveryReceivingPublicKey: cryptox.EncodeBase64(recoverPub)}, recovery)
	check(t, e)
	envKey, e := cryptox.GenerateEnvironmentKey()
	check(t, e)
	defer clear(envKey)
	envelope, e := cryptox.WrapEnvironmentKey(envKey, cryptox.EnvelopeContext{AccountID: "management-account", AccountGeneration: "1", EnvironmentID: "managed-env", KeyVersion: "1", RecipientType: "device", RecipientID: root.RootDeviceID, RecipientGeneration: "1", RecipientPublicKey: root.RootReceivingPublicKey})
	check(t, e)
	signed, e := cryptox.SignGrant(cryptox.Grant{AccountID: "management-account", AccountGeneration: "1", IssuerDeviceID: root.RootDeviceID, SubjectDeviceID: root.RootDeviceID, SubjectSigningPublicKey: root.RootSigningPublicKey, SubjectReceivingPublicKey: root.RootReceivingPublicKey, EnvironmentID: "managed-env", KeyVersion: "1", GrantGeneration: "1", Role: "admin", ExpiresAt: "0", IdempotencyKey: "management-init", Envelope: cryptox.EncodeBase64(envelope)}, key)
	check(t, e)
	f := &managementFixture{key: key, grant: cryptox.GrantToWire(signed)}
	f.initial = f.grant
	f.proof = dagfixture.Root(t, "management-account", root, key, recovery, []cryptox.InitializationEnvironment{{EnvironmentID: "managed-env", KeyVersion: "1", RecoveryEnvelope: cryptox.EncodeBase64(make([]byte, 80)), Grant: f.grant}})
	f.control = ManagementControl{AccountID: "management-account", AccountGeneration: "1", EnvironmentID: "managed-env", Sequence: 1, KeyVersion: "1", Subjects: []ManagementSubject{{DeviceID: root.RootDeviceID, SigningPublicKey: root.RootSigningPublicKey, ReceivingPublicKey: root.RootReceivingPublicKey, CurrentGrant: &f.grant, HighestGrantGeneration: "1"}}, IssuerDAGEvidence: &f.proof}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/grant-status"):
			status := f.status
			status.IdempotencyKey = r.URL.Query().Get("idempotencyKey")
			if f.wrongHash && status.Accepted {
				status.ContentHash = strings.Repeat("0", 64)
			}
			_ = json.NewEncoder(w).Encode(status)
		case strings.HasSuffix(r.URL.Path, "/grant-management"):
			_ = json.NewEncoder(w).Encode(f.control)
		case strings.HasSuffix(r.URL.Path, "/grants"):
			f.posts++
			var packet cryptox.SignedGrantWire
			check(t, json.NewDecoder(r.Body).Decode(&packet))
			check(t, cryptox.VerifyGrant(packet.SignedGrant(), key.Public().(ed25519.PublicKey)))
			content, e := GrantContentHash(packet)
			check(t, e)
			f.status = GrantStatus{IdempotencyKey: packet.Grant.IdempotencyKey, Accepted: true, Sequence: 2, ContentHash: content}
			f.grant = packet
			if f.lose {
				w.WriteHeader(504)
				_, _ = w.Write([]byte(`{"error":"request_rejected"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(Acceptance{Sequence: 2})
		case strings.HasSuffix(r.URL.Path, "/pull"):
			p := cloneDAGEvidence(f.proof)
			if f.status.Accepted {
				parent, e := cryptox.IssuerAuthorityHash(f.initial)
				check(t, e)
				h, e := cryptox.IssuerAuthorityHash(f.grant)
				check(t, e)
				p.Source.View.Authorities = append(append([]cryptox.IssuerRecoveryAuthority(nil), p.Source.View.Authorities...), cryptox.IssuerRecoveryAuthority{Grant: f.grant, ParentHash: parent})
				p.Source.View.Targets = []cryptox.IssuerTarget{{EnvironmentID: "managed-env", AuthorityHash: h}}
			}
			seq := uint64(1)
			if f.status.Accepted {
				seq = 2
			}
			_ = json.NewEncoder(w).Encode(Pull{AccountID: "management-account", AccountGeneration: "1", Sequence: seq, Grants: []SignedGrant{{Grant: f.grant.Grant, Signature: f.grant.Signature}}, Events: []Event{}, IssuerDAGEvidence: &p})
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":"not_found"}`))
		}
	}))
	t.Cleanup(server.Close)
	engine, e := localstate.New(&volatileStore{state: localstate.EmptyState()})
	check(t, e)
	v, e := NewRootDAGPinnedVerifier(PinnedTrust{AccountID: "management-account", AccountGeneration: 1, DeviceID: root.RootDeviceID, DeviceSigningPublicKey: key.Public().(ed25519.PublicKey), ReceivingPrivateKey: private, Now: func() time.Time { return time.Unix(2030000000, 0) }}, f.proof.Initialization)
	check(t, e)
	t.Cleanup(v.Close)
	f.c, e = New(Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: "management-account", AccountGeneration: 1, DeviceID: root.RootDeviceID, Token: cryptox.EncodeBase64(bytes.Repeat([]byte{42}, 32)), Engine: engine, Verifier: v, Now: func() time.Time { return time.Unix(2030000000, 0) }})
	check(t, e)
	_, e = f.c.Pull(context.Background())
	check(t, e)
	return f
}
func TestGrantUpdateOriginalBytesReceiptAndNoOptimisticApply(t *testing.T) {
	f := newManagementFixture(t)
	ctx := context.Background()
	before := f.c.config.Engine.State().Cloud
	tx, e := f.c.PrepareGrantUpdate(ctx, GrantUpdateIntent{ID: "original-grant", EnvironmentID: "managed-env", SubjectDeviceID: "management-root", Role: "rw"}, f.key)
	check(t, e)
	wire, e := tx.ProtectedBytes()
	check(t, e)
	restored, e := f.c.RestoreGrantUpdate(wire)
	check(t, e)
	round, e := restored.ProtectedBytes()
	check(t, e)
	if !bytes.Equal(wire, round) || f.posts != 0 {
		t.Fatal("native restore changed signed original or submitted during prepare")
	}
	f.lose = true
	if _, e = restored.SubmitWithBarrier(ctx, func() error { return nil }); e == nil {
		t.Fatal("accepted response loss reported success")
	}
	if f.c.config.Engine.State().Cloud.Sequence != before.Sequence || f.c.config.Engine.State().Cloud.Environments["managed-env"].Role != localstate.Admin {
		t.Fatal("lost response optimistically applied target grant")
	}
	f.wrongHash = true
	if _, e = restored.Status(ctx); !errors.Is(e, ErrGrantUpdateConflict) {
		t.Fatal("wrong immutable receipt hash accepted", e)
	}
	f.wrongHash = false
	status, e := restored.Status(ctx)
	check(t, e)
	result, e := restored.Confirm(ctx, Acceptance{Sequence: status.Sequence})
	check(t, e)
	if !result.Applied || f.posts != 1 || f.c.config.Engine.State().Cloud.Environments["managed-env"].Role != localstate.ReadWrite {
		t.Fatal("original accepted transaction not confirmed through verified pull")
	}
	if _, e = f.c.PrepareGrantUpdate(ctx, tx.Intent(), f.key); !errors.Is(e, ErrGrantUpdateConflict) {
		t.Fatal("accepted id produced fresh envelope", e)
	}
}
func TestGrantUpdateRejectsCorruptProtectedBindingEpochAndUnsafeIntent(t *testing.T) {
	f := newManagementFixture(t)
	ctx := context.Background()
	tx, e := f.c.PrepareGrantUpdate(ctx, GrantUpdateIntent{ID: "binding-grant", EnvironmentID: "managed-env", SubjectDeviceID: "management-root", Role: "rw"}, f.key)
	check(t, e)
	wire, e := tx.ProtectedBytes()
	check(t, e)
	for _, mutate := range []func(*grantUpdateRecord){func(r *grantUpdateRecord) { r.SessionEpoch++ }, func(r *grantUpdateRecord) { r.Intent.SubjectDeviceID = "rogue-device" }, func(r *grantUpdateRecord) { r.Signed.Signature = cryptox.EncodeBase64(make([]byte, 64)) }, func(r *grantUpdateRecord) {
		r.Control.Subjects[0].SigningPublicKey = cryptox.EncodeBase64(make([]byte, 32))
	}, func(r *grantUpdateRecord) { r.Control.Subjects[0].HighestGrantGeneration = "0" }} {
		var r grantUpdateRecord
		check(t, json.Unmarshal(wire, &r))
		mutate(&r)
		bad, e := json.Marshal(r)
		check(t, e)
		if _, e = f.c.RestoreGrantUpdate(bad); e == nil {
			t.Fatal("corrupt native transaction accepted")
		}
	}
	if _, e = f.c.RestoreGrantUpdate(append(wire, []byte(` {}`)...)); e == nil {
		t.Fatal("trailing protected packet accepted")
	}
	for _, in := range []GrantUpdateIntent{{ID: "expired", EnvironmentID: "managed-env", SubjectDeviceID: "management-root", Role: "rw", ExpiresAt: 2030000000}, {ID: "none-expiry", EnvironmentID: "managed-env", SubjectDeviceID: "management-root", Role: "none", ExpiresAt: 2030000060}, {ID: "bad-role", EnvironmentID: "managed-env", SubjectDeviceID: "management-root", Role: "owner"}} {
		if _, e = f.c.PrepareGrantUpdate(ctx, in, f.key); e == nil {
			t.Fatal("unsafe role/expiry intent accepted")
		}
	}
	check(t, f.c.config.Engine.SetPaused(true))
	if _, e = tx.SubmitWithBarrier(ctx, func() error { return nil }); !errors.Is(e, ErrPaused) {
		t.Fatal("paused grant update reached network", e)
	}
	if f.posts != 0 {
		t.Fatal("negative intent submitted")
	}
	check(t, f.c.config.Engine.Logout())
	if _, e = tx.Status(ctx); e == nil {
		t.Fatal("old epoch queried native journal")
	}
}

func TestGrantUpdatePersistenceBarrierFailureStopsPost(t *testing.T) {
	f := newManagementFixture(t)
	ctx := context.Background()
	tx, e := f.c.PrepareGrantUpdate(ctx, GrantUpdateIntent{ID: "barrier-grant", EnvironmentID: "managed-env", SubjectDeviceID: "management-root", Role: "rw"}, f.key)
	check(t, e)
	barrierError := errors.New("synthetic native barrier failure")
	calls := 0
	if _, e = tx.SubmitWithBarrier(ctx, func() error { calls++; return barrierError }); !errors.Is(e, barrierError) || calls != 1 || f.posts != 0 {
		t.Fatal("POST happened before successful protected barrier", e)
	}
	check(t, f.c.config.Engine.SetPaused(true))
	if _, e = tx.SubmitWithBarrier(ctx, func() error { calls++; return nil }); !errors.Is(e, ErrPaused) || calls != 1 || f.posts != 0 {
		t.Fatal("paused preflight invoked committing barrier", e)
	}
}

func TestGrantUpdateReceiptSchemaAndCurrentDirectoryBinding(t *testing.T) {
	f := newManagementFixture(t)
	ctx := context.Background()
	for _, status := range []GrantStatus{{Accepted: false, Sequence: 1}, {Accepted: false, ContentHash: strings.Repeat("0", 64)}, {Accepted: true, Sequence: 0, ContentHash: strings.Repeat("0", 64)}, {Accepted: true, Sequence: 1, ContentHash: strings.Repeat("A", 64)}} {
		f.status = status
		if _, e := f.c.GrantStatus(ctx, "strict-receipt"); e == nil {
			t.Fatal("invalid receipt shape accepted")
		}
	}
	f.status = GrantStatus{}
	original := cloneManagementControl(f.control)
	for _, mutate := range []func(*ManagementControl){func(c *ManagementControl) { c.AccountGeneration = "2" }, func(c *ManagementControl) { c.Subjects[0].HighestGrantGeneration = "01" }, func(c *ManagementControl) {
		c.Subjects[0].ReceivingPublicKey = cryptox.EncodeBase64(bytes.Repeat([]byte{99}, 32))
	}, func(c *ManagementControl) {
		c.Subjects[0].CurrentGrant = nil
		c.Subjects[0].HighestGrantGeneration = "1"
	}} {
		f.control = cloneManagementControl(original)
		mutate(&f.control)
		if _, e := f.c.ManagementControl(ctx, "managed-env"); e == nil {
			t.Fatal("unverified directory tuple accepted")
		}
	}
	if f.posts != 0 {
		t.Fatal("invalid receipt or directory caused mutation")
	}
}
