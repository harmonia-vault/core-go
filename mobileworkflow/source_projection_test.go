package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

func sourceRoot(t *testing.T) (*Workflow, *selfFixture) {
	t.Helper()
	f := newSelfFixture(t)
	w, err := New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w, f
}

// 公开向量仅供合成测试；用成熟 grant/certificate 签名与真实 HPKE 重绑本机身份。
func sourceV3(t *testing.T, role string) (*Workflow, *int64) {
	t.Helper()
	raw, err := os.ReadFile("../cryptox/testdata/environment-origin-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Approval cryptox.EnrollmentApprovalV3 `json:"approval"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	sign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	recv := bytes.Repeat([]byte{15}, 32)
	x := selfMust(ecdh.X25519().NewPrivateKey(recv))
	hash := sha256.Sum256(sign.Public().(ed25519.PublicKey))
	id := hex.EncodeToString(hash[:])
	a := fixture.Approval
	a.Context.InitiatorDeviceID = id
	a.Context.InitiatorReceivingPublicKey = cryptox.EncodeBase64(x.PublicKey().Bytes())
	g := a.Grants[0].Grant
	g.SubjectDeviceID = id
	g.SubjectReceivingPublicKey = a.Context.InitiatorReceivingPublicKey
	g.Role = role
	wrapped := selfMust(cryptox.WrapEnvironmentKey(bytes.Repeat([]byte{9}, 32), cryptox.EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: id, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey}))
	g.Envelope = cryptox.EncodeBase64(wrapped)
	own := selfMust(cryptox.SignGrant(g, manager))
	a.Grants = []cryptox.SignedGrantWire{cryptox.GrantToWire(own)}
	cert := selfMust(a.Certificate())
	a.ApproverSignature = selfMust(cryptox.SignEnrollmentCertificateV3(cert, manager))
	a.InitiatorSignature = selfMust(cryptox.SignEnrollmentCertificateV3(cert, sign))
	now := int64(2030000000)
	receipt := syncclient.EnrollmentReceiptV3{IdempotencyKey: "synthetic-source-v3", Approval: a}
	verified := selfMust(cryptox.VerifyCompletedEnrollmentV3(cryptox.ConfirmedEnrollmentAnchor{Context: a.Context, TranscriptHash: a.TranscriptHash}, a))
	proof := clone(a.IssuerProof)
	parent := map[string]string{}
	for _, target := range proof.Targets {
		parent[target.EnvironmentID] = target.AuthorityHash
	}
	proof.Path = append(proof.Path, cryptox.IssuerEnrollment{CertificateVersion: "3", IssuerProofHash: cert.IssuerProofHash, Approval: cryptox.EnrollmentApproval{Context: a.Context, PairingProfile: a.PairingProfile, TranscriptHash: a.TranscriptHash, Grants: a.Grants, ApproverSignature: a.ApproverSignature, InitiatorSignature: a.InitiatorSignature}})
	proof.Targets = nil
	for _, grant := range a.Grants {
		proof.Authorities = append(proof.Authorities, cryptox.IssuerAuthorityV2{Grant: grant, ParentHash: parent[grant.Grant.EnvironmentID]})
		proof.Targets = append(proof.Targets, cryptox.IssuerTarget{EnvironmentID: grant.Grant.EnvironmentID, AuthorityHash: selfMust(cryptox.IssuerAuthorityHash(grant))})
	}
	pin := cryptox.PinnedIssuerRoot{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, DeviceID: proof.TrustRoot.RootDeviceID, SigningPublicKey: proof.TrustRoot.RootSigningPublicKey, ReceivingPublicKey: proof.TrustRoot.RootReceivingPublicKey}
	if _, err = cryptox.VerifyIssuerEvidenceV2(pin, proof, verified.InitialAuthorities()...); err != nil {
		t.Fatal(err)
	}
	verifier := selfMust(syncclient.NewPinnedVerifierV3(syncclient.IssuerOriginPinnedTrust{AccountID: g.AccountID, AccountGeneration: 1, DeviceID: id, DeviceSigningPublicKey: sign.Public().(ed25519.PublicKey), ReceivingPrivateKey: recv, Receipt: receipt, Now: func() time.Time { return time.Unix(now, 0) }}))
	defer verifier.Close()
	cloud := selfMust(verifier.VerifyPull(context.Background(), syncclient.Pull{Full: true, AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, Sequence: 20, Grants: []syncclient.SignedGrant{{Grant: g, Signature: own.Signature}}, IssuerEvidence: &proof}, localstate.CloudSnapshot{}))
	state := protectedState{Version: 1, Endpoint: "https://synthetic.example.invalid", DeviceID: id, SigningPublicKey: cryptox.EncodeBase64(sign.Public().(ed25519.PublicKey)), ReceivingPublicKey: g.SubjectReceivingPublicKey, AccountID: g.AccountID, AccountGeneration: "1", Root: &proof.TrustRoot, Cloud: localstate.EmptyState(), Grants: a.Grants, Labels: map[string]labelState{}, EnrollmentV3: &mobileEnrollmentRecord{Version: 1, CreatedAt: now, LastObservedAt: now, Receipt: receipt, Sequence: 20, Applied: true}}
	state.Cloud.Cloud = cloud
	state.EnrollmentV3.SessionEpoch = state.Cloud.SessionEpoch
	w := selfMust(New(Config{Endpoint: state.Endpoint, SigningKey: sign, ReceivingPrivateKey: recv, ProtectedState: selfMust(json.Marshal(state)), Now: func() time.Time { return time.Unix(now, 0) }, SaveProtectedState: func([]byte) error { return nil }}))
	t.Cleanup(w.Close)
	return w, &now
}

func sourceV4(t *testing.T) *Workflow {
	t.Helper()
	var fixture struct {
		Recovery struct {
			Now        int64                              `json:"syntheticNow"`
			Seeds      map[string]string                  `json:"syntheticSeedsHex"`
			Pin        cryptox.PinnedIssuerRoot           `json:"rootPin"`
			Original   cryptox.OriginalInitialization     `json:"originalInitialization"`
			Transition cryptox.AcceptedRecoveryTransition `json:"oldRecoveryTransition"`
			Accepted   cryptox.AcceptedRecoveredDevice    `json:"recoveredDevice"`
		} `json:"recovery"`
	}
	raw := selfMust(os.ReadFile("../cryptox/testdata/issuer-recovery-v1.json"))
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	f := fixture.Recovery
	decode := func(s string) []byte { return selfMust(hex.DecodeString(s)) }
	sign := ed25519.NewKeyFromSeed(decode(f.Seeds["deviceEd"]))
	recv := decode(f.Seeds["deviceX"])
	authority := selfMust(cryptox.VerifyRecoveryInitialization(f.Pin, f.Original))
	authority = selfMust(cryptox.VerifyAcceptedRecoveryTransition(authority, f.Transition))
	p := clone(f.Accepted.Submission)
	hash := sha256.Sum256(sign.Public().(ed25519.PublicKey))
	id := hex.EncodeToString(hash[:])
	// 相同真实软件钥，改为Workflow正式本机ID，并重新签完整恢复包；不是伪造信任bool。
	for i, wire := range p.Grants {
		g := wire.Grant
		key := selfMust(cryptox.UnwrapEnvironmentKey(recv, cryptox.EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey}, selfMust(cryptox.DecodeBase64(g.Envelope, 80, 80))))
		g.SubjectDeviceID = id
		g.IssuerDeviceID = id
		packet := selfMust(cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: id, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey}))
		clear(key)
		g.Envelope = cryptox.EncodeBase64(packet)
		p.Grants[i] = cryptox.GrantToWire(selfMust(cryptox.SignGrant(g, sign)))
		p.Envelopes[i].Envelope = g.Envelope
	}
	p.Enrollment.DeviceID = id
	p.Enrollment.GrantsHash = selfMust(cryptox.RecoveredDeviceGrantsHash(p.Grants))
	p.Enrollment.EnvelopesHash = selfMust(cryptox.RecoveredDeviceEnvelopesHash(p.Envelopes))
	keys := selfMust(cryptox.DeriveRecoveryKeys(decode(f.Seeds["newRecovery"]), f.Pin.AccountID, f.Pin.AccountGeneration, p.Enrollment.RecoveryGeneration))
	defer clear(keys.SigningPrivate)
	defer clear(keys.ReceivingPrivate)
	now := time.Unix(f.Now, 0)
	p.RecoverySignature = selfMust(cryptox.SignRecoveredDeviceByRecovery(authority, p, keys.SigningPrivate, now))
	p.DeviceSignature = selfMust(cryptox.SignRecoveredDeviceAfterHPKE(authority, p, sign, recv, now))
	accepted := cryptox.AcceptedRecoveredDevice{Submission: p, Sequence: f.Accepted.Sequence}
	proof := selfMust(cryptox.BuildRecoveredDeviceIssuerEvidence(f.Pin, f.Original, []cryptox.AcceptedRecoveryTransition{f.Transition}, accepted))
	verifier := selfMust(syncclient.NewRecoveredDevicePinnedVerifier(syncclient.RecoveredDevicePinnedTrust{Trust: syncclient.PinnedTrust{AccountID: f.Pin.AccountID, AccountGeneration: 1, DeviceID: id, DeviceSigningPublicKey: sign.Public().(ed25519.PublicKey), ReceivingPrivateKey: recv, Now: func() time.Time { return now }}, Pin: f.Pin, Evidence: proof, Accepted: accepted}))
	defer verifier.Close()
	own := p.Grants[0]
	cloud := selfMust(verifier.VerifyPull(context.Background(), syncclient.Pull{Full: true, AccountID: f.Pin.AccountID, AccountGeneration: f.Pin.AccountGeneration, Sequence: 32, Grants: []syncclient.SignedGrant{{Grant: own.Grant, Signature: own.Signature}}, IssuerRecoveryEvidence: &proof}, localstate.CloudSnapshot{}))
	state := protectedState{Version: 1, Endpoint: "https://synthetic.example.invalid", DeviceID: id, SigningPublicKey: p.Enrollment.DeviceSigningPublicKey, ReceivingPublicKey: p.Enrollment.DeviceReceivingPublicKey, AccountID: f.Pin.AccountID, AccountGeneration: f.Pin.AccountGeneration, Root: &proof.TrustRoot, Cloud: localstate.EmptyState(), Grants: p.Grants, Labels: map[string]labelState{}}
	state.Cloud.Cloud = cloud
	state.RecoveredDevice = &recoveredDeviceRecord{Version: 1, CreatedAt: f.Now, SessionEpoch: state.Cloud.SessionEpoch, Pin: f.Pin, OriginalInitialization: f.Original, Transitions: []cryptox.AcceptedRecoveryTransition{f.Transition}, Packet: p, ContentHash: selfMust(cryptox.RecoveredDeviceReferenceHash(p)), AcceptedSequence: accepted.Sequence, Applied: true, Evidence: &proof}
	w := selfMust(New(Config{Endpoint: state.Endpoint, SigningKey: sign, ReceivingPrivateKey: recv, ProtectedState: selfMust(json.Marshal(state)), Now: func() time.Time { return now }, SaveProtectedState: func([]byte) error { return nil }}))
	t.Cleanup(w.Close)
	return w
}

func TestSourceProjectionThreeVerifiedOrigins(t *testing.T) {
	for _, kind := range []string{"root", "v3", "recovered-v4"} {
		t.Run(kind, func(t *testing.T) {
			var w *Workflow
			expected := "3"
			switch kind {
			case "root":
				w, _ = sourceRoot(t)
			case "v3":
				w, _ = sourceV3(t, "admin")
			case "recovered-v4":
				w = sourceV4(t)
				expected = "4"
			}
			result, err := w.RestoreSessionWithSource()
			if err != nil {
				t.Fatal(err)
			}
			if !result.TrustedDevice || result.AccountID != w.state.AccountID || result.DeviceID != w.state.DeviceID || result.ApprovalSource.CertificateVersion != expected || result.ApprovalSource.Checkpoint != result.View.Checkpoint || len(result.ApprovalSource.AdminEnvironmentIDs) != 1 {
				t.Fatal("unbound or missing projection", result.ApprovalSource)
			}
			encoded := selfMust(json.Marshal(result))
			if bytes.Contains(encoded, []byte("issuerProof")) || bytes.Contains(encoded, []byte("token")) || bytes.Contains(encoded, []byte("authority")) {
				t.Fatal("private evidence exported")
			}
		})
	}
}

func TestSourceProjectionNoAdminAndExpiresBeforeProjection(t *testing.T) {
	t.Run("RO-source-is-not-admin", func(t *testing.T) {
		w, _ := sourceV3(t, "ro")
		r, err := w.RestoreSessionWithSource()
		if err != nil || len(r.ApprovalSource.AdminEnvironmentIDs) != 0 || r.ApprovalSource.CertificateVersion != "3" {
			t.Fatal(r.ApprovalSource, err)
		}
	})
	t.Run("expired-admin-clears-cache", func(t *testing.T) {
		w, now := sourceV3(t, "admin")
		*now = 2030000501
		r, err := w.RestoreSessionWithSource()
		if err != nil || len(r.ApprovalSource.AdminEnvironmentIDs) != 0 || len(r.View.Environments) != 0 {
			t.Fatal(r.ApprovalSource, err)
		}
	})
}

func TestSourceProjectionRejectsBadSignatureGenerationLedgerAndPending(t *testing.T) {
	for _, kind := range []string{"bad-initial-signature", "wrong-generation", "missing-initial-authorities", "unknown-ledger", "restricted", "pending-v3", "unapplied-v4", "bad-v3-signature", "bad-v4-signature"} {
		t.Run(kind, func(t *testing.T) {
			w, _ := sourceRoot(t)
			switch kind {
			case "bad-initial-signature":
				w.state.InitialAuthorities[0].Signature = cryptox.EncodeBase64(make([]byte, 64))
			case "wrong-generation":
				w.state.AccountGeneration = "2"
			case "missing-initial-authorities":
				w.state.InitialAuthorities = nil
			case "unknown-ledger":
				s := w.engine.State()
				s.Cloud.IssuerEvidence = json.RawMessage(`{"profile":"unknown-future-source"}`)
				w.store.state = s
				w.engine = selfMust(localstate.New(w.store))
			case "restricted":
				w.state.Recovery = &recoveryRecord{}
			case "pending-v3":
				w.state.EnrollmentV3 = &mobileEnrollmentRecord{}
			case "unapplied-v4":
				w = sourceV4(t)
				w.state.RecoveredDevice.Applied = false
			case "bad-v3-signature":
				w, _ = sourceV3(t, "admin")
				w.state.EnrollmentV3.Receipt.Approval.InitiatorSignature = cryptox.EncodeBase64(make([]byte, 64))
			case "bad-v4-signature":
				w = sourceV4(t)
				w.state.RecoveredDevice.Packet.RecoverySignature = cryptox.EncodeBase64(make([]byte, 64))
			}
			saves := 0
			w.saveNative = func([]byte) error { saves++; return nil }
			r, err := w.RestoreSessionWithSource()
			if err == nil || r.TrustedDevice || r.AccountID != "" || saves != 0 {
				t.Fatal("bad source produced/persisted DTO", kind, err)
			}
		})
	}
}

func TestSourceProjectionFinalSaveFailureReturnsNoTrustedDTO(t *testing.T) {
	w, _ := sourceRoot(t)
	saves := 0
	w.saveNative = func([]byte) error { saves++; return errors.New("synthetic final seal failure") }
	r, err := w.RestoreSessionWithSource()
	if err == nil || saves != 1 || !reflect.DeepEqual(r, TrustedSourceView{}) {
		t.Fatal("final save failure leaked projection", err)
	}
}

func TestSourceProjectionPullUsesVerifiedSameCheckpoint(t *testing.T) {
	w, f := sourceRoot(t)
	var pulls atomic.Int64
	original := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/pull") {
			pulls.Add(1)
		}
		original.ServeHTTP(writer, request)
	})
	r, err := w.PullWithSource(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.View.Checkpoint != 1 || r.ApprovalSource.Checkpoint != 1 || r.AccountGeneration != strconv.FormatUint(w.engine.State().Cloud.AccountGeneration, 10) || len(f.saved) == 0 {
		t.Fatal("pull source binding mismatch")
	}
	if pulls.Load() == 0 {
		t.Fatal("online method did not actually pull")
	}
}

func TestSourceProjectionPullFinalSaveFailureReturnsNoTrustedDTO(t *testing.T) {
	w, _ := sourceRoot(t)
	saves := 0
	w.saveNative = func([]byte) error {
		saves++
		if saves == 2 {
			return errors.New("synthetic final source seal failure")
		}
		return nil
	}
	result, err := w.PullWithSource(context.Background())
	if err == nil || saves != 2 || !reflect.DeepEqual(result, TrustedSourceView{}) {
		t.Fatal("online last-save failure returned source", saves, err)
	}
}

func TestSourceProjectionUnknownSignedJournalSurvivesRestartAndClosesSource(t *testing.T) {
	w, f := sourceRoot(t)
	original := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/mutation-status") {
			writer.WriteHeader(502)
			_ = json.NewEncoder(writer).Encode(map[string]string{"error": "synthetic_unknown_original_write"})
			return
		}
		original.ServeHTTP(writer, request)
	})
	if _, err := w.SetVariable(context.Background(), "env", "SYNTHETIC_PENDING", "synthetic-only", "original-source-pending"); err == nil {
		t.Fatal("expected original uncertain journal")
	}
	originalJournal := bytes.Clone(w.state.WriteJournal)
	f.config.ProtectedState = selfMust(w.ExportProtectedState())
	reopened := selfMust(New(f.config))
	defer reopened.Close()
	for _, method := range []string{"restore", "pull"} {
		var r TrustedSourceView
		var err error
		if method == "restore" {
			r, err = reopened.RestoreSessionWithSource()
		} else {
			r, err = reopened.PullWithSource(context.Background())
		}
		if !errors.Is(err, ErrSourceProjectionPending) || r.TrustedDevice {
			t.Fatal("unknown original transaction allowed source", method, err)
		}
	}
	if !bytes.Equal(originalJournal, reopened.state.WriteJournal) {
		t.Fatal("original signed journal changed by source query")
	}
	infos := selfMust(reopened.PendingBusinessOperations())
	if len(infos) != 1 || infos[0].ID != "original-source-pending" || infos[0].State != "unknown" {
		t.Fatal("original metadata not retained")
	}
}

func TestSourceProjectionFinalSaveHoldsWorkflowLockAndPublishesAfterSave(t *testing.T) {
	w, _ := sourceRoot(t)
	entered, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var saves atomic.Int64
	w.saveNative = func([]byte) error {
		if saves.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	}
	type outcome struct {
		result TrustedSourceView
		err    error
	}
	result := make(chan outcome, 1)
	go func() { r, err := w.RestoreSessionWithSource(); result <- outcome{r, err} }()
	<-entered
	select {
	case <-result:
		t.Fatal("projection published before protected save")
	default:
	}
	closeStarted := make(chan struct{})
	go func() { close(closeStarted); w.Close(); close(closed) }()
	<-closeStarted
	select {
	case <-closed:
		t.Fatal("Close bypassed source/save lock")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	r := <-result
	if r.err != nil || !r.result.TrustedDevice {
		t.Fatal("authenticated save did not publish", r.err)
	}
	<-closed
	if _, err := w.RestoreSessionWithSource(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed workflow restored", err)
	}
}
