package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/internal/dagfixture"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

// 单元夹具隔离native保护上下文/事务边界；真正首机入网与TS SQLite撤销另有HTTPS验收。
type selfFixture struct {
	t               *testing.T
	mu              sync.Mutex
	now             atomic.Int64
	config          Config
	native          []byte
	saved           [][]byte
	failSave        atomic.Bool
	journalSaved    atomic.Bool
	account, device string
	public          ed25519.PublicKey
	receivingPublic []byte
	grant           cryptox.SignedGrant
	evidence        *cryptox.IssuerRecoveryDAG
	server          *httptest.Server
	tokens          map[string]bool
	boots           map[string]cryptox.DeviceBootProof
	challenge       *cryptox.DeviceRevocation
	queries         int
	prepares        int
	posts           [][]byte
	rejectQuery     bool
	rejectPost      bool
	revoked         bool
	badChallenge    string
}

func selfMust[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
func newSelfFixture(t *testing.T) *selfFixture {
	t.Helper()
	f := &selfFixture{t: t, account: "unit-self-account", tokens: map[string]bool{}, boots: map[string]cryptox.DeviceBootProof{}}
	f.now.Store(time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC).Unix())
	f.config = testConfig(t)
	f.config.Now = func() time.Time { return time.Unix(f.now.Load(), 0) }
	f.public = f.config.SigningKey.Public().(ed25519.PublicKey)
	hash := sha256.Sum256(f.public)
	f.device = hex.EncodeToString(hash[:])
	receive := selfMust(ecdh.X25519().NewPrivateKey(f.config.ReceivingPrivateKey))
	f.receivingPublic = receive.PublicKey().Bytes()
	envKey := selfMust(cryptox.GenerateEnvironmentKey())
	recovery := selfMust(cryptox.DeriveRecoveryKeys(selfMust(cryptox.GenerateRecoverySeed()), f.account, "1", "1"))
	root := selfMust(cryptox.SignTrustRoot(f.account, "1", cryptox.TrustRoot{RootDeviceID: f.device, RootSigningPublicKey: cryptox.EncodeBase64(f.public), RootReceivingPublicKey: cryptox.EncodeBase64(f.receivingPublic), RecoveryGeneration: "1", RecoverySigningPublicKey: cryptox.EncodeBase64(recovery.SigningPublic), RecoveryReceivingPublicKey: cryptox.EncodeBase64(recovery.ReceivingPublic)}, recovery.SigningPrivate))
	envelope := selfMust(cryptox.WrapEnvironmentKey(envKey, cryptox.EnvelopeContext{AccountID: f.account, AccountGeneration: "1", EnvironmentID: "env", KeyVersion: "1", RecipientType: "device", RecipientID: f.device, RecipientGeneration: "1", RecipientPublicKey: root.RootReceivingPublicKey}))
	f.grant = selfMust(cryptox.SignGrant(cryptox.Grant{AccountID: f.account, AccountGeneration: "1", IssuerDeviceID: f.device, SubjectDeviceID: f.device, SubjectSigningPublicKey: root.RootSigningPublicKey, SubjectReceivingPublicKey: root.RootReceivingPublicKey, EnvironmentID: "env", KeyVersion: "1", GrantGeneration: "1", Role: "admin", ExpiresAt: "0", IdempotencyKey: "unit-initial", Envelope: cryptox.EncodeBase64(envelope)}, f.config.SigningKey))
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	f.config.Endpoint = f.server.URL
	f.config.HTTPClient = f.server.Client()
	state := protectedState{Version: 2, Endpoint: f.server.URL, DeviceID: f.device, SigningPublicKey: root.RootSigningPublicKey, ReceivingPublicKey: root.RootReceivingPublicKey, AccountID: f.account, AccountGeneration: "1", Root: &root, Cloud: localstate.EmptyState(), Grants: []cryptox.SignedGrantWire{cryptox.GrantToWire(f.grant)}, Labels: map[string]labelState{}}
	p := dagfixture.Root(t, f.account, root, f.config.SigningKey, recovery.SigningPrivate, []cryptox.InitializationEnvironment{{EnvironmentID: "env", KeyVersion: "1", RecoveryEnvelope: cryptox.EncodeBase64(make([]byte, 80)), Grant: cryptox.GrantToWire(f.grant)}})
	f.evidence = &p
	state.Initialization = &p.Initialization
	payload := selfMust(cryptox.EncryptValue(envKey, cryptox.ValueContext{AccountID: f.account, AccountGeneration: "1", EnvironmentID: "env", KeyVersion: "1", Name: "UNIT_SYNTHETIC"}, []byte("synthetic-unit-value")))
	mutation := selfMust(cryptox.SignMutation(cryptox.Mutation{AccountID: f.account, AccountGeneration: "1", DeviceID: f.device, EnvironmentID: "env", KeyVersion: "1", GrantGeneration: "1", Operation: "put", IdempotencyKey: "unit-value", Name: "UNIT_SYNTHETIC", Payload: cryptox.EncodeBase64(payload)}, f.config.SigningKey))
	grant := syncclient.SignedGrant{Grant: f.grant.Grant, Signature: f.grant.Signature}
	state.InitialAuthorities = []cryptox.SignedGrantWire{cryptox.GrantToWire(f.grant)}
	originVerifier := selfMust(syncclient.NewRootDAGPinnedVerifier(syncclient.PinnedTrust{AccountID: f.account, AccountGeneration: 1, DeviceID: f.device, DeviceSigningPublicKey: f.public, ReceivingPrivateKey: f.config.ReceivingPrivateKey, Now: f.config.Now}, p.Initialization))
	state.Cloud.Cloud = selfMust(originVerifier.VerifyPull(context.Background(), syncclient.Pull{Full: true, IssuerDAGEvidence: f.evidence, AccountID: f.account, AccountGeneration: "1", Sequence: 1, Grants: []syncclient.SignedGrant{grant}, Events: []syncclient.Event{{Sequence: 1, Mutation: syncclient.SignedMutation{Mutation: mutation.Mutation, Signature: mutation.Signature}, Authorization: &grant}}}, localstate.CloudSnapshot{}))
	originVerifier.Close()
	f.config.ProtectedState = selfMust(json.Marshal(state))
	f.config.SaveProtectedState = func(blob []byte) error {
		var state protectedState
		if json.Unmarshal(blob, &state) != nil {
			return errors.New("unit context invalid")
		}
		if len(state.SelfRevocation) > 0 {
			if f.failSave.Load() {
				return errors.New("synthetic seal failure")
			}
			f.journalSaved.Store(true)
		}
		f.native = bytes.Clone(blob)
		f.saved = append(f.saved, bytes.Clone(blob))
		return nil
	}
	return f
}
func (f *selfFixture) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Harmonia-Protocol-Major", "2")
	f.mu.Lock()
	defer f.mu.Unlock()
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	fail := func(code string, status int) { w.WriteHeader(status); write(map[string]string{"error": code}) }
	path := r.URL.Path
	if strings.HasSuffix(path, "/boot-challenges") {
		if f.revoked {
			fail("device_untrusted", 403)
			return
		}
		id := "boot-" + strconv.Itoa(len(f.boots)+1)
		nonce := make([]byte, 32)
		_, _ = rand.Read(nonce)
		expires := f.now.Load() + 120
		proof := selfMust(cryptox.NewDeviceBootProof(f.account, "1", f.device, f.public, f.receivingPublic, id, cryptox.EncodeBase64(nonce), strconv.FormatInt(expires, 10)))
		f.boots[id] = proof
		var fields []string
		_ = json.Unmarshal(selfMust(proof.SigningBytes()), &fields)
		write(syncclient.DeviceChallenge{ChallengeID: id, Nonce: cryptox.EncodeBase64(nonce), ExpiresAt: expires, SigningPayload: fields})
		return
	}
	if strings.HasSuffix(path, "/boot-sessions") {
		var body struct {
			DeviceID          string `json:"deviceId"`
			AccountGeneration string `json:"accountGeneration"`
			ChallengeID       string `json:"challengeId"`
			Signature         string `json:"signature"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		proof := f.boots[body.ChallengeID]
		if cryptox.VerifyDeviceBootProof(proof, body.Signature, f.public) != nil {
			fail("signature_invalid", 403)
			return
		}
		token := make([]byte, 32)
		_, _ = rand.Read(token)
		encoded := cryptox.EncodeBase64(token)
		f.tokens[encoded] = true
		write(syncclient.DeviceSession{Token: encoded, ExpiresAt: f.now.Load() + 3600})
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !f.tokens[token] {
		fail("unauthorized", 401)
		return
	}
	switch {
	case strings.HasSuffix(path, "/pull"):
		write(syncclient.Pull{IssuerDAGEvidence: f.evidence, AccountID: f.account, AccountGeneration: "1", Sequence: 1, Grants: []syncclient.SignedGrant{{Grant: f.grant.Grant, Signature: f.grant.Signature}}, Events: []syncclient.Event{}})
	case strings.HasSuffix(path, "/device-revocations"):
		f.prepares++
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		nonce := make([]byte, 32)
		_, _ = rand.Read(nonce)
		hash := sha256.Sum256([]byte(token))
		challenge := cryptox.DeviceRevocation{AccountID: f.account, AccountGeneration: "1", DeviceID: f.device, SubjectDeviceID: f.device, SubjectSigningPublicKey: cryptox.EncodeBase64(f.public), SubjectReceivingPublicKey: cryptox.EncodeBase64(f.receivingPublic), IdempotencyKey: body["idempotencyKey"], ChallengeID: "revocation-unit", SessionHash: hex.EncodeToString(hash[:]), Nonce: cryptox.EncodeBase64(nonce), ExpiresAt: strconv.FormatInt(f.now.Load()+120, 10), Authorities: []cryptox.RevocationAuthority{{EnvironmentID: "env", KeyVersion: "1", GrantGeneration: "1"}}}
		switch f.badChallenge {
		case "account":
			challenge.AccountID = "other"
		case "device":
			challenge.SubjectDeviceID = "other"
		case "receiving":
			challenge.SubjectReceivingPublicKey = cryptox.EncodeBase64(make([]byte, 32))
		case "session":
			challenge.SessionHash = strings.Repeat("0", 64)
		case "deadline":
			challenge.ExpiresAt = strconv.FormatInt(f.now.Load()+126, 10)
		case "nonce":
			challenge.Nonce = "invalid"
		}
		f.challenge = &challenge
		write(challenge)
	case strings.HasSuffix(path, "/device-revocations/complete"):
		var signed cryptox.SignedDeviceRevocation
		raw := selfMust(io.ReadAll(r.Body))
		_ = json.Unmarshal(raw, &signed)
		if !f.journalSaved.Load() {
			f.t.Error("POST before native journal saved")
		}
		if cryptox.VerifyDeviceRevocation(signed, f.public) != nil {
			f.t.Error("invalid signed revoke")
		}
		f.posts = append(f.posts, bytes.Clone(raw))
		if f.rejectPost {
			f.rejectPost = false
			fail("synthetic_not_accepted", 502)
			return
		}
		f.revoked = true
		f.tokens = map[string]bool{}
		write(syncclient.Acceptance{Sequence: 2})
	default:
		f.queries++
		if f.rejectQuery {
			f.rejectQuery = false
			fail("synthetic_query_loss", 502)
			return
		}
		write(syncclient.SelfRevocationStatus{State: "pending", ExpiresAt: f.challenge.ExpiresAt})
	}
}
func (f *selfFixture) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.prepares, len(f.posts)
}
func TestSelfRevocationPendingCacheGateSealedResumeAndSameBundle(t *testing.T) {
	f := newSelfFixture(t)
	f.rejectPost = true
	w := selfMust(New(f.config))
	result, err := w.RevokeSelf(context.Background(), "unit-revoke")
	if !errors.Is(err, ErrSelfRevocationPending) || !result.AcceptanceUnknown || result.Completed {
		t.Fatal(result, err)
	}
	if _, err = w.View(); !errors.Is(err, ErrSelfRevocationPending) {
		t.Fatal("pending cache readable", err)
	}
	if _, err = w.Pull(context.Background()); !errors.Is(err, ErrSelfRevocationPending) {
		t.Fatal("pending normal pull allowed", err)
	}
	info := selfMust(w.SelfRevocationInfo())
	if info.ID != "unit-revoke" || info.State != "pending" {
		t.Fatal(info)
	}
	if _, err = w.RevokeSelf(context.Background(), "changed-id"); !errors.Is(err, syncclient.ErrWriteConflict) {
		t.Fatal("pending changed id accepted", err)
	}
	w.Close()
	f.config.ProtectedState = f.native
	w = selfMust(New(f.config))
	defer w.Close()
	result, err = w.RevokeSelf(context.Background(), "unit-revoke")
	if err != nil || !result.Completed || !result.DeviceInvalidated || result.AcceptanceUnknown {
		t.Fatal(result, err)
	}
	prepares, posts := f.counts()
	if prepares != 1 || posts != 2 {
		t.Fatal(prepares, posts)
	}
	f.mu.Lock()
	same := bytes.Equal(f.posts[0], f.posts[1])
	f.mu.Unlock()
	if !same {
		t.Fatal("restart re-signed original revocation")
	}
	var state protectedState
	_ = json.Unmarshal(f.native, &state)
	if state.Root != nil || len(state.SelfRevocation) != 0 || !state.Cloud.AccountClosed || len(w.signing) > 0 {
		t.Fatal("known200 failed to scrub")
	}
}
func TestSelfRevocationNativeSaveFailureBlocksPOSTAndLogoutClearsPending(t *testing.T) {
	f := newSelfFixture(t)
	f.failSave.Store(true)
	w := selfMust(New(f.config))
	defer w.Close()
	if _, err := w.RevokeSelf(context.Background(), "save-failure"); err == nil {
		t.Fatal("native save failure ignored")
	}
	_, posts := f.counts()
	if posts != 0 {
		t.Fatal("native save failure still POSTed")
	}
	f.failSave.Store(false)
	if err := w.Logout(); err != nil {
		t.Fatal(err)
	}
	var state protectedState
	_ = json.Unmarshal(f.native, &state)
	if len(state.SelfRevocation) != 0 || !state.Cloud.AccountClosed {
		t.Fatal("logout retained pending token")
	}
}
func TestSelfRevocationDeadlineScrubsBearerDoesNotReplayOrUnlockCache(t *testing.T) {
	f := newSelfFixture(t)
	f.rejectQuery = true
	w := selfMust(New(f.config))
	_, err := w.RevokeSelf(context.Background(), "deadline")
	if !errors.Is(err, ErrSelfRevocationPending) {
		t.Fatal(err)
	}
	w.Close()
	f.now.Add(121)
	f.config.ProtectedState = f.native
	w = selfMust(New(f.config))
	defer w.Close()
	result, err := w.RevokeSelf(context.Background(), "deadline")
	if !errors.Is(err, syncclient.ErrSelfRevocationExpired) || !result.Expired || !result.AcceptanceUnknown || result.Completed {
		t.Fatal(result, err)
	}
	_, posts := f.counts()
	if posts != 0 {
		t.Fatal("expired request replayed")
	}
	var state protectedState
	_ = json.Unmarshal(f.native, &state)
	var transaction struct {
		Token string `json:"sessionToken"`
	}
	_ = json.Unmarshal(state.SelfRevocation, &transaction)
	if transaction.Token != "" || len(state.SelfRevocation) == 0 {
		t.Fatal("expired bearer retained or pending discarded")
	}
	if _, err = w.View(); !errors.Is(err, ErrSelfRevocationPending) {
		t.Fatal("expired unknown unlocked cache")
	}
	if selfMust(w.SelfRevocationInfo()).State != "expired-pending" {
		t.Fatal("deadline metadata missing")
	}
}
func TestSelfRevocationChallengeBindingAndRestoredTamperFailClosed(t *testing.T) {
	for _, kind := range []string{"account", "device", "receiving", "session", "deadline", "nonce"} {
		t.Run(kind, func(t *testing.T) {
			f := newSelfFixture(t)
			f.badChallenge = kind
			w := selfMust(New(f.config))
			defer w.Close()
			if _, err := w.RevokeSelf(context.Background(), "bound"); err == nil {
				t.Fatal("unbound challenge accepted")
			}
			prepares, posts := f.counts()
			if posts != 0 || prepares != 1 {
				t.Fatal("unbound challenge phase incorrect", prepares, posts)
			}
		})
	}
	f := newSelfFixture(t)
	f.rejectQuery = true
	w := selfMust(New(f.config))
	_, _ = w.RevokeSelf(context.Background(), "restore")
	w.Close()
	var state protectedState
	_ = json.Unmarshal(f.native, &state)
	var raw map[string]any
	_ = json.Unmarshal(state.SelfRevocation, &raw)
	raw["sessionToken"] = cryptox.EncodeBase64(make([]byte, 32))
	state.SelfRevocation = selfMust(json.Marshal(raw))
	f.config.ProtectedState = selfMust(json.Marshal(state))
	if _, err := New(f.config); err == nil {
		t.Fatal("restored token/sessionhash mismatch accepted")
	}
}
