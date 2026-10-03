package syncclient

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// 公开合成向量只检typed控制、代际下界和native barrier；真实HPKE/PAKE另有HTTPS联合主项。
func TestDAGManagementTypedJournalBoundsAndBarrier(t *testing.T) {
	var f struct {
		Now   int64                     `json:"syntheticNow"`
		Seeds map[string]string         `json:"syntheticSeedsHex"`
		Pin   cryptox.PinnedIssuerRoot  `json:"rootPin"`
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	data, e := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
	check(t, e)
	check(t, json.Unmarshal(data, &f))
	ed, e := hex.DecodeString(f.Seeds["GEd"])
	check(t, e)
	key := ed25519.NewKeyFromSeed(ed)
	defer clear(key)
	receiving, e := hex.DecodeString(f.Seeds["GX"])
	check(t, e)
	defer clear(receiving)
	var accepted cryptox.AcceptedRecoveredDeviceV2
	for _, r := range f.Proof.Records {
		if r.Kind == "recovered-v2" {
			accepted = *r.RecoveredV2
		}
	}
	own := accepted.Submission.Grants
	trust := RecoveredDAGPinnedTrust{Trust: PinnedTrust{AccountID: f.Proof.AccountID, AccountGeneration: 1, DeviceID: accepted.Submission.Enrollment.DeviceID, DeviceSigningPublicKey: key.Public().(ed25519.PublicKey), ReceivingPrivateKey: receiving, Now: func() time.Time { return time.Unix(f.Now, 0) }}, Pin: f.Pin, Evidence: f.Proof, Accepted: accepted}
	verifier, e := NewRecoveredDAGPinnedVerifier(trust)
	check(t, e)
	defer verifier.Close()
	signed := make([]SignedGrant, len(own))
	for i, g := range own {
		signed[i] = SignedGrant{Grant: g.Grant, Signature: g.Signature}
	}
	cloud, e := verifier.VerifyPull(context.Background(), Pull{Full: true, AccountID: f.Proof.AccountID, AccountGeneration: "1", Sequence: 42, Grants: signed, IssuerDAGEvidence: &f.Proof}, localstate.CloudSnapshot{})
	check(t, e)
	engine, e := localstate.New(&volatileStore{state: localstate.EmptyState()})
	check(t, e)
	check(t, engine.AcceptSnapshot(cloud, time.Unix(f.Now, 0)))
	env := "environment-Z"
	var actor cryptox.SignedGrantWire
	for _, g := range own {
		if g.Grant.EnvironmentID == env {
			actor = g
		}
	}
	proof := cloneDAGEvidence(f.Proof)
	view, e := dagView(&proof)
	check(t, e)
	selected := []cryptox.IssuerTarget{}
	for _, target := range view.Targets {
		if target.EnvironmentID == env {
			selected = append(selected, target)
		}
	}
	view.Targets = selected

	var other cryptox.SignedGrantWire
	for _, node := range view.Authorities {
		if node.Grant.Grant.SubjectDeviceID == "recovered-E" && node.Grant.Grant.EnvironmentID == env {
			other = node.Grant
		}
	}
	if other.Grant.SubjectDeviceID == "" {
		t.Fatal("synthetic historical target missing")
	}
	out := ManagementControl{AccountID: f.Proof.AccountID, AccountGeneration: "1", EnvironmentID: env, Sequence: cloud.Sequence, KeyVersion: "1", Subjects: []ManagementSubject{{DeviceID: actor.Grant.SubjectDeviceID, SigningPublicKey: actor.Grant.SubjectSigningPublicKey, ReceivingPublicKey: actor.Grant.SubjectReceivingPublicKey, CurrentGrant: &actor, HighestGrantGeneration: actor.Grant.GrantGeneration}, {DeviceID: other.Grant.SubjectDeviceID, SigningPublicKey: other.Grant.SubjectSigningPublicKey, ReceivingPublicKey: other.Grant.SubjectReceivingPublicKey, CurrentGrant: &other, HighestGrantGeneration: other.Grant.GrantGeneration}}, IssuerDAGEvidence: &proof}
	var posts atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")
		if r.Header.Get("Harmonia-Protocol-Major") != "2" {
			t.Error("DAG major lost")
			w.WriteHeader(400)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/accounts/"+f.Proof.AccountID+"/grant-management":
			if r.URL.Query().Get("capability") != cryptox.RecoveryDAGCapability {
				t.Error("DAG parser downgraded")
				w.WriteHeader(400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"accountId": out.AccountID, "accountGeneration": out.AccountGeneration, "environmentId": out.EnvironmentID, "sequence": out.Sequence, "keyVersion": out.KeyVersion, "subjects": out.Subjects, "issuerEvidence": proof})
		case r.Method == "GET":
			_ = json.NewEncoder(w).Encode(GrantStatus{IdempotencyKey: r.URL.Query().Get("idempotencyKey")})
		default:
			posts.Add(1)
			_ = json.NewEncoder(w).Encode(Acceptance{Sequence: cloud.Sequence + 1})
		}
	}))
	defer server.Close()
	client, e := New(Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: f.Proof.AccountID, AccountGeneration: 1, DeviceID: trust.Trust.DeviceID, Token: cryptox.EncodeBase64(make([]byte, 32)), Verifier: verifier, Engine: engine, Now: trust.Trust.Now})
	check(t, e)
	live, e := client.ManagementControl(context.Background(), env)
	check(t, e)
	if live.IssuerDAGEvidence == nil || live.IssuerRecoveryEvidence != nil || live.IssuerEvidence.Profile != "" {
		t.Fatal("management mixed profiles")
	}
	if _, e := client.PrepareGrantUpdate(context.Background(), GrantUpdateIntent{ID: "dag-permanent-denied", EnvironmentID: env, SubjectDeviceID: other.Grant.SubjectDeviceID, Role: "admin", ExpiresAt: 0}, key); !errors.Is(e, ErrWritePermission) {
		t.Fatal("temporary Admin created permanent grant")
	}
	tx, e := client.PrepareGrantUpdate(context.Background(), GrantUpdateIntent{ID: "dag-management-update", EnvironmentID: env, SubjectDeviceID: other.Grant.SubjectDeviceID, Role: "rw", ExpiresAt: f.Now + 100}, key)
	check(t, e)
	packet, e := tx.ProtectedBytes()
	check(t, e)
	var original grantUpdateRecord
	check(t, json.Unmarshal(packet, &original))
	if original.Version != 2 || original.Capability != cryptox.RecoveryDAGCapability {
		t.Fatal("P4 record lacks explicit profile")
	}
	for _, attack := range []func(*grantUpdateRecord){func(r *grantUpdateRecord) { r.Version = 1 }, func(r *grantUpdateRecord) { r.Capability = "" }, func(r *grantUpdateRecord) { r.Control.IssuerDAGEvidence = nil }, func(r *grantUpdateRecord) { r.SessionEpoch++ }} {
		var bad grantUpdateRecord
		check(t, json.Unmarshal(packet, &bad))
		attack(&bad)
		wire, e := json.Marshal(bad)
		check(t, e)
		if _, e = client.RestoreGrantUpdate(wire); e == nil {
			t.Fatal("altered protected record accepted")
		}
	}
	restored, e := client.RestoreGrantUpdate(packet)
	check(t, e)
	if restored.record.Signed.Grant.GrantGeneration != strconv.FormatUint(environmentValueForManagement(t, other.Grant.GrantGeneration)+1, 10) {
		t.Fatal("highestGG was reset")
	}
	if _, e = restored.Submit(context.Background()); !errors.Is(e, ErrWriteJournal) {
		t.Fatal("P4 POST lacked native barrier")
	}
	barrier := errors.New("synthetic native save failed")
	if _, e = restored.SubmitWithBarrier(context.Background(), func() error { return barrier }); !errors.Is(e, barrier) || posts.Load() != 0 {
		t.Fatal("failed barrier posted signed packet")
	}
	_, e = restored.SubmitWithBarrier(context.Background(), func() error { return nil })
	check(t, e)
	if posts.Load() != 1 {
		t.Fatal("approved barrier did not send original packet")
	}
	if _, e = client.PrepareOtherRevocation(context.Background(), "global-remains-closed", other.Grant.SubjectDeviceID, env, key); !errors.Is(e, ErrWritePermission) {
		t.Fatal("P4 global revoke opened indirectly")
	}
	if _, e = client.RestoreOtherRevocation([]byte(`{}`)); !errors.Is(e, ErrWritePermission) {
		t.Fatal("P4 global revoke restore opened indirectly")
	}
	check(t, client.CheckManagementControlLowerBounds(live, live))
	lower := cloneManagementControl(live)
	lower.Subjects[1].CurrentGrant = nil
	lower.Subjects[1].HighestGrantGeneration = "0"
	if _, _, e = client.verifyManagementControl(lower); e != nil {
		t.Fatal("synthetic null metadata should be valid before saved bounds", e)
	}
	if e = client.CheckManagementControlLowerBounds(lower, live); !errors.Is(e, ErrGrantUpdateConflict) {
		t.Fatal("null/GG0 reset saved generation")
	}
	changed := cloneManagementControl(live)
	seed, e := hex.DecodeString(f.Seeds["EEd"])
	check(t, e)
	otherKey := ed25519.NewKeyFromSeed(seed)
	defer clear(otherKey)
	g := changed.Subjects[1].CurrentGrant.Grant
	g.Role = "ro"
	g.IdempotencyKey = "signed-metadata-different"
	fresh, e := cryptox.SignGrant(g, otherKey)
	check(t, e)
	row := cryptox.GrantToWire(fresh)
	changed.Subjects[1].CurrentGrant = &row
	if _, _, e = client.verifyManagementControl(changed); e != nil {
		t.Fatal("same GG candidate must first pass source validation", e)
	}
	if e = client.CheckManagementControlLowerBounds(changed, live); !errors.Is(e, ErrGrantUpdateConflict) {
		t.Fatal("same GG changed signed fingerprint")
	}
	future := cloud
	future.Sequence++
	check(t, engine.AcceptSnapshot(future, time.Unix(f.Now, 0)))
	if _, _, e = client.verifyManagementControl(live, false); e == nil {
		t.Fatal("false bypassed live checkpoint")
	}
	if _, _, e = client.verifyManagementControl(live, true, false); e == nil {
		t.Fatal("multiple history arguments accepted")
	}
	_, _, e = client.verifyManagementControl(live, true)
	check(t, e)
}
func environmentValueForManagement(t *testing.T, value string) uint64 {
	t.Helper()
	n, e := strconv.ParseUint(value, 10, 64)
	check(t, e)
	return n
}

// 只验证旧来源不会被新增P4门槛截断；未构造全局撤销可信包或声称该操作新验收。
func TestLegacyOtherRevocationEntrypointsRemainAvailable(t *testing.T) {
	f := newManagementFixture(t)
	_, e := f.c.PrepareOtherRevocation(context.Background(), "legacy-revoke-route", "synthetic-other", "managed-env", f.key)
	var request *RequestError
	if !errors.As(e, &request) || request.Status != http.StatusNotFound {
		t.Fatal("legacy prepare must reach existing receipt route", e)
	}
	if _, e = f.c.RestoreOtherRevocation([]byte(`{}`)); !errors.Is(e, cryptox.ErrInvalidWire) {
		t.Fatal("legacy restore must retain strict original parser", e)
	}
	if f.posts != 0 {
		t.Fatal("legacy entrypoint compatibility probe posted")
	}
}
