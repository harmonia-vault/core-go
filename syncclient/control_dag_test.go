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
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// 固定公开向量只检验本地typed DTO门槛；真实HTTP接受/HPKE/PAKE另有联合测试。
func TestDAGEnvironmentControlsExplicitProfileHistoryAndPause(t *testing.T) {
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
	var fault atomic.Int64
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Harmonia-Protocol-Major", "2")
		if r.Method != "GET" || r.URL.Query().Get("capability") != cryptox.RecoveryDAGCapability || r.Header.Get("Harmonia-Protocol-Major") != "2" {
			t.Error("wrong capability/method/major")
			w.WriteHeader(400)
			return
		}
		candidate := cloneDAGEvidence(proof)
		var evidence any = candidate
		switch fault.Load() {
		case 1:
			evidence = cryptox.IssuerProofV2{Profile: cryptox.IssuerProofV2Profile}
		case 2:
			evidence = cryptox.IssuerRecoveryProof{Profile: cryptox.IssuerRecoveryProfile}
		case 3:
			candidate.Records = []cryptox.RecoveryDAGRecord{}
			evidence = candidate
		case 4:
			candidate.Records[0].TransitionV1.Sequence++
			evidence = candidate
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sequence": cloud.Sequence, "grants": []cryptox.SignedGrantWire{actor}, "issuerEvidence": evidence})
	}))
	defer server.Close()
	client, e := New(Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: f.Proof.AccountID, AccountGeneration: 1, DeviceID: trust.Trust.DeviceID, Token: cryptox.EncodeBase64(make([]byte, 32)), Verifier: verifier, Engine: engine, Now: trust.Trust.Now})
	check(t, e)
	control, e := client.EnvironmentControl(context.Background(), env)
	check(t, e)
	if control.IssuerDAGEvidence == nil || control.IssuerRecoveryEvidence != nil || control.IssuerEvidence.Profile != "" {
		t.Fatal("DAG cast as old profile")
	}
	for _, kind := range []int64{1, 2, 3, 4} {
		fault.Store(kind)
		if _, e := client.EnvironmentControl(context.Background(), env); e == nil {
			t.Fatalf("invalid candidate accepted: class%d", kind)
		}
	}
	fault.Store(0)
	mixed := control
	mixed.IssuerRecoveryEvidence = &cryptox.IssuerRecoveryProof{}
	if _, e := client.VerifyEnvironmentControl(mixed, env, true); e == nil {
		t.Fatal("mixed profiles accepted")
	}
	future := cloud
	future.Sequence++
	check(t, engine.AcceptSnapshot(future, time.Unix(f.Now, 0)))
	if _, e := client.VerifyEnvironmentControl(control, env, false); e == nil {
		t.Fatal("false bypassed live checkpoint")
	}
	if _, e := client.VerifyEnvironmentControl(control, env); e == nil {
		t.Fatal("default bypassed live checkpoint")
	}
	if _, e := client.VerifyEnvironmentControl(control, env, true, false); e == nil {
		t.Fatal("multiple history flags accepted")
	}
	_, e = client.VerifyEnvironmentControl(control, env, true)
	check(t, e)
	before := requests.Load()
	if _, e := client.EnvironmentStatusV2(context.Background(), "old-id"); !errors.Is(e, ErrWritePermission) {
		t.Fatal("P4 used P2 namespace")
	}
	if _, e := client.PrepareEnvironmentChangeV3(context.Background(), cryptox.SignedEnvironmentChange{}, key); !errors.Is(e, ErrWritePermission) {
		t.Fatal("P4 used P3 namespace")
	}
	check(t, engine.SetPaused(true))
	if _, e := client.EnvironmentControl(context.Background(), env); !errors.Is(e, ErrPaused) {
		t.Fatal("paused environment preparation allowed")
	}
	if requests.Load() != before {
		t.Fatal("blocked operation reached network")
	}
}
