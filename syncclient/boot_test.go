package syncclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

func TestBootUsesExactKeysWithoutLoginCredential(t *testing.T) {
	f := newCryptoFixture(t)
	nonce := cryptox.EncodeBase64(make([]byte, 32))
	expires := fixedNow.Add(2 * time.Minute).Unix()
	receivingPublic, err := cryptox.DecodeBase64(f.verifier.receivingPublicKey, 32, 32)
	check(t, err)
	proof, err := cryptox.NewDeviceBootProof("acct", "1", "dev", f.devicePublic, receivingPublic, "boot-1", nonce, fmtInt(expires))
	check(t, err)
	wire, err := proof.SigningBytes()
	check(t, err)
	var fields []string
	_ = json.Unmarshal(wire, &fields)
	boundToken := cryptox.EncodeBase64(append([]byte{7}, make([]byte, 31)...))
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		calls.Add(1)
		switch {
		case strings.HasSuffix(r.URL.Path, "/boot-challenges"):
			if r.Header.Get("Authorization") != "" {
				t.Error("boot sent a login credential")
			}
			_ = json.NewEncoder(w).Encode(DeviceChallenge{ChallengeID: "boot-1", Nonce: nonce, ExpiresAt: expires, SigningPayload: fields})
		case strings.HasSuffix(r.URL.Path, "/boot-sessions"):
			if r.Header.Get("Authorization") != "" {
				t.Error("boot session sent a login credential")
			}
			var request struct {
				DeviceID          string `json:"deviceId"`
				AccountGeneration string `json:"accountGeneration"`
				ChallengeID       string `json:"challengeId"`
				Signature         string `json:"signature"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request.DeviceID != "dev" || request.AccountGeneration != "1" || request.ChallengeID != "boot-1" || cryptox.VerifyDeviceBootProof(proof, request.Signature, f.devicePublic) != nil {
				http.Error(w, "invalid proof", 403)
				return
			}
			_ = json.NewEncoder(w).Encode(DeviceSession{Token: boundToken, ExpiresAt: fixedNow.Add(time.Hour).Unix()})
		default:
			if r.Header.Get("Authorization") != "Bearer "+boundToken {
				http.Error(w, "bound device session required", 403)
				return
			}
			_ = json.NewEncoder(w).Encode(f.pull(1, f.event(t, 1, "synthetic-boot-value")))
		}
	}))
	defer server.Close()
	client, err := NewForBoot(Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: "acct", AccountGeneration: 1, DeviceID: "dev", Engine: testEngine(t), Verifier: f.verifier, Now: func() time.Time { return fixedNow }})
	check(t, err)
	if _, err = client.Pull(context.Background()); err == nil || calls.Load() != 0 {
		t.Fatal("anonymous boot client read data")
	}
	bound, err := client.BootDevice(context.Background(), f.devicePrivate)
	check(t, err)
	_, err = bound.Pull(context.Background())
	check(t, err)
	if bound.config.Engine.State().Cloud.Environments["env"].Values["TOKEN"] != "synthetic-boot-value" {
		t.Fatal("boot pull did not verify/decrypt")
	}
}
func TestBootRejectsBlindSigningAndLoginCredential(t *testing.T) {
	f := newCryptoFixture(t)
	var signed atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		if strings.HasSuffix(r.URL.Path, "boot-sessions") {
			signed.Add(1)
		}
		_ = json.NewEncoder(w).Encode(DeviceChallenge{ChallengeID: "boot-1", Nonce: cryptox.EncodeBase64(make([]byte, 32)), ExpiresAt: fixedNow.Add(time.Minute).Unix(), SigningPayload: []string{"unrelated operation"}})
	}))
	defer server.Close()
	config := Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: "acct", AccountGeneration: 1, DeviceID: "dev", Engine: testEngine(t), Verifier: f.verifier, Now: func() time.Time { return fixedNow }}
	client, err := NewForBoot(config)
	check(t, err)
	if _, err = client.BootDevice(context.Background(), f.devicePrivate); err == nil || signed.Load() != 0 {
		t.Fatal("boot blind-signed an unrelated challenge")
	}
	config.Token = "SYNTHETIC_LOGIN_CREDENTIAL"
	if _, err = NewForBoot(config); err == nil {
		t.Fatal("boot retained a login credential")
	}
	if _, err = client.BootDevice(context.Background(), ed25519.NewKeyFromSeed(make([]byte, 32))); err == nil {
		t.Fatal("wrong local signing key accepted")
	}
}

type logoutDuringVerification struct{ engine *localstate.Engine }

func (v logoutDuringVerification) VerifyPull(_ context.Context, pull Pull, _ localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	if err := v.engine.Logout(); err != nil {
		return localstate.CloudSnapshot{}, err
	}
	return acceptVerifier{}.VerifyPull(context.Background(), pull, localstate.CloudSnapshot{})
}
func TestOldPullCannotRepopulateAfterLogout(t *testing.T) {
	engine := testEngine(t)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(Pull{AccountID: "acct", AccountGeneration: "1", Sequence: 1})
	}))
	defer server.Close()
	client := testClient(t, server, engine, logoutDuringVerification{engine})
	if _, err := client.Pull(context.Background()); !errors.Is(err, localstate.ErrLocalSession) {
		t.Fatal(err)
	}
	if len(engine.State().Cloud.Environments) != 0 || engine.State().Cloud.AccountID != "" {
		t.Fatal("old pull revived logged-out cache")
	}
	if _, err := client.Pull(context.Background()); !errors.Is(err, localstate.ErrLocalSession) || calls.Load() != 1 {
		t.Fatal("old client made a new request after logout", err)
	}
}
