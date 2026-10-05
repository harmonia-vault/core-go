package localkeys

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/harmonia-vault/core-go/localstate"
)

func trustFixture(t *testing.T, v *Vault) TrustContext {
	t.Helper()
	keys, err := GenerateDeviceKeys("synthetic-device")
	if err != nil {
		t.Fatal(err)
	}
	if err = v.SaveDeviceKeys(keys); err != nil {
		t.Fatal(err)
	}
	return TrustContext{Endpoint: "https://synthetic.invalid/harmonia", AccountID: "synthetic-account", AccountGeneration: 1, DeviceID: keys.DeviceID, SigningPublic: keys.SigningPublic, ReceivingPublic: keys.ReceivingPublic, CertificateVersion: "5", PairingProfile: EnrollmentPairingProfile, EnrollmentCertificate: json.RawMessage(`{"syntheticReceipt":true}`), EnrollmentKey: "synthetic-enrollment"}
}
func TestTrustPendingRestartBindingsAndAcceptance(t *testing.T) {
	config := testConfig(t)
	v := openTest(t, config)
	trust := trustFixture(t, v)
	session := LoginSession{Endpoint: trust.Endpoint, AccountID: trust.AccountID, AccountGeneration: trust.AccountGeneration, Token: "synthetic-login-token-0123456789", ExpiresAt: "2030-01-01T00:00:00Z"}
	if err := v.SaveSession(session); err != nil {
		t.Fatal(err)
	}
	if err := v.SaveTrustContext(trust); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	v = openTest(t, config)
	restored, err := v.LoadTrustContext()
	if err != nil || restored.Accepted || restored.EnrollmentKey != trust.EnrollmentKey || !bytes.Equal(restored.SigningPublic, trust.SigningPublic) {
		t.Fatal("pending receipt did not survive restart")
	}
	trust.Accepted = true
	if err := v.SaveTrustContext(trust); err != nil {
		t.Fatal(err)
	}
	if restored, err = v.LoadTrustContext(); err != nil || !restored.Accepted {
		t.Fatal("accepted status not persisted")
	}
	trust.Accepted = false
	if err := v.SaveTrustContext(trust); !errors.Is(err, ErrIdentity) {
		t.Fatal("accepted receipt moved backwards")
	}
	trust.Accepted = true
	session.AccountGeneration++
	if err := v.SaveSession(session); !errors.Is(err, ErrIdentity) {
		t.Fatal("session changed bound generation")
	}
	keys, err := GenerateDeviceKeys(trust.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SaveDeviceKeys(keys); !errors.Is(err, ErrIdentity) {
		t.Fatal("bound device keys were replaced")
	}
	trust.AccountGeneration++
	if err := v.SaveTrustContext(trust); !errors.Is(err, ErrIdentity) {
		t.Fatal("trust changed bound account generation")
	}
}
func TestTrustValidationAndMissingOrMismatchedMaterial(t *testing.T) {
	v := openTest(t, testConfig(t))
	trust := trustFixture(t, v)
	for _, field := range []string{"endpoint", "account", "generation", "device", "enrollment", "signing", "receiving", "profile", "certificate", "certificate-size"} {
		t.Run(field, func(t *testing.T) {
			data, _ := json.Marshal(trust)
			var candidate TrustContext
			_ = json.Unmarshal(data, &candidate)
			switch field {
			case "endpoint":
				candidate.Endpoint = "https://synthetic.invalid?secret=query"
			case "account":
				candidate.AccountID = "../synthetic"
			case "generation":
				candidate.AccountGeneration = 0
			case "device":
				candidate.DeviceID = ""
			case "enrollment":
				candidate.EnrollmentKey = "../synthetic"
			case "signing":
				candidate.SigningPublic = nil
			case "receiving":
				candidate.ReceivingPublic = nil
			case "profile":
				candidate.PairingProfile = "unverified-profile"
			case "certificate":
				candidate.EnrollmentCertificate = json.RawMessage(`null`)
			case "certificate-size":
				candidate.EnrollmentCertificate = json.RawMessage(`{"x":"` + string(bytes.Repeat([]byte{'x'}, maxEnrollmentCertificateV5)) + `"}`)
			}
			if err := v.SaveTrustContext(candidate); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid trust field accepted: %v", err)
			}
		})
	}
	trust.SigningPublic = append([]byte(nil), trust.SigningPublic...)
	trust.SigningPublic[0] ^= 1
	if err := v.SaveTrustContext(trust); !errors.Is(err, ErrIdentity) {
		t.Fatal("trust/device public keys mismatch accepted")
	}
	if err := v.Delete("device-v1"); err != nil {
		t.Fatal(err)
	}
	if err := v.SaveTrustContext(trust); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("trust saved without device keys")
	}
}
func TestTrustLoadsRejectIndependentSlotMismatchAndAccountState(t *testing.T) {
	config := testConfig(t)
	store, err := OpenEncryptedStateStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	v := store.Vault()
	trust := trustFixture(t, v)
	trust.Accepted = true
	if err := v.SaveTrustContext(trust); err != nil {
		t.Fatal(err)
	}
	state := localstate.EmptyState()
	state.Cloud.AccountID, state.Cloud.AccountGeneration, state.Cloud.Sequence = trust.AccountID, trust.AccountGeneration, 1
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	state.Cloud.AccountGeneration++
	if err := store.Save(state); !errors.Is(err, ErrIdentity) {
		t.Fatal("wrong account entered encrypted state")
	}
	data, _ := json.Marshal(state)
	if err := v.Save("state-v1", data); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrIdentity) {
		t.Fatal("wrong account state loaded")
	}
	badSession := LoginSession{Endpoint: trust.Endpoint, AccountID: "other-synthetic-account", AccountGeneration: 1, Token: "synthetic-token-0123456789", ExpiresAt: "2030-01-01T00:00:00Z"}
	data, _ = json.Marshal(badSession)
	if err := v.Save("session-v1", data); err != nil {
		t.Fatal(err)
	}
	if _, err := v.LoadTrustContext(); !errors.Is(err, ErrIdentity) {
		t.Fatal("independent wrong session slot not rejected")
	}
	if err := v.Delete("session-v1"); err != nil {
		t.Fatal(err)
	}
	keys, err := GenerateDeviceKeys(trust.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = json.Marshal(keys)
	if err := v.Save("device-v1", data); err != nil {
		t.Fatal(err)
	}
	if _, err := v.LoadTrustContext(); !errors.Is(err, ErrIdentity) {
		t.Fatal("independent wrong device slot not rejected")
	}
}
