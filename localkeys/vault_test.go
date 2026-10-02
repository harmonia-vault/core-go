package localkeys

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/harmonia-vault/core-go/localstate"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := CurrentUserID()
	if err != nil {
		t.Fatal(err)
	}
	return Config{Directory: filepath.Join(canonical, "protected"), UserID: owner}
}
func openTest(t *testing.T, c Config) *Vault {
	t.Helper()
	v, err := Open(c)
	if err != nil {
		t.Fatalf("cannot open isolated key store: %v", err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}
func TestEncryptedRestartMaterialsAndStateStore(t *testing.T) {
	c := testConfig(t)
	store, err := OpenEncryptedStateStore(c)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := GenerateDeviceKeys("synthetic-device")
	if err != nil {
		t.Fatal(err)
	}
	session := LoginSession{Endpoint: "https://synthetic.invalid", AccountID: "synthetic-account", AccountGeneration: 1, Token: "synthetic-session-token-0123456789", ExpiresAt: "2030-01-01T00:00:00Z"}
	if err := store.Vault().SaveDeviceKeys(keys); err != nil {
		t.Fatal(err)
	}
	if err := store.Vault().SaveSession(session); err != nil {
		t.Fatal(err)
	}
	state := localstate.EmptyState()
	state.Overrides = map[string]map[string]string{"synthetic-env": {"SYNTHETIC_KEY": "synthetic-local-secret"}}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	for _, slot := range []string{"state-v1", "device-v1", "session-v1"} {
		name := slots[slot]
		data, err := os.ReadFile(filepath.Join(c.Directory, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, needle := range []string{"synthetic-session-token", "synthetic-local-secret", base64.StdEncoding.EncodeToString(keys.SigningSeed), base64.StdEncoding.EncodeToString(keys.ReceivingPrivate)} {
			if bytes.Contains(data, []byte(needle)) {
				t.Fatal("sensitive fixture appears in encrypted disk record")
			}
		}
	}
	if _, err := Open(c); !errors.Is(err, ErrBusy) {
		t.Fatalf("second writer did not fail busy: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenEncryptedStateStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	restored, err := store.Load()
	if err != nil || restored.Overrides["synthetic-env"]["SYNTHETIC_KEY"] != "synthetic-local-secret" {
		t.Fatal("state did not survive restart")
	}
	restoredKeys, err := store.Vault().LoadDeviceKeys()
	if err != nil || !bytes.Equal(restoredKeys.SigningSeed, keys.SigningSeed) || !bytes.Equal(restoredKeys.ReceivingPrivate, keys.ReceivingPrivate) {
		t.Fatal("device keys did not survive restart")
	}
	restoredSession, err := store.Vault().LoadSession()
	if err != nil || restoredSession.Token != session.Token {
		t.Fatal("session did not survive restart")
	}
	state.Synthetic = true
	if err := store.Save(state); !errors.Is(err, ErrFixture) {
		t.Fatal("fixture state entered encrypted service store")
	}
	if _, err := store.Vault().Load("../machine-key.v1"); !errors.Is(err, ErrSlot) {
		t.Fatal("accepted arbitrary path slot")
	}
}
func TestCiphertextAuthenticationNonceAndSlotBinding(t *testing.T) {
	c := testConfig(t)
	v := openTest(t, c)
	if err := v.Save("state-v1", []byte("synthetic-sensitive")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.Directory, slots["state-v1"])
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Save("state-v1", []byte("synthetic-sensitive")); err != nil {
		t.Fatal(err)
	}
	repeated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, repeated) {
		t.Fatal("nonce reused for repeated save")
	}
	for _, mutation := range []string{"ciphertext", "nonce", "schema", "user", "owner", "key", "slot", "unknown", "trailing"} {
		t.Run(mutation, func(t *testing.T) {
			var record encryptedRecord
			if err := json.Unmarshal(original, &record); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "ciphertext":
				record.Ciphertext[0] ^= 1
			case "nonce":
				record.Nonce[0] ^= 1
			case "schema":
				record.Schema = "other"
			case "user":
				record.UserID = "other"
			case "owner":
				record.OwnerID = "other"
			case "key":
				record.KeyID = "other"
			case "slot":
				record.Slot = "session-v1"
			}
			data, _ := json.Marshal(record)
			if mutation == "unknown" {
				data = append(data[:len(data)-1], []byte(`,"unexpected":true}`)...)
			}
			if mutation == "trailing" {
				data = append(data, []byte(` {}`)...)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := v.Load("state-v1"); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("accepted tampered record: %v", err)
			}
		})
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	var moved encryptedRecord
	if err := json.Unmarshal(original, &moved); err != nil {
		t.Fatal(err)
	}
	moved.Slot = "device-v1"
	data, _ := json.Marshal(moved)
	if err := os.WriteFile(filepath.Join(c.Directory, slots["device-v1"]), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Load("device-v1"); !errors.Is(err, ErrCorrupt) {
		t.Fatal("ciphertext accepted in another slot after metadata rewrite")
	}
	if plaintext, err := v.Load("state-v1"); err != nil || string(plaintext) != "synthetic-sensitive" {
		t.Fatal("authentic state failed after restoration")
	}
}
func TestMissingOrCorruptMachineKeyNeverReinitializes(t *testing.T) {
	c := testConfig(t)
	v := openTest(t, c)
	if err := v.Save("state-v1", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	v.Close()
	path := filepath.Join(c.Directory, keyFile)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(c); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing key was not rejected: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing key silently regenerated")
	}
	corrupt := []byte("not a machine key")
	fs, _, err := openSecureFS(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Write(keyFile, corrupt, true); err != nil {
		fs.Close()
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(c); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt key accepted: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, corrupt) {
		t.Fatal("corrupt key overwritten")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if value, err := restored.Load("state-v1"); err != nil || string(value) != "synthetic" {
		t.Fatal("restore with original key failed")
	}
}
func TestClosedDeletionAndMaterialValidation(t *testing.T) {
	c := testConfig(t)
	v := openTest(t, c)
	if _, err := v.Load("session-v1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new store has implicit login session")
	}
	if err := v.Save("session-v1", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete("session-v1"); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete("session-v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Load("session-v1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted session remained")
	}
	keys, err := GenerateDeviceKeys("synthetic")
	if err != nil {
		t.Fatal(err)
	}
	keys.SigningPublic[0] ^= 1
	if err := v.SaveDeviceKeys(keys); !errors.Is(err, ErrCorrupt) {
		t.Fatal("inconsistent public/private keys accepted")
	}
	bad := LoginSession{Endpoint: "http://synthetic.invalid", AccountID: "test", AccountGeneration: 1, Token: "synthetic-token-0123456789", ExpiresAt: "2030-01-01T00:00:00Z"}
	if err := v.SaveSession(bad); !errors.Is(err, ErrCorrupt) {
		t.Fatal("insecure endpoint accepted")
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Load("state-v1"); !errors.Is(err, ErrClosed) {
		t.Fatal("closed store could decrypt")
	}
	if err := v.Save("state-v1", []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatal("closed store could write")
	}
}
func TestUserIdentityRejectedBeforeDirectoryCreation(t *testing.T) {
	c := testConfig(t)
	if runtime.GOOS == "windows" {
		c.UserID = "S-1-5-21-11-22-33-1002"
	} else {
		c.UserID = "4294967294"
	}
	if _, err := Open(c); !errors.Is(err, ErrIdentity) {
		t.Fatalf("wrong user not rejected: %v", err)
	}
	if _, err := os.Stat(c.Directory); !os.IsNotExist(err) {
		t.Fatal("wrong user created state directory")
	}
}
