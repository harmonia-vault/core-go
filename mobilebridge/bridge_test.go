package mobilebridge

import (
	"bytes"
	"encoding/json"
	"github.com/harmonia-vault/core-go/pairing"
	"strings"
	"testing"
)

func TestStrictCommandsAndEndpoint(t *testing.T) {
	good := []string{"https://vault.example.invalid", "https://vault.example.invalid:8443/api", "https://[::1]:8443"}
	for _, endpoint := range good {
		raw, _ := json.Marshal(map[string]any{"version": 1, "operation": "validateEndpoint", "endpoint": endpoint})
		if _, err := ExecutePublic(string(raw)); err != nil {
			t.Fatalf("valid endpoint %q: %v", endpoint, err)
		}
	}
	bad := []string{"http://vault.example.invalid", "https://u:p@host", "https://host?", "https://host#", "https://host:0", "https://host:65536", "https://host:0443", "https://host:", "https://host./", "https://-host", "https://host/a/../b", "https://host/a%2fb", "https://host//a", "https://host\\evil", " https://host"}
	for _, endpoint := range bad {
		raw, _ := json.Marshal(map[string]any{"version": 1, "operation": "validateEndpoint", "endpoint": endpoint})
		if _, err := ExecutePublic(string(raw)); err == nil {
			t.Fatalf("unsafe endpoint accepted %q", endpoint)
		}
	}
	for _, raw := range []string{`{"version":1,"version":1,"operation":"capabilities"}`, `{"version":1,"operation":"capabilities","endpoint":""}`, `{"version":1,"operation":"capabilities","role":"admin"}`, `{"version":2,"operation":"capabilities"}`, `{"version":1,"operation":"capabilities"} {}`, `{"version":1,"operation":"capabilities","x":{}}`, strings.Repeat(" ", 4097), "[]"} {
		if _, err := ExecutePublic(raw); err == nil {
			t.Fatalf("bad command accepted %q", raw)
		}
	}
}
func TestIndependentKeysProtectedRoundTripAndClose(t *testing.T) {
	d, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	public, err := d.Execute(`{"version":1,"operation":"publicInfo"}`)
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	if json.Unmarshal([]byte(public), &info) != nil || info["trusted"] != false || info["signingPublicKey"] == info["receivingPublicKey"] {
		t.Fatal("untrusted independent keys failed")
	}
	material, err := d.ExportProtectedMaterial()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material)
	restored, err := ImportProtectedMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	same, err := restored.Execute(`{"version":1,"operation":"publicInfo"}`)
	if err != nil || same != public {
		t.Fatal("protected material identity changed")
	}
	material[8] ^= 1
	same, _ = restored.Execute(`{"version":1,"operation":"publicInfo"}`)
	if same != public {
		t.Fatal("import aliases caller buffer")
	}
	if _, err := restored.Execute(`{"version":1,"operation":"cryptoCheck"}`); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"pull", "submit", "approveDevice", "revokeDevice", "recover"} {
		if _, err := restored.Execute(`{"version":1,"operation":"` + op + `"}`); err == nil {
			t.Fatal("unenrolled security operation accepted", op)
		}
	}
	restored.Close()
	if _, err := restored.ExportProtectedMaterial(); err == nil {
		t.Fatal("closed secret exported")
	}
	if _, err := restored.Execute(`{"version":1,"operation":"publicInfo"}`); err == nil {
		t.Fatal("closed device used")
	}
	for _, bad := range [][]byte{nil, []byte(materialHeader), append([]byte(materialHeader), make([]byte, 64)...), append(bytes.Clone(material), 0)} {
		if device, err := ImportProtectedMaterial(bad); err == nil {
			device.Close()
			t.Fatal("invalid material accepted")
		}
	}
}
func TestNativeGateAndSelfTest(t *testing.T) {
	output, err := NativeSelfTest()
	if pairing.NativeAvailable() {
		if err != nil || !strings.Contains(output, `"spake2":true`) {
			t.Fatalf("native selftest: %s %v", output, err)
		}
	} else if err == nil {
		t.Fatal("unlinked native accepted")
	}
}
func TestSHA256Boundary(t *testing.T) {
	hash, err := Hash256([]byte("abc"))
	if err != nil || len(hash) != 32 {
		t.Fatal(err)
	}
	if _, err := Hash256(make([]byte, 16385)); err == nil {
		t.Fatal("oversize hash accepted")
	}
}
