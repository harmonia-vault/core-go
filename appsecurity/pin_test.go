package appsecurity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func fixture(t *testing.T) (Record, AttemptState, Binding, []byte) {
	t.Helper()
	material := append([]byte("HARMKEY1"), bytes.Repeat([]byte{31}, 32)...)
	material = append(material, bytes.Repeat([]byte{37}, 32)...)
	ed := ed25519.NewKeyFromSeed(material[8:40])
	defer clear(ed)
	x, e := ecdh.X25519().NewPrivateKey(material[40:])
	if e != nil {
		t.Fatal(e)
	}
	b := Binding{Package: "org.harmonia.fixture", Namespace: "harmonia/local-protection/v1", Slot: "synthetic-slot", Endpoint: "https://example.invalid", Mode: "pin", AuthGeneration: strings.Repeat("1", 32), KeyEpoch: strings.Repeat("2", 32), SigningPublicKey: enc(ed.Public().(ed25519.PublicKey)), ReceivingPublicKey: enc(x.PublicKey().Bytes())}
	r, s, e := CreateRecord([]byte("12345678"), []byte("12345678"), b, material)
	if e != nil {
		t.Fatal(e)
	}
	return r, s, b, material
}
func TestPINUsesRealArgon2AndAEADWithNoFastVerifier(t *testing.T) {
	r, _, b, material := fixture(t)
	data, e := r.Encode()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeRecord(data, b)
	if e != nil {
		t.Fatal(e)
	}
	got, e := openRecord([]byte("12345678"), decoded)
	if e != nil || !bytes.Equal(got, material) {
		t.Fatal("real protected material roundtrip failed", e)
	}
	clear(got)
	if _, e = openRecord([]byte("12345679"), decoded); !errors.Is(e, ErrPIN) {
		t.Fatal("wrong PIN opened material", e)
	}
	for _, which := range []string{"wrapped-key", "material", "endpoint"} {
		changed := r
		switch which {
		case "wrapped-key":
			packet, _ := raw(changed.WrappedVaultKey, 48)
			packet[0] ^= 1
			changed.WrappedVaultKey = enc(packet)
		case "material":
			packet, _ := raw(changed.SealedMaterial, 88)
			packet[0] ^= 1
			changed.SealedMaterial = enc(packet)
		case "endpoint":
			changed.Binding.Endpoint = "https://other.invalid"
		}
		if _, e = openRecord([]byte("12345678"), changed); e == nil {
			t.Fatal("tampered packet/AAD opened material", which)
		}
	}
}
func TestPINStrictScopeParametersAndSetupReentry(t *testing.T) {
	r, _, b, material := fixture(t)
	for _, pin := range [][]byte{nil, []byte("12345"), []byte("１２３４５６"), []byte("123456 "), bytes.Repeat([]byte{'7'}, 33)} {
		if _, _, e := CreateRecord(pin, pin, b, material); !errors.Is(e, ErrConfiguration) {
			t.Fatal("invalid PIN setup accepted", e)
		}
	}
	if _, _, e := CreateRecord([]byte("12345678"), []byte("12345679"), b, material); e == nil {
		t.Fatal("setup skipped full reentry")
	}
	data, _ := r.Encode()
	for _, bad := range [][]byte{append(data, []byte("{}")...), []byte(strings.Replace(string(data), `"version":1`, `"version":1,"version":1`, 1)), []byte(strings.Replace(string(data), `"memoryKiB":65536`, `"memoryKiB":1`, 1)), []byte(strings.Replace(string(data), `"profile":`, `"unknown":1,"profile":`, 1))} {
		if _, e := DecodeRecord(bad, b); !errors.Is(e, ErrRecord) {
			t.Fatal("malformed or weakened KDF record accepted", e)
		}
	}
	wrong := b
	wrong.Mode = "system"
	if _, e := DecodeRecord(data, wrong); e == nil {
		t.Fatal("mode downgrade accepted")
	}
	wrong = b
	wrong.AuthGeneration = strings.Repeat("3", 32)
	if _, e := DecodeRecord(data, wrong); e == nil {
		t.Fatal("old auth generation revived record")
	}
	var object map[string]json.RawMessage
	if e := json.Unmarshal(data, &object); e != nil || len(object) != 9 {
		t.Fatal("unexpected fast verifier/secret field", e)
	}
}
