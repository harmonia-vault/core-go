package cryptox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func fixtureBytes(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPasswordExactlySHA256(t *testing.T) {
	got := PasswordCredential("synthetic-password")
	if hex.EncodeToString(got[:]) != "d7edf5af6b41d1725d40892f976e6cd8ba97046d0e1ffb48365ce759630a4d41" {
		t.Fatalf("unexpected SHA256 fixture: %x", got)
	}
}

func TestValueAuthenticationAndBounds(t *testing.T) {
	key := fixtureBytes(32, 0)
	c := ValueContext{"account-test", "1", "environment-test", "1", "TEST_VALUE"}
	plain := []byte("synthetic-secret-only")
	packet, err := EncryptValue(key, c, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptValue(key, c, packet)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	for i := range packet {
		corrupt := bytes.Clone(packet)
		corrupt[i] ^= 1
		if _, err := DecryptValue(key, c, corrupt); err == nil {
			t.Fatalf("accepted tampering at %d", i)
		}
	}
	contexts := []ValueContext{
		{"other-account", "1", c.EnvironmentID, "1", c.Name},
		{c.AccountID, "2", c.EnvironmentID, "1", c.Name},
		{c.AccountID, "1", "other-environment", "1", c.Name},
		{c.AccountID, "1", c.EnvironmentID, "2", c.Name},
		{c.AccountID, "1", c.EnvironmentID, "1", "OTHER_NAME"},
	}
	for _, other := range contexts {
		if _, err := DecryptValue(key, other, packet); err == nil {
			t.Fatalf("accepted context substitution: %+v", other)
		}
	}
	if _, err := DecryptValue(fixtureBytes(32, 1), c, packet); err == nil {
		t.Fatal("accepted wrong key")
	}
	for _, p := range [][]byte{nil, make([]byte, 39), make([]byte, MaxValueBytes+41)} {
		if _, err := DecryptValue(key, c, p); err == nil {
			t.Fatal("accepted malformed packet")
		}
	}
	if _, err := EncryptValue(key, c, make([]byte, MaxValueBytes+1)); err == nil {
		t.Fatal("accepted oversized value")
	}
	second, err := EncryptValue(key, c, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(packet[:24], second[:24]) {
		t.Fatal("random nonces repeated")
	}
	for _, p := range [][]byte{nil, make([]byte, MaxValueBytes)} {
		packet, err := EncryptValue(key, c, p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecryptValue(key, c, packet)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatal("boundary round trip failed")
		}
	}
}

func TestHPKEEnvelopeBinding(t *testing.T) {
	pub, priv, err := GenerateReceivingKey()
	if err != nil {
		t.Fatal(err)
	}
	c := EnvelopeContext{"account-test", "1", "environment-test", "2", "device", "device-test", "3", EncodeBase64(pub)}
	key := fixtureBytes(32, 40)
	packet, err := WrapEnvironmentKey(key, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 80 {
		t.Fatalf("packet length %d", len(packet))
	}
	got, err := UnwrapEnvironmentKey(priv, c, packet)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("round trip: %x %v", got, err)
	}
	for i := range packet {
		bad := bytes.Clone(packet)
		bad[i] ^= 1
		if _, err := UnwrapEnvironmentKey(priv, c, bad); err == nil {
			t.Fatalf("accepted HPKE tamper at %d", i)
		}
	}
	for _, field := range []string{"AccountID", "AccountGeneration", "EnvironmentID", "KeyVersion", "RecipientID", "RecipientGeneration", "RecipientType"} {
		bad := c
		f := reflect.ValueOf(&bad).Elem().FieldByName(field)
		switch field {
		case "AccountGeneration", "KeyVersion", "RecipientGeneration":
			f.SetString("9")
		case "RecipientType":
			f.SetString("recovery")
		default:
			f.SetString("other-test")
		}
		if _, err := UnwrapEnvironmentKey(priv, bad, packet); err == nil {
			t.Fatalf("accepted substituted %s", field)
		}
	}
	otherPub, otherPriv, err := GenerateReceivingKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapEnvironmentKey(otherPriv, c, packet); err == nil {
		t.Fatal("accepted mismatched recipient")
	}
	bad := c
	bad.RecipientPublicKey = EncodeBase64(otherPub)
	if _, err := UnwrapEnvironmentKey(otherPriv, bad, packet); err == nil {
		t.Fatal("accepted another recipient")
	}
	bad = c
	bad.RecipientPublicKey = EncodeBase64(make([]byte, 32))
	if _, err := WrapEnvironmentKey(key, bad); err == nil {
		t.Fatal("accepted low-order recipient key")
	}
}

// RFC 9180 附录 A.2.1 的公开合成向量，验证选定 HPKE 套件的接收互操作。
func TestHPKERFC9180KnownAnswer(t *testing.T) {
	sk, err := ecdh.X25519().NewPrivateKey(mustHex(t, "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"))
	if err != nil {
		t.Fatal(err)
	}
	hsk, err := hpke.NewDHKEMPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	r, err := hpke.NewRecipient(mustHex(t, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"), hsk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), mustHex(t, "4f6465206f6e2061204772656369616e2055726e"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Open(mustHex(t, "436f756e742d30"), mustHex(t, "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustHex(t, "4265617574792069732074727574682c20747275746820626561757479")) {
		t.Fatal("RFC HPKE plaintext mismatch")
	}
}

func TestRecoveryPurposeAndGenerationSeparation(t *testing.T) {
	seed := fixtureBytes(32, 0)
	keys, err := DeriveRecoveryKeys(seed, "account-test", "1", "1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keys.SigningPrivate.Seed(), keys.ReceivingPrivate) {
		t.Fatal("recovery purposes share a key")
	}
	for _, args := range [][3]string{{"other-account", "1", "1"}, {"account-test", "2", "1"}, {"account-test", "1", "2"}} {
		other, err := DeriveRecoveryKeys(seed, args[0], args[1], args[2])
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(keys.SigningPublic, other.SigningPublic) || bytes.Equal(keys.ReceivingPublic, other.ReceivingPublic) {
			t.Fatal("recovery context not separated")
		}
	}
	code, err := EncodeRecoveryCode(seed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRecoveryCode(code[:13] + "-" + code[13:])
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatal("recovery code round trip")
	}
	for _, invalid := range []string{strings.ToLower(code), code[:51], code + "A", code[:51] + "B"} {
		if _, err := DecodeRecoveryCode(invalid); err == nil {
			t.Fatal("accepted malformed recovery code")
		}
	}
	c := EnvelopeContext{"account-test", "1", "environment-test", "1", "recovery", "recovery", "1", EncodeBase64(keys.ReceivingPublic)}
	key := fixtureBytes(32, 90)
	packet, err := WrapEnvironmentKey(key, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err = UnwrapEnvironmentKey(keys.ReceivingPrivate, c, packet)
	if err != nil || !bytes.Equal(key, got) {
		t.Fatal("recovery envelope round trip")
	}
	if _, err := DeriveRecoveryKeys(make([]byte, 31), "account-test", "1", "1"); err == nil {
		t.Fatal("accepted truncated seed")
	}
}

type signatureVectors struct {
	Description                string         `json:"description"`
	SigningSeedHex             string         `json:"syntheticSigningSeedHex"`
	SigningPublicKey           string         `json:"signingPublicKey"`
	Mutation                   SignedMutation `json:"mutation"`
	MutationSigningHex         string         `json:"mutationSigningHex"`
	Grant                      SignedGrant    `json:"grant"`
	GrantSigningHex            string         `json:"grantSigningHex"`
	ValueKeyHex                string         `json:"syntheticValueKeyHex"`
	ValuePlaintext             string         `json:"syntheticValuePlaintext"`
	RecoverySeedHex            string         `json:"syntheticRecoverySeedHex"`
	RecoverySigningPublicKey   string         `json:"recoverySigningPublicKey"`
	RecoveryReceivingPublicKey string         `json:"recoveryReceivingPublicKey"`
}

func readVectors(t *testing.T) signatureVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/signatures-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v signatureVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCrossLanguageStaticVectors(t *testing.T) {
	v := readVectors(t)
	pub, err := DecodeBase64(v.SigningPublicKey, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		bytes func() ([]byte, error)
		hex   string
	}{{v.Mutation.Mutation.SigningBytes, v.MutationSigningHex}, {v.Grant.Grant.SigningBytes, v.GrantSigningHex}} {
		b, err := item.bytes()
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(b) != item.hex {
			t.Fatal("cross-language canonical bytes drift")
		}
	}
	if err := VerifyMutation(v.Mutation, pub); err != nil {
		t.Fatal(err)
	}
	if err := VerifyGrant(v.Grant, pub); err != nil {
		t.Fatal(err)
	}
	sk := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeedHex))
	signed, err := SignMutation(v.Mutation.Mutation, sk)
	if err != nil || signed.Signature != v.Mutation.Signature {
		t.Fatal("mutation signature vector mismatch")
	}
	sg, err := SignGrant(v.Grant.Grant, sk)
	if err != nil || sg.Signature != v.Grant.Signature {
		t.Fatal("grant signature vector mismatch")
	}
	packet, err := DecodeBase64(v.Mutation.Payload, 40, MaxValueBytes+40)
	if err != nil {
		t.Fatal(err)
	}
	c := ValueContext{v.Mutation.AccountID, v.Mutation.AccountGeneration, v.Mutation.EnvironmentID, v.Mutation.KeyVersion, v.Mutation.Name}
	got, err := DecryptValue(mustHex(t, v.ValueKeyHex), c, packet)
	if err != nil || string(got) != v.ValuePlaintext {
		t.Fatal("XChaCha static vector mismatch")
	}
	keys, err := DeriveRecoveryKeys(mustHex(t, v.RecoverySeedHex), "account-test", "1", "1")
	if err != nil {
		t.Fatal(err)
	}
	if EncodeBase64(keys.SigningPublic) != v.RecoverySigningPublicKey || EncodeBase64(keys.ReceivingPublic) != v.RecoveryReceivingPublicKey {
		t.Fatal("recovery derivation vector mismatch")
	}
}

func TestSignatureBindsEveryMutationAndGrantField(t *testing.T) {
	v := readVectors(t)
	pub, err := DecodeBase64(v.SigningPublicKey, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < reflect.TypeFor[Mutation]().NumField(); i++ {
		bad := v.Mutation
		f := reflect.ValueOf(&bad.Mutation).Elem().Field(i)
		f.SetString(f.String() + "x")
		if err := VerifyMutation(bad, pub); err == nil {
			t.Fatalf("unbound mutation field %d", i)
		}
	}
	for i := 0; i < reflect.TypeFor[Grant]().NumField(); i++ {
		bad := v.Grant
		f := reflect.ValueOf(&bad.Grant).Elem().Field(i)
		f.SetString(f.String() + "x")
		if err := VerifyGrant(bad, pub); err == nil {
			t.Fatalf("unbound grant field %d", i)
		}
	}
	other := ed25519.NewKeyFromSeed(fixtureBytes(32, 50)).Public().(ed25519.PublicKey)
	if VerifyMutation(v.Mutation, other) == nil || VerifyGrant(v.Grant, other) == nil {
		t.Fatal("accepted untrusted signing key")
	}
	b, _ := v.Grant.Grant.SigningBytes()
	sig, _ := DecodeBase64(v.Mutation.Signature, 64, 64)
	if ed25519.Verify(pub, b, sig) {
		t.Fatal("signature domains overlap")
	}
}

func TestWireRejectsAmbiguousEncodings(t *testing.T) {
	v := readVectors(t)
	for _, generation := range []string{"01", "0", "+1", "-1", "1.0", "18446744073709551616"} {
		m := v.Mutation.Mutation
		m.AccountGeneration = generation
		if _, err := m.SigningBytes(); err == nil {
			t.Fatal("accepted generation", generation)
		}
	}
	for _, id := range []string{"", "<script>", "a\"b", "中文", "a b", strings.Repeat("a", 129)} {
		m := v.Mutation.Mutation
		m.AccountID = id
		if _, err := m.SigningBytes(); err == nil {
			t.Fatal("accepted ID", id)
		}
	}
	for _, payload := range []string{v.Mutation.Payload + "=", "+abc", "AA\nAA"} {
		m := v.Mutation.Mutation
		m.Payload = payload
		if _, err := m.SigningBytes(); err == nil {
			t.Fatal("accepted noncanonical payload")
		}
	}
	m := v.Mutation.Mutation
	m.Operation = "delete"
	m.Payload = ""
	if _, err := m.SigningBytes(); err != nil {
		t.Fatal(err)
	}
	m.Payload = v.Mutation.Payload
	if _, err := m.SigningBytes(); err == nil {
		t.Fatal("delete accepted ciphertext")
	}
	g := v.Grant.Grant
	g.Role = "none"
	g.Envelope = ""
	if _, err := g.SigningBytes(); err != nil {
		t.Fatal(err)
	}
	g.Envelope = v.Grant.Envelope
	if _, err := g.SigningBytes(); err == nil {
		t.Fatal("revoke accepted envelope")
	}
	if _, err := DecodeBase64("AB", 1, 1); err == nil {
		t.Fatal("accepted nonzero trailing bits")
	}
}
