package appsecurity

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/argon2"
)

func validPIN(pin []byte) bool {
	if len(pin) < 6 || len(pin) > 32 {
		return false
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func materialMatches(material []byte, b Binding) bool {
	if len(material) != 72 || !bytes.Equal(material[:8], []byte("HARMKEY1")) {
		return false
	}
	key := ed25519.NewKeyFromSeed(material[8:40])
	defer clear(key)
	x, e := ecdh.X25519().NewPrivateKey(material[40:])
	return e == nil && enc(key.Public().(ed25519.PublicKey)) == b.SigningPublicKey && enc(x.PublicKey().Bytes()) == b.ReceivingPublicKey
}
func gcm(key []byte) (cipher.AEAD, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrRecord
	}
	return cipher.NewGCM(block)
}
func random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		clear(b)
		return nil, ErrConfiguration
	}
	return b, nil
}

// CreateRecord is provisioning only. Native must independently prove objective
// OS-auth absence, full setup intent, fresh slot, and durable atomic publication.
// It does not activate a trusted device or create an operation lease.
func CreateRecord(pin, confirmation []byte, b Binding, material []byte) (Record, AttemptState, error) {
	if !validPIN(pin) || !validPIN(confirmation) || !bytes.Equal(pin, confirmation) || !b.valid() || !materialMatches(material, b) {
		return Record{}, AttemptState{}, ErrConfiguration
	}
	owned := bytes.Clone(pin)
	defer clear(owned)
	salt, e := random(32)
	if e != nil {
		return Record{}, AttemptState{}, e
	}
	vault, e := random(32)
	if e != nil {
		return Record{}, AttemptState{}, e
	}
	defer clear(vault)
	kn, e := random(12)
	if e != nil {
		return Record{}, AttemptState{}, e
	}
	mn, e := random(12)
	if e != nil {
		return Record{}, AttemptState{}, e
	}
	r := Record{Profile: recordProfile, Version: 1, Binding: b, KDF: fixedKDF(), Salt: enc(salt), KeyNonce: enc(kn), MaterialNonce: enc(mn)}
	kek := argon2.IDKey(owned, salt, 3, 65536, 1, 32)
	defer clear(kek)
	a, e := gcm(kek)
	if e != nil {
		return Record{}, AttemptState{}, e
	}
	r.WrappedVaultKey = enc(a.Seal(nil, kn, vault, r.aad("vault-key")))
	a, e = gcm(vault)
	if e != nil {
		return Record{}, AttemptState{}, e
	}
	r.SealedMaterial = enc(a.Seal(nil, mn, material, r.aad("device-material")))
	fingerprint := recordHash(r)
	return r, AttemptState{Revision: 1, RecordHash: fingerprint}, nil
}
func recordHash(r Record) string {
	data, _ := r.Encode()
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
func openRecord(pin []byte, r Record) ([]byte, error) {
	owned := bytes.Clone(pin)
	defer clear(owned)
	salt, e := raw(r.Salt, 32)
	if e != nil {
		return nil, ErrRecord
	}
	kek := argon2.IDKey(owned, salt, 3, 65536, 1, 32)
	defer clear(kek)
	a, e := gcm(kek)
	if e != nil {
		return nil, ErrRecord
	}
	nonce, _ := raw(r.KeyNonce, 12)
	packet, _ := raw(r.WrappedVaultKey, 48)
	vault, e := a.Open(nil, nonce, packet, r.aad("vault-key"))
	if e != nil {
		return nil, ErrPIN
	}
	defer clear(vault)
	a, e = gcm(vault)
	if e != nil {
		return nil, ErrPIN
	}
	nonce, _ = raw(r.MaterialNonce, 12)
	packet, _ = raw(r.SealedMaterial, 88)
	material, e := a.Open(nil, nonce, packet, r.aad("device-material"))
	if e != nil {
		return nil, ErrPIN
	}
	if !materialMatches(material, r.Binding) {
		clear(material)
		return nil, ErrPIN
	}
	return material, nil
}
