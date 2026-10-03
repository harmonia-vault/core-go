// Package appsecurity provides native-only App PIN local protection. It cannot
// establish account/device trust or authenticate an Android system CryptoObject.
package appsecurity

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const recordProfile = "harmonia/local-pin/v1"
const maxRecordBytes = 8192

var (
	ErrConfiguration = errors.New("local PIN configuration rejected")
	ErrRecord        = errors.New("local PIN record rejected")
	ErrPIN           = errors.New("local PIN authentication rejected")
	ErrPersistence   = errors.New("local PIN durable state unavailable")
	ErrState         = errors.New("local PIN attempt state rejected")
	ErrLocked        = errors.New("local PIN attempts temporarily locked")
	ErrBusy          = errors.New("local PIN operation already active")
	ErrClosed        = errors.New("local PIN provider closed")
	ErrLease         = errors.New("local PIN operation lease rejected")
	ErrNativeOnly    = errors.New("local PIN lease cannot be serialized")
)

// Binding must come from the fixed native provider, never a Dart authorization
// flag. Generation and epoch are independent CSPRNG 16-byte lowercase hex IDs.
type Binding struct {
	Package            string `json:"package"`
	Namespace          string `json:"namespace"`
	Slot               string `json:"slot"`
	Endpoint           string `json:"endpoint"`
	Mode               string `json:"mode"`
	AuthGeneration     string `json:"authGeneration"`
	KeyEpoch           string `json:"keyEpoch"`
	SigningPublicKey   string `json:"signingPublicKey"`
	ReceivingPublicKey string `json:"receivingPublicKey"`
}
type KDFParameters struct {
	Algorithm   string `json:"algorithm"`
	Version     uint32 `json:"version"`
	MemoryKiB   uint32 `json:"memoryKiB"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	KeyBytes    uint32 `json:"keyBytes"`
}

func fixedKDF() KDFParameters { return KDFParameters{"argon2id", 19, 65536, 3, 1, 32} }

// Record contains ciphertext and public binding only; no fast PIN verifier.
type Record struct {
	Profile         string        `json:"profile"`
	Version         uint32        `json:"version"`
	Binding         Binding       `json:"binding"`
	KDF             KDFParameters `json:"kdf"`
	Salt            string        `json:"salt"`
	KeyNonce        string        `json:"keyNonce"`
	WrappedVaultKey string        `json:"wrappedVaultKey"`
	MaterialNonce   string        `json:"materialNonce"`
	SealedMaterial  string        `json:"sealedMaterial"`
}

var packageName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)
var slotName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func lowerHex(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}
func raw(s string, n int) ([]byte, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(b) != n || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, ErrRecord
	}
	return b, nil
}
func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func (b Binding) valid() bool {
	if len(b.Package) > 256 || !packageName.MatchString(b.Package) || len(b.Namespace) == 0 || len(b.Namespace) > 512 || !utf8.ValidString(b.Namespace) || strings.ContainsAny(b.Namespace, "\r\n") || !slotName.MatchString(b.Slot) || b.Mode != "pin" || !lowerHex(b.AuthGeneration, 16) || !lowerHex(b.KeyEpoch, 16) || b.AuthGeneration == b.KeyEpoch || len(b.Endpoint) > 2048 {
		return false
	}
	u, e := url.Parse(b.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.String() != b.Endpoint || strings.ToLower(u.Host) != u.Host || strings.HasSuffix(b.Endpoint, "/") || strings.ContainsAny(b.Endpoint, "\\#") {
		return false
	}
	_, e = raw(b.SigningPublicKey, 32)
	if e != nil {
		return false
	}
	_, e = raw(b.ReceivingPublicKey, 32)
	return e == nil
}
func (r Record) Validate(expected Binding) error {
	if !expected.valid() || r.Binding != expected || r.Profile != recordProfile || r.Version != 1 || r.KDF != fixedKDF() {
		return ErrRecord
	}
	for _, f := range []struct {
		s string
		n int
	}{{r.Salt, 32}, {r.KeyNonce, 12}, {r.WrappedVaultKey, 48}, {r.MaterialNonce, 12}, {r.SealedMaterial, 88}} {
		if _, e := raw(f.s, f.n); e != nil {
			return ErrRecord
		}
	}
	return nil
}
func (r Record) aad(purpose string) []byte {
	b, k := r.Binding, r.KDF
	v := []string{recordProfile, purpose, strconv.FormatUint(uint64(r.Version), 10), b.Package, b.Namespace, b.Slot, b.Endpoint, b.Mode, b.AuthGeneration, b.KeyEpoch, b.SigningPublicKey, b.ReceivingPublicKey, k.Algorithm, strconv.FormatUint(uint64(k.Version), 10), strconv.FormatUint(uint64(k.MemoryKiB), 10), strconv.FormatUint(uint64(k.Iterations), 10), strconv.FormatUint(uint64(k.Parallelism), 10), strconv.FormatUint(uint64(k.KeyBytes), 10), r.Salt}
	data, _ := json.Marshal(v)
	return data
}
func (r Record) Encode() ([]byte, error) {
	if r.Validate(r.Binding) != nil {
		return nil, ErrRecord
	}
	return json.Marshal(r)
}

// DecodeRecord rejects unknown/duplicate fields and untrusted KDF costs before
// doing any KDF work. expected is native's immutable protection scope.
func DecodeRecord(data []byte, expected Binding) (Record, error) {
	if len(data) == 0 || len(data) > maxRecordBytes {
		return Record{}, ErrRecord
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if duplicateFree(d, 0) != nil {
		return Record{}, ErrRecord
	}
	if _, e := d.Token(); e != io.EOF {
		return Record{}, ErrRecord
	}
	var r Record
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || r.Validate(expected) != nil {
		return Record{}, ErrRecord
	}
	return r, nil
}
func duplicateFree(d *json.Decoder, depth int) error {
	if depth > 8 {
		return ErrRecord
	}
	t, e := d.Token()
	if e != nil {
		return ErrRecord
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for d.More() {
			t, e = d.Token()
			s, ok := t.(string)
			if e != nil || !ok || seen[s] || len(seen) >= 64 {
				return ErrRecord
			}
			seen[s] = true
			if duplicateFree(d, depth+1) != nil {
				return ErrRecord
			}
		}
	} else if delim == '[' {
		return ErrRecord
	} else {
		return ErrRecord
	}
	_, e = d.Token()
	return e
}
