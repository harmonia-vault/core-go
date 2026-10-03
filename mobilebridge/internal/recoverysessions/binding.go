package recoverysessions

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func bounded(v string, n int) bool {
	return v != "" && len(v) <= n && utf8.ValidString(v) && !strings.ContainsAny(v, "\x00\r\n\t")
}
func publicKey(v string) bool {
	b, e := base64.RawURLEncoding.Strict().DecodeString(v)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == v
}
func digest(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
}
func generation(v string) bool {
	n, e := strconv.ParseUint(v, 10, 64)
	return e == nil && n > 0 && strconv.FormatUint(n, 10) == v
}
func validScope(s Scope) bool {
	if !bounded(s.Namespace, 512) || !bounded(s.Slot, 128) || strings.ContainsAny(s.Slot, "/\\") || !bounded(s.Endpoint, 2048) || !publicKey(s.DeviceSigningPublicKey) || !publicKey(s.DeviceReceivingPublicKey) {
		return false
	}
	u, e := url.Parse(s.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.String() != s.Endpoint || strings.ContainsAny(s.Endpoint, "\\#") || strings.ToLower(u.Host) != u.Host || strings.HasSuffix(s.Endpoint, "/") {
		return false
	}
	pub, _ := base64.RawURLEncoding.Strict().DecodeString(s.DeviceSigningPublicKey)
	id := sha256.Sum256(pub)
	return s.DeviceID == hex.EncodeToString(id[:])
}
func validBinding(b Binding) bool {
	if !validScope(b.Scope) || !identifier.MatchString(b.AccountID) || !generation(b.AccountGeneration) || !generation(b.RecoveryGeneration) || !publicKey(b.RootSigningPublicKey) || !publicKey(b.RootReceivingPublicKey) || !publicKey(b.RecoverySigningPublicKey) || !publicKey(b.RecoveryReceivingPublicKey) || !digest(b.InitializationProposalHash) || !digest(b.SessionHash) || !digest(b.AuthorityHeadHash) || !digest(b.RootDeviceID) || b.ExpiresAt <= 0 {
		return false
	}
	if b.TransitionID == "" {
		return b.TransitionHash == ""
	}
	return len(b.TransitionID) <= 64 && identifier.MatchString(b.TransitionID) && digest(b.TransitionHash)
}
