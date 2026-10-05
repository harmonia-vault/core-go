package mobileworkflow

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
)

var ErrApprovalPending = errors.New("original approval result pending; only explicit original query/retry or logout allowed")
var ErrApprovalEvidence = errors.New("initial root environment authority evidence required")

// ApprovalInput 只能由系统认证后的原生层构造，Selections 为用户明确选择。
// ShortCode 不允许 JSON 序列化；只交给本机成熟 SPAKE2，不发送网络或存储。
type ApprovalInput struct {
	PairingID  string
	ShortCode  []byte `json:"-"`
	Selections []ApprovalSelection
}
type ApprovalSelection struct {
	EnvironmentID string `json:"environmentId"`
	Role          string `json:"role"`
	ExpiresAt     string `json:"expiresAt"`
}
type ApprovalResult struct {
	State     string `json:"state"`
	PairingID string `json:"pairingId"`
	DeviceID  string `json:"deviceId,omitempty"`
	Sequence  uint64 `json:"sequence,omitempty"`
}
type ApprovalInfo struct {
	State      string              `json:"state"`
	PairingID  string              `json:"pairingId,omitempty"`
	DeviceID   string              `json:"deviceId,omitempty"`
	Selections []ApprovalSelection `json:"selections,omitempty"`
	ExpiresAt  string              `json:"expiresAt,omitempty"`
	Sequence   uint64              `json:"sequence,omitempty"`
}

func choicesHash(id string, choices []ApprovalSelection) (string, error) {
	if !identifier.MatchString(id) || len(choices) < 1 || len(choices) > 16 {
		return "", errors.New("explicit approval selections required")
	}
	ordered := append([]ApprovalSelection(nil), choices...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].EnvironmentID < ordered[j].EnvironmentID })
	rows := make([][]string, 0, len(ordered))
	for i, s := range ordered {
		n, err := strconv.ParseUint(s.ExpiresAt, 10, 64)
		if !identifier.MatchString(s.EnvironmentID) || i > 0 && ordered[i-1].EnvironmentID == s.EnvironmentID || s.Role != "ro" && s.Role != "rw" && s.Role != "admin" || err != nil || strconv.FormatUint(n, 10) != s.ExpiresAt || n > 253402300799 {
			return "", errors.New("approval role/expiry/environment invalid")
		}
		rows = append(rows, []string{s.EnvironmentID, s.Role, s.ExpiresAt})
	}
	b, _ := json.Marshal([]any{"harmonia/local-approval-choices/v1", id, rows})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func (w *Workflow) validateInitialAuthorities() error {
	if len(w.state.InitialAuthorities) == 0 {
		return nil
	}
	if w.state.Root == nil || len(w.state.InitialAuthorities) > 16 {
		return ErrApprovalEvidence
	}
	seen := map[string]bool{}
	for _, s := range w.state.InitialAuthorities {
		g := s.Grant
		if g.AccountID != w.state.AccountID || g.AccountGeneration != w.state.AccountGeneration || g.IssuerDeviceID != w.state.DeviceID || g.SubjectDeviceID != w.state.DeviceID || g.SubjectSigningPublicKey != w.state.SigningPublicKey || g.SubjectReceivingPublicKey != w.state.ReceivingPublicKey || g.KeyVersion != "1" || g.GrantGeneration != "1" || g.Role != "admin" || g.ExpiresAt != "0" || seen[g.EnvironmentID] || cryptox.VerifyGrant(s.SignedGrant(), w.signing.Public().(ed25519.PublicKey)) != nil {
			return ErrApprovalEvidence
		}
		seen[g.EnvironmentID] = true
	}
	return nil
}
func (w *Workflow) initialAuthority(env string) (cryptox.SignedGrantWire, error) {
	for _, g := range w.state.InitialAuthorities {
		if g.Grant.EnvironmentID == env {
			return g, nil
		}
	}
	return cryptox.SignedGrantWire{}, ErrApprovalEvidence
}
func sameSignedGrant(a, b cryptox.SignedGrantWire) bool {
	x, e := cryptox.IssuerAuthorityHash(a)
	y, f := cryptox.IssuerAuthorityHash(b)
	return e == nil && f == nil && x == y
}
