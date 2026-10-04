package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

const maxPendingPairingsJSON = 32768

type PendingPairingRequest struct {
	IdempotencyKey    string `json:"idempotencyKey"`
	InitiatorDeviceID string `json:"initiatorDeviceId"`
	State             string `json:"state"`
	ExpiresAt         string `json:"expiresAt"`
}

// 只是短期提示快照，不证明申请设备身份或可批准权限。
type PendingPairingRequests struct {
	AccountGeneration  string                  `json:"accountGeneration"`
	CertificateVersion string                  `json:"certificateVersion"`
	Capabilities       []string                `json:"capabilities"`
	Requests           []PendingPairingRequest `json:"requests"`
}

func exactPendingPairingFields(raw []byte, names ...string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(names) {
		return cryptox.ErrInvalidWire
	}
	for _, name := range names {
		v, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return cryptox.ErrInvalidWire
		}
	}
	return nil
}
func (p *PendingPairingRequests) UnmarshalJSON(raw []byte) error {
	if cryptox.ValidateStrictJSON(raw, maxPendingPairingsJSON) != nil || exactPendingPairingFields(raw, "accountGeneration", "certificateVersion", "capabilities", "requests") != nil {
		return cryptox.ErrInvalidWire
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return cryptox.ErrInvalidWire
	}
	var rows []json.RawMessage
	if json.Unmarshal(fields["requests"], &rows) != nil || rows == nil || len(rows) > 64 {
		return cryptox.ErrInvalidWire
	}
	for _, row := range rows {
		if exactPendingPairingFields(row, "idempotencyKey", "initiatorDeviceId", "state", "expiresAt") != nil {
			return cryptox.ErrInvalidWire
		}
	}
	type plain PendingPairingRequests
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var out plain
	if dec.Decode(&out) != nil || dec.Decode(new(any)) != io.EOF {
		return cryptox.ErrInvalidWire
	}
	*p = PendingPairingRequests(out)
	return nil
}
func (c *Client) pendingPairingPermission(version string) error {
	capability := ""
	switch version {
	case "3":
		capability = cryptox.EnvironmentOriginCapability
	case "4":
		capability = cryptox.RecoveryAuthorityCapability
	default:
		return cryptox.ErrInvalidWire
	}
	if c == nil || c.config.Engine == nil || c.config.Token == "" {
		return ErrWritePermission
	}
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.evidenceRoot == nil || v.issuerOriginProof == nil || c.controlCapability() != capability {
		return ErrWritePermission
	}
	s := c.config.Engine.State()
	if s.AccountClosed || s.Paused || s.SessionEpoch != c.epoch || s.Cloud.AccountID != c.config.AccountID || s.Cloud.AccountGeneration != c.config.AccountGeneration {
		return ErrWritePermission
	}
	now := c.config.Now()
	for _, env := range s.Cloud.Environments {
		if env.Role == localstate.Admin && (env.ExpiresAt == nil || env.ExpiresAt.After(now)) {
			return nil
		}
	}
	return ErrWritePermission
}
func validatePendingPairingsSnapshot(out PendingPairingRequests, generation, version string, now int64) (PendingPairingRequests, error) {
	expected := cryptox.EnvironmentOriginCapability
	if version == "4" {
		expected = cryptox.RecoveryAuthorityCapability
	} else if version != "3" {
		return PendingPairingRequests{}, cryptox.ErrInvalidWire
	}
	if out.AccountGeneration != generation || out.CertificateVersion != version || len(out.Capabilities) != 1 || out.Capabilities[0] != expected || out.Requests == nil || len(out.Requests) > 64 || now <= 0 {
		return PendingPairingRequests{}, cryptox.ErrInvalidWire
	}
	seen := map[string]bool{}
	active := make([]PendingPairingRequest, 0, len(out.Requests))
	for _, row := range out.Requests {
		expiry, e := strconv.ParseInt(row.ExpiresAt, 10, 64)
		if !enrollmentID.MatchString(row.IdempotencyKey) || !enrollmentID.MatchString(row.InitiatorDeviceID) || seen[row.IdempotencyKey] || row.State != "pending" && row.State != "approved" || e != nil || expiry <= 0 || strconv.FormatInt(expiry, 10) != row.ExpiresAt || expiry-now > 125 {
			return PendingPairingRequests{}, cryptox.ErrInvalidWire
		}
		seen[row.IdempotencyKey] = true
		if expiry > now {
			active = append(active, row)
		}
	}
	out.Requests = active
	out.Capabilities = append([]string(nil), out.Capabilities...)
	return out, nil
}
func (c *Client) pendingPairingRequests(ctx context.Context, version string) (PendingPairingRequests, error) {
	if ctx == nil || ctx.Err() != nil {
		return PendingPairingRequests{}, cryptox.ErrInvalidWire
	}
	if e := c.pendingPairingPermission(version); e != nil {
		return PendingPairingRequests{}, e
	}
	var out PendingPairingRequests
	if e := c.request(ctx, "GET", c.endpointFor("/pairing-requests-v"+version), nil, &out); e != nil {
		return PendingPairingRequests{}, e
	}
	if e := ctx.Err(); e != nil {
		return PendingPairingRequests{}, e
	}
	if e := c.pendingPairingPermission(version); e != nil {
		return PendingPairingRequests{}, e
	}
	return validatePendingPairingsSnapshot(out, strconv.FormatUint(c.config.AccountGeneration, 10), version, c.config.Now().Unix())
}
func (c *Client) PendingPairingRequestsV3(ctx context.Context) (PendingPairingRequests, error) {
	return c.pendingPairingRequests(ctx, "3")
}
func (c *Client) PendingPairingRequestsV4(ctx context.Context) (PendingPairingRequests, error) {
	return c.pendingPairingRequests(ctx, "4")
}
