package syncclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"regexp"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

type EnvironmentChangeStatusV2 struct {
	State       string `json:"state"`
	Sequence    uint64 `json:"sequence,omitempty"`
	ContentHash string `json:"contentHash,omitempty"`
}
type EnvironmentControlView struct {
	Sequence          uint64                     `json:"sequence"`
	Grants            []cryptox.SignedGrantWire  `json:"grants"`
	IssuerDAGEvidence *cryptox.IssuerRecoveryDAG `json:"issuerEvidence"`
}

func (c *Client) EnvironmentControl(ctx context.Context, environment string) (EnvironmentControlView, error) {
	var out EnvironmentControlView
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.evidenceRoot == nil || !enrollmentID.MatchString(environment) {
		return out, ErrWritePermission
	}
	if c.config.Engine.State().Paused {
		return out, ErrPaused
	}
	if e := c.requestDAGEnvironmentControl(ctx, environment, &out); e != nil {
		return out, e
	}
	if _, e := c.VerifyEnvironmentControl(out, environment); e != nil {
		return EnvironmentControlView{}, e
	}
	return out, nil
}

// VerifyEnvironmentControl 可重验受保护历史 journal；历史来源不替代发送前在线检查。
func (c *Client) VerifyEnvironmentControl(out EnvironmentControlView, environment string, historical ...bool) (VerifiedControlEvidence, error) {
	if len(historical) > 1 {
		return nil, cryptox.ErrInvalidWire
	}
	past := len(historical) == 1 && historical[0]
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.evidenceRoot == nil || !enrollmentID.MatchString(environment) {
		return nil, ErrWritePermission
	}
	old := c.config.Engine.State().Cloud
	if (!past && (out.Sequence < old.Sequence || out.Sequence < old.AuthorizationSequence)) || out.Sequence > 9007199254740991 {
		return nil, cryptox.ErrInvalidWire
	}
	p, e := c.verifyEnvironmentControlEvidence(out, past)
	if e != nil {
		return nil, e
	}
	var own *cryptox.SignedGrantWire
	seen := map[string]bool{}
	kv := ""
	for i, g := range out.Grants {
		gg := g.Grant
		expiry, er := strconv.ParseInt(gg.ExpiresAt, 10, 64)
		if er != nil || (!past && expiry != 0 && expiry <= c.config.Now().Unix()) || gg.Role == "none" || gg.EnvironmentID != environment || seen[gg.SubjectDeviceID] || gg.AccountID != c.config.AccountID || gg.AccountGeneration != strconv.FormatUint(c.config.AccountGeneration, 10) {
			return nil, cryptox.ErrInvalidWire
		}
		seen[gg.SubjectDeviceID] = true
		if kv != "" && kv != gg.KeyVersion {
			return nil, cryptox.ErrInvalidWire
		}
		kv = gg.KeyVersion
		if e = p.VerifyHistoricalGrant(g); e != nil {
			return nil, e
		}
		if gg.SubjectDeviceID == c.config.DeviceID {
			own = &out.Grants[i]
		}
	}
	if own == nil || own.Grant.Role != "admin" || p.VerifyTarget(*own, c.config.DeviceID, cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey), v.receivingPublicKey) != nil {
		return nil, ErrWritePermission
	}
	if !past {
		cached, exists := old.Environments[environment]
		if !exists || cached.Role != localstate.Admin || own.Grant.KeyVersion != strconv.FormatUint(cached.KeyVersion, 10) || own.Grant.GrantGeneration != strconv.FormatUint(cached.GrantGeneration, 10) {
			return nil, ErrFullPullRequired
		}
	}
	return p, nil
}
func (c *Client) prepareEnvironmentChangeOrigin(ctx context.Context, signed cryptox.SignedEnvironmentChange, key ed25519.PrivateKey) (cryptox.EnvironmentChangeV2, error) {
	if e := c.validateEnvironmentChange(signed); e != nil {
		return cryptox.EnvironmentChangeV2{}, e
	}
	control, e := c.EnvironmentControl(ctx, signed.Change.AuthorityEnvironmentID)
	if e != nil {
		return cryptox.EnvironmentChangeV2{}, e
	}
	if signed.Change.ExpectedSequence != strconv.FormatUint(control.Sequence, 10) {
		return cryptox.EnvironmentChangeV2{}, errors.New("environment authority checkpoint changed before signing origin")
	}
	var actor cryptox.SignedGrantWire
	for _, g := range control.Grants {
		if g.Grant.SubjectDeviceID == c.config.DeviceID {
			actor = g
		}
	}
	before := []cryptox.SignedGrantWire{}
	if signed.Change.Operation == "rotate" {
		before = control.Grants
	}
	return cryptox.NewEnvironmentChangeV2(signed, actor, before, key)
}
func (c *Client) environmentOriginStatus(ctx context.Context, id, route string) (EnvironmentChangeStatusV2, error) {
	var s EnvironmentChangeStatusV2
	if !enrollmentID.MatchString(id) {
		return s, cryptox.ErrInvalidWire
	}
	if e := c.request(ctx, "GET", c.endpointFor(route+id), nil, &s); e != nil {
		return s, e
	}
	if s.State == "unknown" {
		if s.Sequence != 0 || s.ContentHash != "" {
			return s, cryptox.ErrInvalidWire
		}
	} else if s.State != "complete" || s.Sequence == 0 || s.Sequence > 9007199254740991 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(s.ContentHash) {
		return s, cryptox.ErrInvalidWire
	}
	return s, nil
}
func (c *Client) validateEnvironmentChangeV2(s cryptox.EnvironmentChangeV2) error {
	if e := c.validateEnvironmentChange(cryptox.SignedEnvironmentChange{Change: s.Change, Signature: s.Signature}); e != nil {
		return e
	}
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.evidenceRoot == nil {
		return ErrWritePermission
	}
	if e := cryptox.VerifyEnvironmentOrigin(s.Origin, v.trust.DeviceSigningPublicKey); e != nil {
		return e
	}
	hash, e := cryptox.EnvironmentChangeReferenceHash(cryptox.SignedEnvironmentChange{Change: s.Change, Signature: s.Signature})
	if e != nil {
		return e
	}
	o, ch := s.Origin.Origin, s.Change
	if o.ChangeHash != hash || o.AccountID != ch.AccountID || o.AccountGeneration != ch.AccountGeneration || o.ActorDeviceID != ch.DeviceID || o.EnvironmentID != ch.EnvironmentID || o.Operation != ch.Operation || o.AuthorityEnvironmentID != ch.AuthorityEnvironmentID || o.AuthorityKeyVersion != ch.AuthorityKeyVersion || o.AuthorityGrantGeneration != ch.AuthorityGrantGeneration || o.PreviousKeyVersion != ch.PreviousKeyVersion || o.KeyVersion != ch.KeyVersion || o.ExpectedSequence != ch.ExpectedSequence || o.IdempotencyKey != ch.IdempotencyKey {
		return cryptox.ErrInvalidWire
	}
	rights, e := cryptox.EnvironmentRights(ch.Grants)
	if e != nil {
		return e
	}
	if !sameJSON(rights, o.After) {
		return cryptox.ErrInvalidWire
	}
	return nil
}
