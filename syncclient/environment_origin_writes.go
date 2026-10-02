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
	Sequence       uint64                    `json:"sequence"`
	Grants         []cryptox.SignedGrantWire `json:"grants"`
	IssuerEvidence cryptox.IssuerProofV2     `json:"issuerEvidence"`
}

func (c *Client) CurrentIssuerEvidence() (cryptox.IssuerProofV2, error) {
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.evidenceRoot == nil || c.config.Engine.State().SessionEpoch != c.epoch {
		return cryptox.IssuerProofV2{}, localstate.ErrLocalSession
	}
	p := cloneEvidence(*v.initialEvidence)
	stored := c.config.Engine.State().Cloud.IssuerEvidence
	if len(stored) > 0 {
		var e error
		p, e = decodeEvidence(stored)
		if e != nil {
			return p, e
		}
	}
	if _, e := cryptox.VerifyIssuerEvidenceV2(*v.evidenceRoot, p, v.genesisAuthorities...); e != nil {
		return p, e
	}
	return p, nil
}

// PrepareEnrollmentProofV3 只能使用已受保护根和本机当前 Admin 的精确来源。
// 高层须先在线刷新当前权限并收集明确用户选择；本方法不替用户批准设备。
func (c *Client) PrepareEnrollmentProofV3(environments []string) (cryptox.IssuerProofV2, cryptox.PinnedIssuerRoot, []cryptox.SignedGrantWire, error) {
	var empty cryptox.IssuerProofV2
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.evidenceRoot == nil || len(environments) == 0 || len(environments) > 16 {
		return empty, cryptox.PinnedIssuerRoot{}, nil, ErrWritePermission
	}
	state := c.config.Engine.State()
	if state.Paused {
		return empty, cryptox.PinnedIssuerRoot{}, nil, ErrPaused
	}
	p, e := c.CurrentIssuerEvidence()
	if e != nil {
		return empty, cryptox.PinnedIssuerRoot{}, nil, e
	}
	byhash := map[string]cryptox.SignedGrantWire{}
	for _, a := range p.Authorities {
		h, _ := cryptox.IssuerAuthorityHash(a.Grant)
		byhash[h] = a.Grant
	}
	ts := map[string]string{}
	for _, t := range p.Targets {
		ts[t.EnvironmentID] = t.AuthorityHash
	}
	seen := map[string]bool{}
	p.Targets = nil
	for _, env := range environments {
		if !enrollmentID.MatchString(env) || seen[env] {
			return empty, cryptox.PinnedIssuerRoot{}, nil, cryptox.ErrInvalidWire
		}
		seen[env] = true
		g, exists := byhash[ts[env]]
		local, lok := state.Cloud.Environments[env]
		expiry, _ := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
		if !exists || !lok || local.Role != localstate.Admin || g.Grant.Role != "admin" || g.Grant.SubjectDeviceID != c.config.DeviceID || g.Grant.SubjectSigningPublicKey != cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey) || g.Grant.SubjectReceivingPublicKey != v.receivingPublicKey || g.Grant.KeyVersion != strconv.FormatUint(local.KeyVersion, 10) || g.Grant.GrantGeneration != strconv.FormatUint(local.GrantGeneration, 10) || (expiry != 0 && expiry <= c.config.Now().Unix()) {
			return empty, cryptox.PinnedIssuerRoot{}, nil, ErrWritePermission
		}
		p.Targets = append(p.Targets, cryptox.IssuerTarget{EnvironmentID: env, AuthorityHash: ts[env]})
	}
	return normalizeEvidence(p), *v.evidenceRoot, append([]cryptox.SignedGrantWire(nil), v.genesisAuthorities...), nil
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
	u := c.endpointFor("/issuer-evidence")
	q := u.Query()
	q.Set("environmentId", environment)
	q.Set("capability", cryptox.EnvironmentOriginCapability)
	u.RawQuery = q.Encode()
	if e := c.request(ctx, "GET", u, nil, &out); e != nil {
		return out, e
	}
	old := c.config.Engine.State().Cloud
	if out.Sequence < old.Sequence || out.Sequence < old.AuthorizationSequence || out.Sequence > 9007199254740991 {
		return EnvironmentControlView{}, cryptox.ErrInvalidWire
	}
	p, e := cryptox.VerifyIssuerEvidenceV2(*v.evidenceRoot, out.IssuerEvidence, v.genesisAuthorities...)
	if e != nil {
		return EnvironmentControlView{}, e
	}
	var own *cryptox.SignedGrantWire
	seen := map[string]bool{}
	kv := ""
	for i, g := range out.Grants {
		gg := g.Grant
		expiry, er := strconv.ParseInt(gg.ExpiresAt, 10, 64)
		if er != nil || (expiry != 0 && expiry <= c.config.Now().Unix()) || gg.Role == "none" || gg.EnvironmentID != environment || seen[gg.SubjectDeviceID] || gg.AccountID != c.config.AccountID || gg.AccountGeneration != strconv.FormatUint(c.config.AccountGeneration, 10) {
			return EnvironmentControlView{}, cryptox.ErrInvalidWire
		}
		seen[gg.SubjectDeviceID] = true
		if kv != "" && kv != gg.KeyVersion {
			return EnvironmentControlView{}, cryptox.ErrInvalidWire
		}
		kv = gg.KeyVersion
		if e = p.VerifyHistoricalGrant(g); e != nil {
			return EnvironmentControlView{}, e
		}
		if gg.SubjectDeviceID == c.config.DeviceID {
			own = &out.Grants[i]
		}
	}
	if own == nil || own.Grant.Role != "admin" || p.VerifyTarget(*own, c.config.DeviceID, cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey), v.receivingPublicKey) != nil {
		return EnvironmentControlView{}, ErrWritePermission
	}
	return out, nil
}
func (c *Client) PrepareEnvironmentChangeV2(ctx context.Context, signed cryptox.SignedEnvironmentChange, key ed25519.PrivateKey) (cryptox.EnvironmentChangeV2, error) {
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
func (c *Client) EnvironmentStatusV2(ctx context.Context, id string) (EnvironmentChangeStatusV2, error) {
	var s EnvironmentChangeStatusV2
	if !enrollmentID.MatchString(id) {
		return s, cryptox.ErrInvalidWire
	}
	if e := c.request(ctx, "GET", c.endpointFor("/environment-changes-v2/"+id), nil, &s); e != nil {
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
func (c *Client) ConfirmEnvironmentChangeV2(ctx context.Context, s cryptox.EnvironmentChangeV2, accepted Acceptance) (SubmitResult, error) {
	result := SubmitResult{Accepted: accepted}
	if e := c.validateEnvironmentChangeV2(s); e != nil {
		return result, e
	}
	if accepted.Sequence == 0 || accepted.Sequence > 9007199254740991 {
		return result, cryptox.ErrInvalidWire
	}
	status, e := c.EnvironmentStatusV2(ctx, s.Change.IdempotencyKey)
	if e != nil {
		return result, errors.Join(ErrAcceptedNotApplied, e)
	}
	hash, e := cryptox.EnvironmentSubmissionHash(s)
	if e != nil {
		return result, e
	}
	if status.State != "complete" || status.Sequence != accepted.Sequence || status.ContentHash != hash {
		return result, ErrAcceptedNotApplied
	}
	result, e = c.ConfirmEnvironmentChange(ctx, cryptox.SignedEnvironmentChange{Change: s.Change, Signature: s.Signature}, accepted)
	if e != nil {
		return result, e
	}
	p, e := c.CurrentIssuerEvidence()
	if e != nil {
		return result, e
	}
	oh, _ := cryptox.EnvironmentOriginHash(s.Origin)
	found := false
	for _, o := range p.Origins {
		h, _ := cryptox.EnvironmentOriginHash(o)
		if h == oh {
			found = true
		}
	}
	if !found {
		return SubmitResult{Accepted: accepted}, ErrAcceptedNotApplied
	}
	return result, nil
}
func (c *Client) SubmitEnvironmentChangeV2(ctx context.Context, s cryptox.EnvironmentChangeV2) (SubmitResult, error) {
	if e := c.validateEnvironmentChangeV2(s); e != nil {
		return SubmitResult{}, e
	}
	var accepted Acceptance
	if e := c.request(ctx, "POST", c.endpointFor("/environment-changes-v2"), s, &accepted); e != nil {
		return SubmitResult{}, e
	}
	return c.ConfirmEnvironmentChangeV2(ctx, s, accepted)
}
