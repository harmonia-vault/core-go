package syncclient

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/harmonia-vault/core-go/cryptox"
)

// V4是明确的P4来源路由；原change/origin签名域、随机封套与原包hash均不变。
func (c *Client) PrepareEnvironmentChangeV4(ctx context.Context, signed cryptox.SignedEnvironmentChange, key ed25519.PrivateKey) (cryptox.EnvironmentChangeV2, error) {
	if !c.dagControls() {
		return cryptox.EnvironmentChangeV2{}, ErrWritePermission
	}
	return c.prepareEnvironmentChangeOrigin(ctx, signed, key)
}
func (c *Client) EnvironmentStatusV4(ctx context.Context, id string) (EnvironmentChangeStatusV2, error) {
	if !c.dagControls() {
		return EnvironmentChangeStatusV2{}, ErrWritePermission
	}
	return c.environmentOriginStatus(ctx, id, "/environment-changes-v4/")
}
func (c *Client) SubmitEnvironmentChangeV4(ctx context.Context, packet cryptox.EnvironmentChangeV2) (SubmitResult, error) {
	if !c.dagControls() {
		return SubmitResult{}, ErrWritePermission
	}
	if e := c.validateEnvironmentChangeV2(packet); e != nil {
		return SubmitResult{}, e
	}
	var accepted Acceptance
	if e := c.request(ctx, "POST", c.endpointFor("/environment-changes-v4"), packet, &accepted); e != nil {
		return SubmitResult{}, e
	}
	return c.ConfirmEnvironmentChangeV4(ctx, packet, accepted)
}
func (c *Client) ConfirmEnvironmentChangeV4(ctx context.Context, packet cryptox.EnvironmentChangeV2, accepted Acceptance) (SubmitResult, error) {
	out := SubmitResult{Accepted: accepted}
	if !c.dagControls() {
		return out, ErrWritePermission
	}
	if e := c.validateEnvironmentChangeV2(packet); e != nil {
		return out, e
	}
	if accepted.Sequence == 0 || accepted.Sequence > 9007199254740991 {
		return out, cryptox.ErrInvalidWire
	}
	status, e := c.EnvironmentStatusV4(ctx, packet.Change.IdempotencyKey)
	if e != nil {
		return out, errors.Join(ErrAcceptedNotApplied, e)
	}
	hash, e := cryptox.EnvironmentSubmissionHash(packet)
	if e != nil {
		return out, e
	}
	if status.State != "complete" || status.Sequence != accepted.Sequence || status.ContentHash != hash {
		return out, ErrAcceptedNotApplied
	}
	result, e := c.ConfirmEnvironmentChange(ctx, cryptox.SignedEnvironmentChange{Change: packet.Change, Signature: packet.Signature}, accepted)
	if e != nil {
		return out, errors.Join(ErrAcceptedNotApplied, e)
	}
	evidence, e := c.CurrentIssuerDAGEvidence()
	if e != nil {
		return out, errors.Join(ErrAcceptedNotApplied, e)
	}
	view, e := dagView(&evidence)
	if e != nil {
		return out, e
	}
	wanted, e := cryptox.EnvironmentOriginHash(packet.Origin)
	if e != nil {
		return out, e
	}
	for _, origin := range view.Origins {
		found, e := cryptox.EnvironmentOriginHash(origin)
		if e != nil {
			return out, e
		}
		if found == wanted {
			return result, nil
		}
	}
	return out, ErrAcceptedNotApplied
}
