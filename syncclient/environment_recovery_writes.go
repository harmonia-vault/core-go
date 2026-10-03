package syncclient

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/harmonia-vault/core-go/cryptox"
)

// V3 路由表示明确的恢复来源能力。签名原语/原包/幂等摘要与 V2 相同，
// 但不能把第三版来源图降级成第二版；旧客户端仍使用独立旧路由。
func (c *Client) PrepareEnvironmentChangeV3(ctx context.Context, signed cryptox.SignedEnvironmentChange, key ed25519.PrivateKey) (cryptox.EnvironmentChangeV2, error) {
	if !c.recoveryControls() {
		return cryptox.EnvironmentChangeV2{}, ErrWritePermission
	}
	return c.prepareEnvironmentChangeOrigin(ctx, signed, key)
}
func (c *Client) EnvironmentStatusV3(ctx context.Context, id string) (EnvironmentChangeStatusV2, error) {
	if !c.recoveryControls() {
		return EnvironmentChangeStatusV2{}, ErrWritePermission
	}
	return c.environmentOriginStatus(ctx, id, "/environment-changes-v3/")
}
func (c *Client) SubmitEnvironmentChangeV3(ctx context.Context, packet cryptox.EnvironmentChangeV2) (SubmitResult, error) {
	if !c.recoveryControls() {
		return SubmitResult{}, ErrWritePermission
	}
	if e := c.validateEnvironmentChangeV2(packet); e != nil {
		return SubmitResult{}, e
	}
	var accepted Acceptance
	if e := c.request(ctx, "POST", c.endpointFor("/environment-changes-v3"), packet, &accepted); e != nil {
		return SubmitResult{}, e
	}
	return c.ConfirmEnvironmentChangeV3(ctx, packet, accepted)
}
func (c *Client) ConfirmEnvironmentChangeV3(ctx context.Context, packet cryptox.EnvironmentChangeV2, accepted Acceptance) (SubmitResult, error) {
	out := SubmitResult{Accepted: accepted}
	if !c.recoveryControls() {
		return out, ErrWritePermission
	}
	if e := c.validateEnvironmentChangeV2(packet); e != nil {
		return out, e
	}
	if accepted.Sequence == 0 || accepted.Sequence > 9007199254740991 {
		return out, cryptox.ErrInvalidWire
	}
	status, e := c.EnvironmentStatusV3(ctx, packet.Change.IdempotencyKey)
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
		return out, e
	}
	proof, e := c.CurrentIssuerRecoveryEvidence()
	if e != nil {
		return out, errors.Join(ErrAcceptedNotApplied, e)
	}
	wanted, e := cryptox.EnvironmentOriginHash(packet.Origin)
	if e != nil {
		return out, e
	}
	for _, origin := range proof.Origins {
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
