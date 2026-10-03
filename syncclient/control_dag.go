package syncclient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

func (c *Client) dagControls() bool {
	v, ok := c.config.Verifier.(*PinnedVerifier)
	return ok && v.initialDAGEvidence != nil
}

// HTTP字段issuerEvidence由明确的capability选择唯一P4类型，不尝试旧parser。
func (c *Client) requestDAGEnvironmentControl(ctx context.Context, environment string, out *EnvironmentControlView) error {
	target := c.endpointFor("/issuer-evidence")
	q := target.Query()
	q.Set("environmentId", environment)
	q.Set("capability", cryptox.RecoveryDAGCapability)
	target.RawQuery = q.Encode()
	var wire struct {
		Sequence       uint64                    `json:"sequence"`
		Grants         []cryptox.SignedGrantWire `json:"grants"`
		IssuerEvidence cryptox.IssuerRecoveryDAG `json:"issuerEvidence"`
	}
	if e := c.request(ctx, http.MethodGet, target, nil, &wire); e != nil {
		return e
	}
	*out = EnvironmentControlView{Sequence: wire.Sequence, Grants: wire.Grants, IssuerDAGEvidence: &wire.IssuerEvidence}
	return nil
}

// 历史来源只供保护journal重验，不能让发送前检查绕过当前权限/时间/检查点。
func (c *Client) verifyEnvironmentControlEvidence(out EnvironmentControlView, historical bool) (VerifiedControlEvidence, error) {
	if !c.dagControls() {
		if out.IssuerDAGEvidence != nil {
			return nil, cryptox.ErrInvalidWire
		}
		return c.verifyControlEvidence(out.IssuerEvidence, out.IssuerRecoveryEvidence, out.Sequence, historical)
	}
	v := c.config.Verifier.(*PinnedVerifier)
	state := c.config.Engine.State()
	if state.AccountClosed || state.SessionEpoch != c.epoch {
		return nil, localstate.ErrLocalSession
	}
	if out.IssuerDAGEvidence == nil || out.IssuerRecoveryEvidence != nil || !sameJSON(out.IssuerEvidence, cryptox.IssuerProofV2{}) {
		return nil, cryptox.ErrInvalidWire
	}
	if len(out.Grants) < 1 || len(out.Grants) > 256 {
		return nil, cryptox.ErrInvalidWire
	}
	candidate := *out.IssuerDAGEvidence
	if !sameJSON(candidate.Initialization, v.initialDAGEvidence.Initialization) {
		return nil, cryptox.ErrInvalidWire
	}
	if e := validateDAGSequence(candidate, out.Sequence); e != nil {
		return nil, e
	}
	view, e := dagView(&candidate)
	if e != nil {
		return nil, e
	}
	if len(view.Targets) != 1 {
		return nil, cryptox.ErrInvalidWire
	}
	for _, origin := range view.Origins {
		seq, e := strconv.ParseUint(origin.Origin.ExpectedSequence, 10, 64)
		if e != nil || seq >= out.Sequence {
			return nil, cryptox.ErrInvalidWire
		}
	}
	if historical {
		return cryptox.VerifyIssuerRecoveryDAG(*v.evidenceRoot, candidate)
	}
	previous, e := c.CurrentIssuerDAGEvidence()
	if e != nil {
		return nil, e
	}
	prior, e := cryptox.VerifyIssuerRecoveryDAG(*v.evidenceRoot, previous)
	if e != nil {
		return nil, e
	}
	return cryptox.VerifyRecoveryDAGAdvance(prior, candidate)
}
