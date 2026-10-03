package syncclient

import (
	"context"
	"net/http"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// VerifiedControlEvidence 仅提供完整密码学验证后的历史身份/权限查询。
// 历史查询不授予当前权限，控制命令仍逐次核验本机状态与服务端授权。
type VerifiedControlEvidence interface {
	VerifyHistoricalGrant(cryptox.SignedGrantWire) error
	VerifyTarget(cryptox.SignedGrantWire, string, string, string) error
	IssuerBindings() []cryptox.IssuerBinding
}

func (c *Client) recoveryControls() bool {
	v, ok := c.config.Verifier.(*PinnedVerifier)
	return ok && v.initialRecoveryEvidence != nil
}
func (c *Client) controlCapability() string {
	if c.recoveryControls() {
		return cryptox.RecoveryAuthorityCapability
	}
	return cryptox.EnvironmentOriginCapability
}

// 历史 journal 可在恢复链前进后查询旧收据；发送前始终重新取当前控制图。
func (c *Client) verifyControlEvidence(origin cryptox.IssuerProofV2, recovery *cryptox.IssuerRecoveryProof, sequence uint64, historical bool) (VerifiedControlEvidence, error) {
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.evidenceRoot == nil {
		return nil, ErrWritePermission
	}
	state := c.config.Engine.State()
	if state.AccountClosed || state.SessionEpoch != c.epoch {
		return nil, localstate.ErrLocalSession
	}
	if c.recoveryControls() {
		if recovery == nil || origin.Profile != "" {
			return nil, cryptox.ErrInvalidWire
		}
		if e := validateRecoveryLedgerSequence(*recovery, sequence); e != nil {
			return nil, e
		}
		proof, e := cryptox.VerifyIssuerRecoveryEvidence(*v.evidenceRoot, *recovery)
		if e != nil {
			return nil, e
		}
		if !historical {
			prior, e := c.CurrentIssuerRecoveryEvidence()
			if e != nil {
				return nil, e
			}
			previous, e := cryptox.VerifyIssuerRecoveryEvidence(*v.evidenceRoot, prior)
			if e != nil {
				return nil, e
			}
			if _, e = cryptox.VerifyRecoveryCheckpointAdvance(previous, *recovery); e != nil {
				return nil, e
			}
		}
		return proof, nil
	}
	if recovery != nil {
		return nil, cryptox.ErrInvalidWire
	}
	return cryptox.VerifyIssuerEvidenceV2(*v.evidenceRoot, origin, v.genesisAuthorities...)
}

func (c *Client) requestEnvironmentControl(ctx context.Context, environment string, out *EnvironmentControlView) error {
	target := c.endpointFor("/issuer-evidence")
	query := target.Query()
	query.Set("environmentId", environment)
	query.Set("capability", c.controlCapability())
	target.RawQuery = query.Encode()
	if !c.recoveryControls() {
		return c.request(ctx, http.MethodGet, target, nil, out)
	}
	var wire struct {
		Sequence       uint64                      `json:"sequence"`
		Grants         []cryptox.SignedGrantWire   `json:"grants"`
		IssuerEvidence cryptox.IssuerRecoveryProof `json:"issuerEvidence"`
	}
	if e := c.request(ctx, http.MethodGet, target, nil, &wire); e != nil {
		return e
	}
	*out = EnvironmentControlView{Sequence: wire.Sequence, Grants: wire.Grants, IssuerRecoveryEvidence: &wire.IssuerEvidence}
	return nil
}
func (c *Client) requestManagementControl(ctx context.Context, environment string, out *ManagementControl) error {
	target := c.endpointFor("/grant-management")
	query := target.Query()
	query.Set("environmentId", environment)
	query.Set("capability", c.controlCapability())
	target.RawQuery = query.Encode()
	if !c.recoveryControls() {
		return c.request(ctx, http.MethodGet, target, nil, out)
	}
	var wire struct {
		AccountID         string                      `json:"accountId"`
		AccountGeneration string                      `json:"accountGeneration"`
		EnvironmentID     string                      `json:"environmentId"`
		Sequence          uint64                      `json:"sequence"`
		KeyVersion        string                      `json:"keyVersion"`
		Subjects          []ManagementSubject         `json:"subjects"`
		IssuerEvidence    cryptox.IssuerRecoveryProof `json:"issuerEvidence"`
	}
	if e := c.request(ctx, http.MethodGet, target, nil, &wire); e != nil {
		return e
	}
	*out = ManagementControl{AccountID: wire.AccountID, AccountGeneration: wire.AccountGeneration, EnvironmentID: wire.EnvironmentID, Sequence: wire.Sequence, KeyVersion: wire.KeyVersion, Subjects: wire.Subjects, IssuerRecoveryEvidence: &wire.IssuerEvidence}
	return nil
}
