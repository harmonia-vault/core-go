package syncclient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
)

// P4管理投影只按明确cap解析；公钥仍由完整受签身份图验证。
func (c *Client) requestDAGManagementControl(ctx context.Context, environment string, out *ManagementControl) error {
	target := c.endpointFor("/grant-management")
	q := target.Query()
	q.Set("environmentId", environment)
	q.Set("capability", cryptox.RecoveryDAGCapability)
	target.RawQuery = q.Encode()
	var wire struct {
		AccountID         string                    `json:"accountId"`
		AccountGeneration string                    `json:"accountGeneration"`
		EnvironmentID     string                    `json:"environmentId"`
		Sequence          uint64                    `json:"sequence"`
		KeyVersion        string                    `json:"keyVersion"`
		Subjects          []ManagementSubject       `json:"subjects"`
		IssuerEvidence    cryptox.IssuerRecoveryDAG `json:"issuerEvidence"`
	}
	if e := c.request(ctx, http.MethodGet, target, nil, &wire); e != nil {
		return e
	}
	*out = ManagementControl{AccountID: wire.AccountID, AccountGeneration: wire.AccountGeneration, EnvironmentID: wire.EnvironmentID, Sequence: wire.Sequence, KeyVersion: wire.KeyVersion, Subjects: wire.Subjects, IssuerDAGEvidence: &wire.IssuerEvidence}
	return nil
}
func (c *Client) verifyManagementEvidence(out ManagementControl, historical bool) (VerifiedControlEvidence, error) {
	if !c.dagControls() {
		return nil, cryptox.ErrInvalidWire
	}
	// 复用严格初始化、原pin、完整DAG、来源序号、唯一actor target与连续扩展校验。
	// Subject逐行的历史身份/签权/currentGG检查由verifyManagementControl接着执行。
	actor := []cryptox.SignedGrantWire{}
	for _, s := range out.Subjects {
		if s.DeviceID == c.config.DeviceID && s.CurrentGrant != nil {
			actor = append(actor, *s.CurrentGrant)
		}
	}
	return c.verifyEnvironmentControlEvidence(EnvironmentControlView{Sequence: out.Sequence, Grants: actor, IssuerDAGEvidence: out.IssuerDAGEvidence}, historical)
}

// CheckManagementControlLowerBounds 验证密封历史控制的下界，不修改/清空业务Highest。
// 调用方必须保留已见行，即使下一投影省略全局已撤销设备或返回null/GG0。
func (c *Client) CheckManagementControlLowerBounds(current, previous ManagementControl) error {
	if _, _, e := c.verifyManagementControl(current); e != nil {
		return e
	}
	if _, _, e := c.verifyManagementControl(previous, true); e != nil {
		return e
	}
	if current.AccountID != previous.AccountID || current.AccountGeneration != previous.AccountGeneration || current.EnvironmentID != previous.EnvironmentID || current.Sequence < previous.Sequence {
		return ErrGrantUpdateConflict
	}
	prior := map[string]ManagementSubject{}
	for _, s := range previous.Subjects {
		prior[s.DeviceID] = s
	}
	for _, s := range current.Subjects {
		p, ok := prior[s.DeviceID]
		if !ok || p.CurrentGrant == nil {
			continue
		}
		old, e := parsePositive(p.HighestGrantGeneration)
		if e != nil {
			return e
		}
		now, e := parseNonnegativeManagementGeneration(s.HighestGrantGeneration)
		if e != nil {
			return e
		}
		if now < old || now == old && (s.CurrentGrant == nil || !sameJSON(*s.CurrentGrant, *p.CurrentGrant)) {
			return ErrGrantUpdateConflict
		}
	}
	return nil
}

func parseNonnegativeManagementGeneration(value string) (uint64, error) {
	n, e := strconv.ParseUint(value, 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != value {
		return 0, cryptox.ErrInvalidWire
	}
	return n, nil
}
