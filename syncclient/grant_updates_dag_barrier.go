package syncclient

import (
	"context"
	"crypto/ed25519"

	"github.com/harmonia-vault/core-go/cryptox"
)

// PrepareDAGGrantUpdate 在实际完整验证的当前目录之后、任何HPKE/签包之前
// 保存调用者的已见下界。回调拿独立副本，不能修改生成器使用的目录。
func (c *Client) PrepareDAGGrantUpdate(ctx context.Context, in GrantUpdateIntent, key ed25519.PrivateKey, controlBarrier func(ManagementControl) error) (*GrantUpdateTransaction, error) {
	if !c.dagControls() || controlBarrier == nil {
		return nil, cryptox.ErrInvalidWire
	}
	return c.prepareGrantUpdate(ctx, in, key, controlBarrier)
}

// SubmitDAGWithControlBarrier 将原包重交所用的实际目录先保存，再检查
// 原GG/KV/双钥/期限；最后仍须Attempted屏障成功才发原SignedGrant。
func (t *GrantUpdateTransaction) SubmitDAGWithControlBarrier(ctx context.Context, controlBarrier func(ManagementControl) error, beforePost func() error) (Acceptance, error) {
	if !t.client.dagControls() || controlBarrier == nil || beforePost == nil {
		return Acceptance{}, cryptox.ErrInvalidWire
	}
	return t.submit(ctx, beforePost, controlBarrier)
}

// OriginalGrant 仅返回该已验原transaction的独立签包副本。原生层须另核
// 精确receipt/hash/接受seq后才可把它记为已见下界，不代表当前权限。
func (t *GrantUpdateTransaction) OriginalGrant() cryptox.SignedGrantWire {
	copy := cloneManagementControl(ManagementControl{Subjects: []ManagementSubject{{CurrentGrant: &t.record.Signed}}})
	return *copy.Subjects[0].CurrentGrant
}
