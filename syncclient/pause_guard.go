package syncclient

import (
	"context"
	"errors"

	"github.com/harmonia-vault/core-go/localstate"
)

// 普通拉取在途遇到暂停时，不应用任何值或数据序号。原响应仍包含当前签授权
// 和签环境生命周期证明；只投影这些证明，处理已经收到的撤销/删除。
// Scope仅用于本地应用语义；签名验证仍独立检查账号/设备/版本/已见检查点。
func (c *Client) acceptLateAuthorizationProjection(ctx context.Context, result Pull, previous localstate.CloudSnapshot) error {
	verifier, ok := c.config.Verifier.(interface {
		VerifyAuthorizationRefresh(context.Context, Pull, localstate.CloudSnapshot) (localstate.CloudSnapshot, error)
	})
	if !ok {
		return errors.Join(ErrPaused, errors.New("paused response requires pinned permission verification"))
	}
	result.Scope = "authorizations"
	result.Events = nil
	verified, err := verifier.VerifyAuthorizationRefresh(ctx, result, previous)
	if err != nil {
		return errors.Join(ErrPaused, err)
	}
	if err = c.config.Engine.AcceptAuthorizationRefreshAtEpoch(verified, c.config.Now(), c.epoch); err != nil {
		return err
	}
	return ErrPaused
}
