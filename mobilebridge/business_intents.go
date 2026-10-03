package mobilebridge

import (
	"context"
	"strconv"

	"github.com/harmonia-vault/core-go/mobileworkflow"
)

// 只接明确账号登录或原密封事务ID；不接会话、变量替代值或完整状态。
var businessIntentFields = map[string][]string{
	"loginAccount":           {"email", "password"},
	"restoreSession":         {},
	"businessPendingInfo":    {},
	"retryBusinessOperation": {"id"},
}

func businessIntentOperation(op string) bool { _, ok := businessIntentFields[op]; return ok }

type accountLoginResult struct {
	Authenticated bool `json:"authenticated"`
	TrustedDevice bool `json:"trustedDevice"`
}

type trustedSessionResult struct {
	TrustedDevice     bool                `json:"trustedDevice"`
	AccountID         string              `json:"accountId"`
	AccountGeneration string              `json:"accountGeneration"`
	DeviceID          string              `json:"deviceId"`
	View              mobileworkflow.View `json:"view"`
}

func (v *VaultWorkflow) executeBusinessIntent(ctx context.Context, c workflowCommand) (any, error) {
	switch c.operation {
	case "loginAccount":
		if err := v.workflow.Login(ctx, c.fields["email"], c.fields["password"]); err != nil {
			return nil, err
		}
		// 只有成熟Go HTTPS登录真实成功才返回。RAM登录session随本次Workflow.Close清除。
		// 它只导航账号向导，不能授予View/Pull、设备授权或保险库可信状态。
		return accountLoginResult{Authenticated: true, TrustedDevice: false}, nil
	case "restoreSession":
		// View先检查已验来源/有效权限并同步密封成功；binding来自本次AES认证后
		// 已核验的inner record和本次Save回调，绝不由Dart或文件header决定trust。
		view, err := v.workflow.View()
		if err != nil {
			return nil, err
		}
		generation, parseErr := strconv.ParseUint(v.binding.AccountGeneration, 10, 64)
		if parseErr != nil || generation == 0 || strconv.FormatUint(generation, 10) != v.binding.AccountGeneration || v.binding.AccountID == "" || v.binding.AccountClosed || view.DeviceID != v.binding.DeviceID || view.Checkpoint != v.binding.Checkpoint {
			return nil, errInput
		}
		return trustedSessionResult{TrustedDevice: true, AccountID: v.binding.AccountID, AccountGeneration: v.binding.AccountGeneration, DeviceID: v.binding.DeviceID, View: view}, nil
	case "businessPendingInfo":
		return v.workflow.PendingBusinessOperations()
	case "retryBusinessOperation":
		return v.workflow.RetryBusinessOperationByID(ctx, c.fields["id"])
	default:
		return nil, mobileworkflow.ErrUnsupported
	}
}
