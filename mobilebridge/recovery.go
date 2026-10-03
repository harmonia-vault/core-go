package mobilebridge

import (
	"context"
	"errors"
	"github.com/harmonia-vault/core-go/mobileworkflow"
)

var recoveryFields = map[string][]string{
	"beginRecoveryAuthority":  {"email", "password", "recoveryCode"},
	"resumeRecoveryAuthority": {"recoveryCode"},
	"recoveryInfo":            {}, "recoveryView": {},
	"beginRecoveryTransition": {"id"}, "completeRecoveryTransition": {"recoveryCode"}, "queryRecoveryTransition": {},
	"registerRecoveredDevice": {"id", "selections"}, "retryRecoveredDevice": {"id"}, "recoveredDeviceInfo": {},
}

func recoveryOperation(op string) bool { _, ok := recoveryFields[op]; return ok }
func (v *VaultWorkflow) executeRecovery(ctx context.Context, c workflowCommand) (data any, code string, err error) {
	if v.recoveryRegistry == nil {
		return nil, "", mobileworkflow.ErrRecoverySession
	}
	defer func() {
		if ctx.Err() != nil {
			err = errors.Join(err, ctx.Err())
		}
		if err != nil {
			v.clearRecoveryOwner()
			if info, ok := data.(mobileworkflow.RecoveredDeviceInfo); ok {
				info.TrustedDevice = false
				data = info
			}
		}
	}()
	f := c.fields
	switch c.operation {
	case "beginRecoveryAuthority":
		v.clearRecoveryOwner()
		if err = v.workflow.Login(ctx, f["email"], f["password"]); err != nil {
			return
		}
		var owner *mobileworkflow.RecoverySession
		owner, data, err = v.workflow.BeginRecoveryAuthoritySession(ctx, f["recoveryCode"])
		if err == nil {
			err = v.installRecoveryOwner(owner)
		} else if owner != nil {
			owner.Close()
		}
	case "resumeRecoveryAuthority":
		v.clearRecoveryOwner()
		var owner *mobileworkflow.RecoverySession
		owner, err = v.workflow.ResumeRecoveryAuthoritySession(ctx, f["recoveryCode"])
		if err == nil {
			err = v.installRecoveryOwner(owner)
		} else if owner != nil {
			owner.Close()
		}
		if err == nil {
			data, err = v.workflow.RecoveryInfo()
		}
	case "recoveryInfo":
		data, err = v.workflow.RecoveryInfo()
	case "recoveryView":
		err = v.withRecoveryOwner(ctx, func(context.Context) error { data, err = v.workflow.RecoveryView(); return err })
	case "beginRecoveryTransition":
		err = v.withRecoveryOwner(ctx, func(inner context.Context) error {
			code, err = v.workflow.BeginRecoveryAuthorityTransition(inner, f["id"])
			return err
		})
	case "completeRecoveryTransition":
		var owner *mobileworkflow.RecoverySession
		operation := func(inner context.Context) error {
			owner, data, err = v.workflow.CompleteRecoveryAuthorityTransition(inner, f["recoveryCode"])
			return err
		}
		err = v.withRecoveryOwner(ctx, operation)
		// oldOwner在原25域两签包密封后已关闭；unknown/进程重启只用原journal，绝不重建旧私钥。
		if errors.Is(err, mobileworkflow.ErrRecoverySession) {
			v.clearRecoveryOwner()
			err = operation(ctx)
		}
		v.clearRecoveryOwner()
		if err == nil {
			err = v.installRecoveryOwner(owner)
		} else if owner != nil {
			owner.Close()
		}
	case "queryRecoveryTransition":
		data, err = v.workflow.QueryRecoveryAuthorityTransition(ctx)
	case "registerRecoveredDevice":
		var choices []mobileworkflow.ApprovalSelection
		choices, err = parseApprovalSelections(f["selections"])
		if err != nil {
			return
		}
		selected := make([]mobileworkflow.RecoveryDeviceSelection, len(choices))
		for i, s := range choices {
			selected[i] = mobileworkflow.RecoveryDeviceSelection{EnvironmentID: s.EnvironmentID, Role: s.Role, ExpiresAt: s.ExpiresAt}
		}
		err = v.withRecoveryOwner(ctx, func(inner context.Context) error {
			data, err = v.workflow.RegisterRecoveredDevice(inner, f["id"], selected)
			return err
		})
		v.clearRecoveryOwner()
	case "retryRecoveredDevice":
		data, err = v.workflow.RetryRecoveredDevice(ctx, f["id"])
		v.clearRecoveryOwner()
	case "recoveredDeviceInfo":
		data, err = v.workflow.RecoveredDeviceInfo()
	}
	return
}
