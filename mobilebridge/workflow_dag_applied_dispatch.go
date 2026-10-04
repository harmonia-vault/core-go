package mobilebridge

import (
	"context"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/mobileworkflow"
)

// 只投影成熟业务已经验证并最终CAS保存的来源，不把服务器回显或accepted视为信任。
func nativeDAGAppliedView(x mobileworkflow.DAGRecoveredView, b stateBinding) (map[string]any, error) {
	if x.Version != 1 || x.Profile != cryptox.RecoveryDAGCapability || !x.TrustedDevice || !nativeDAGID.MatchString(x.OperationID) || !nativeDAGHash.MatchString(x.ContentHash) || x.AcceptedSequence == 0 || x.View.Checkpoint < x.AcceptedSequence || !x.View.Experimental || b.AccountClosed || !nativeDAGID.MatchString(b.AccountID) || b.AccountGeneration == "" || !nativeDAGID.MatchString(b.DeviceID) || b.DeviceID != x.View.DeviceID || b.Checkpoint != x.View.Checkpoint {
		return nil, errInput
	}
	if _, e := nativeDAGDecimal(b.AccountGeneration, true); e != nil {
		return nil, errInput
	}
	rows := make([]map[string]any, 0, len(x.View.Environments))
	seen := map[string]bool{}
	for _, env := range x.View.Environments {
		if !nativeDAGID.MatchString(env.ID) || seen[env.ID] || env.Role != localstate.ReadOnly && env.Role != localstate.ReadWrite && env.Role != localstate.Admin {
			return nil, errInput
		}
		seen[env.ID] = true
		values := make(map[string]string, len(env.Variables))
		for key, value := range env.Variables {
			values[key] = value
		}
		rows = append(rows, map[string]any{"id": env.ID, "name": env.Name, "role": string(env.Role), "variables": values})
	}
	checkpoint := strconv.FormatUint(x.View.Checkpoint, 10)
	return map[string]any{"version": 1, "profile": x.Profile, "operationId": x.OperationID, "contentHash": x.ContentHash, "acceptedSequence": strconv.FormatUint(x.AcceptedSequence, 10), "trustedDevice": true, "binding": map[string]string{"accountId": b.AccountID, "accountGeneration": b.AccountGeneration, "deviceId": b.DeviceID, "checkpoint": checkpoint}, "view": map[string]any{"deviceId": x.View.DeviceID, "checkpoint": checkpoint, "experimental": true, "environments": rows}}, nil
}

func (v *VaultWorkflow) executeNativeDAGApplied(ctx context.Context, r *NativeDAGRegistry, c workflowCommand) (data any, operationErr, metadataErr error) {
	var result mobileworkflow.DAGRecoveredView
	switch c.operation {
	case "applyDAGRecoveredDevice":
		// 已确认原签包的ID/hash/接受序号先核；陌生ID、未确认原包零网络。
		p, e := v.workflow.RecoveryDAGPendingInfo()
		if e != nil {
			return nil, e, nil
		}
		if p.Kind != "recovered-v2" || p.OperationID != c.fields["operationId"] || p.ContentHash != c.fields["contentHash"] || p.AcceptedSequence == 0 || !p.OriginalApplied || p.TrustedDevice {
			return nil, errInput, nil
		}
		result, operationErr = v.workflow.ApplyDAGRecoveredDevice(ctx, r.domain, r.scope)
		if operationErr == nil && (result.OperationID != p.OperationID || result.ContentHash != p.ContentHash || result.AcceptedSequence != p.AcceptedSequence) {
			return nil, nil, errInput
		}
	case "restoreDAGRecoveredDevice":
		result, operationErr = v.workflow.RestoreDAGRecoveredDevice()
	case "pullDAGRecoveredDevice":
		result, operationErr = v.workflow.PullDAGRecoveredDevice(ctx)
	default:
		return nil, errInput, nil
	}
	if operationErr == nil {
		data, metadataErr = nativeDAGAppliedView(result, v.binding)
	}
	return
}
