package mobilebridge

import (
	"context"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"github.com/harmonia-vault/core-go/syncclient"
)

func validateNativeDAGResolutionCommand(c workflowCommand) error {
	if c.operation == "queryDAGRecoveryResolution" || c.operation == "closeDAGRecoveryOriginal" {
		if !nativeDAGID.MatchString(c.fields["operationId"]) || !nativeDAGHash.MatchString(c.fields["targetHash"]) {
			return errInput
		}
	}
	return nil
}

// 墓碑/观察只是成熟高层的持久状态；不能作为设备可信或可复用授权。
func nativeDAGResolution(x mobileworkflow.RecoveryDAGResolutionResult) (map[string]any, error) {
	if x.Version != 1 || x.Profile != cryptox.RecoveryOperationClosureCapability || x.TrustedDevice || !x.RotationRequired || !nativeDAGID.MatchString(x.OperationID) || !nativeDAGHash.MatchString(x.TargetHash) {
		return nil, errInput
	}
	switch x.LocalState {
	case "pending":
		if x.Observation != "unknown" && x.Observation != "pending" || x.Confirmation != "none" || x.Sequence != 0 {
			return nil, errInput
		}
	case "closed":
		if x.Observation != "closed" || x.Confirmation != "native-confirmed" || x.Sequence == 0 {
			return nil, errInput
		}
	case "accepted-original-confirmed":
		if x.Observation != "accepted" || x.Confirmation != "original-history-confirmed" || x.Sequence == 0 {
			return nil, errInput
		}
	default:
		return nil, errInput
	}
	return map[string]any{"version": 1, "profile": x.Profile, "operationId": x.OperationID, "targetHash": x.TargetHash, "observation": x.Observation, "localState": x.LocalState, "confirmation": x.Confirmation, "sequence": strconv.FormatUint(x.Sequence, 10), "rotationRequired": true, "trustedDevice": false}, nil
}

func (v *VaultWorkflow) executeNativeDAGResolution(ctx context.Context, r *NativeDAGRegistry, c workflowCommand, code []byte) (data any, operationErr, metadataErr error) {
	if c.operation == "openDAGRecoveryAfterClosure" {
		var info syncclient.DAGRecoveryInfo
		info, operationErr = v.workflow.BeginDAGRecoveryAfterClosure(ctx, r.domain, r.scope, code)
		if operationErr == nil {
			data, metadataErr = nativeDAGInfo(info)
			if metadataErr == nil {
				r.opened.Store(true)
			}
		}
		return
	}
	// 必须成熟Info无歧义核原sealed transition-v2，不能接受Dart自带target或manifest。
	info, e := v.workflow.RecoveryDAGResolutionInfo()
	if e != nil {
		return nil, e, nil
	}
	if c.operation == "dagRecoveryResolutionInfo" {
		data, metadataErr = nativeDAGResolution(info)
		return
	}
	if info.OperationID != c.fields["operationId"] || info.TargetHash != c.fields["targetHash"] {
		return nil, errInput, nil
	}
	switch c.operation {
	case "queryDAGRecoveryResolution":
		info, operationErr = v.workflow.QueryDAGOperationResolution(ctx, r.domain, r.scope, code)
	case "closeDAGRecoveryOriginal":
		info, operationErr = v.workflow.CloseDAGOperationOriginal(ctx, r.domain, r.scope, code, c.fields["targetHash"])
	default:
		return nil, errInput, nil
	}
	if operationErr == nil {
		data, metadataErr = nativeDAGResolution(info)
	}
	return
}
