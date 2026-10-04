package mobilebridge

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
)

var nativeDAGID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var nativeDAGHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func nativeDAGDecimal(value string, positive bool) (uint64, error) {
	n, e := strconv.ParseUint(value, 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != value || positive && n == 0 {
		return 0, errInput
	}
	return n, nil
}

// selections 只接收明确的完整选择，不从候选列表补角色、期限或钥版本。
func nativeDAGRecoveredIntent(c workflowCommand) (mobileworkflow.DAGRecoveredIntent, error) {
	var out mobileworkflow.DAGRecoveredIntent
	n, e := nativeDAGDecimal(c.fields["expectedSequence"], true)
	if e != nil || n > 9007199254740991 || !nativeDAGHash.MatchString(c.fields["recoveryHeadHash"]) {
		return out, errInput
	}
	raw := []byte(c.fields["selections"])
	if cryptox.ValidateStrictJSON(raw, maxWorkflowCommand) != nil {
		return out, errInput
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	var rows []map[string]json.RawMessage
	if d.Decode(&rows) != nil || d.Decode(new(any)) != io.EOF || len(rows) == 0 || len(rows) > 16 {
		return out, errInput
	}
	rights := make([]cryptox.RecoveredDeviceRight, 0, len(rows))
	seen := map[string]bool{}
	for _, row := range rows {
		if len(row) != 4 {
			return out, errInput
		}
		values := make([]string, 4)
		for i, name := range []string{"environmentId", "keyVersion", "role", "expiresAt"} {
			var value *string
			if json.Unmarshal(row[name], &value) != nil || value == nil {
				return out, errInput
			}
			values[i] = *value
		}
		if !nativeDAGID.MatchString(values[0]) || seen[values[0]] {
			return out, errInput
		}
		if _, e = nativeDAGDecimal(values[1], true); e != nil {
			return out, errInput
		}
		expiry, e := nativeDAGDecimal(values[3], false)
		if e != nil || expiry > math.MaxInt64 || values[2] != "ro" && values[2] != "rw" && values[2] != "admin" {
			return out, errInput
		}
		seen[values[0]] = true
		rights = append(rights, cryptox.RecoveredDeviceRight{EnvironmentID: values[0], KeyVersion: values[1], Role: values[2], ExpiresAt: values[3]})
	}
	out.ExpectedSequence, out.RecoveryHeadHash, out.SelectedRights = n, c.fields["recoveryHeadHash"], rights
	return out, nil
}

func validateNativeDAGRecoveredCommand(c workflowCommand) error {
	switch c.operation {
	case "sealDAGRecoveredDevice":
		_, e := nativeDAGRecoveredIntent(c)
		return e
	case "retryDAGRecoveredDevice", "applyDAGRecoveredDevice":
		if !nativeDAGID.MatchString(c.fields["operationId"]) || !nativeDAGHash.MatchString(c.fields["contentHash"]) {
			return errInput
		}
	}
	return nil
}

func nativeDAGRecoveredChoices(x mobileworkflow.DAGRecoveredChoices) (map[string]any, error) {
	if x.Version != 1 || x.Profile != cryptox.RecoveryDAGCapability || x.TrustedDevice || x.Sequence == 0 || !nativeDAGHash.MatchString(x.RecoveryHeadHash) || len(x.Environments) == 0 || len(x.Environments) > 256 {
		return nil, errInput
	}
	rows := make([]map[string]string, 0, len(x.Environments))
	seen := map[string]bool{}
	for _, row := range x.Environments {
		if !nativeDAGID.MatchString(row.EnvironmentID) || seen[row.EnvironmentID] {
			return nil, errInput
		}
		if _, e := nativeDAGDecimal(row.KeyVersion, true); e != nil {
			return nil, errInput
		}
		seen[row.EnvironmentID] = true
		rows = append(rows, map[string]string{"environmentId": row.EnvironmentID, "keyVersion": row.KeyVersion})
	}
	return map[string]any{"version": 1, "profile": x.Profile, "sequence": strconv.FormatUint(x.Sequence, 10), "recoveryHeadHash": x.RecoveryHeadHash, "environments": rows, "trustedDevice": false}, nil
}

func nativeDAGRecoveredInfo(x mobileworkflow.DAGRecoveredInfo, p mobileworkflow.RecoveryDAGPendingInfo) (map[string]any, error) {
	if x.Version != 1 || x.Profile != cryptox.RecoveryDAGCapability || x.TrustedDevice || p.Version != 1 || p.Profile != x.Profile || p.TrustedDevice {
		return nil, errInput
	}
	hash := ""
	if x.State == "pending-original" || x.State == "accepted-not-device-applied" {
		if p.Kind != "recovered-v2" || p.OperationID != x.OperationID || p.AcceptedSequence != x.AcceptedSequence || p.OriginalApplied != x.OriginalConfirmed || !nativeDAGHash.MatchString(p.ContentHash) {
			return nil, errInput
		}
		hash = p.ContentHash
	}
	return map[string]any{"version": 1, "profile": x.Profile, "state": x.State, "operationId": x.OperationID, "phase": x.Phase, "contentHash": hash, "acceptance": x.Acceptance, "acceptedSequence": strconv.FormatUint(x.AcceptedSequence, 10), "originalConfirmed": x.OriginalConfirmed, "needsOriginalOwner": x.NeedsOriginalOwner, "trustedDevice": false}, nil
}

func (v *VaultWorkflow) projectNativeDAGRecoveredState() (map[string]any, error) {
	info, e := v.workflow.DAGRecoveredDeviceInfo()
	if e != nil {
		return nil, e
	}
	if info.State == "interrupted-original" || info.State == "none" {
		// preparation已由成熟Info复验；尚无recovered原签包，不能读取旧transition作它的Pending。
		return nativeDAGRecoveredInfo(info, mobileworkflow.RecoveryDAGPendingInfo{Version: 1, Profile: cryptox.RecoveryDAGCapability})
	}
	pending, e := v.workflow.RecoveryDAGPendingInfo()
	if e != nil {
		return nil, e
	}
	return nativeDAGRecoveredInfo(info, pending)
}

func (v *VaultWorkflow) executeNativeDAGRecovered(ctx context.Context, r *NativeDAGRegistry, c workflowCommand) (data any, operationErr, metadataErr error) {
	switch c.operation {
	case "dagRecoveredEnrollmentChoices":
		var x mobileworkflow.DAGRecoveredChoices
		x, operationErr = v.workflow.DAGRecoveredEnrollmentChoices(ctx, r.domain, r.scope)
		if operationErr == nil {
			data, metadataErr = nativeDAGRecoveredChoices(x)
		}
	case "sealDAGRecoveredDevice":
		in, e := nativeDAGRecoveredIntent(c)
		if e != nil {
			return nil, e, nil
		}
		_, operationErr = v.workflow.SealDAGRecoveredDevice(ctx, r.domain, r.scope, in)
		if operationErr == nil {
			data, metadataErr = v.projectNativeDAGRecoveredState()
		}
	case "retryDAGRecoveredDevice":
		// 原包匹配在任何业务网络请求前；不使用调用者包、私钥、token或新ID。
		pending, e := v.workflow.RecoveryDAGPendingInfo()
		if e != nil {
			return nil, e, nil
		}
		if pending.Kind != "recovered-v2" || pending.OperationID != c.fields["operationId"] || pending.ContentHash != c.fields["contentHash"] {
			return nil, errInput, nil
		}
		_, operationErr = v.workflow.RetryDAGRecoveredDevice(ctx, r.domain, r.scope)
		if operationErr == nil {
			data, metadataErr = v.projectNativeDAGRecoveredState()
		}
	case "dagRecoveredDeviceInfo":
		data, operationErr = v.projectNativeDAGRecoveredState()
	default:
		return nil, errInput, nil
	}
	return
}
