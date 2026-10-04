package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"github.com/harmonia-vault/core-go/syncclient"
)

var dagNativeFields = map[string][]string{
	"openDAGRecoveryOwner": {"email", "password"},
	"dagRecoveryOwnerInfo": {}, "dagRecoveryPreparationInfo": {}, "dagRecoveryPendingInfo": {},
	"beginDAGRecoveryTransition": {}, "sealDAGRecoveryTransition": {}, "retryDAGRecoveryTransition": {}, "queryDAGRecoveryOriginal": {},
	"dagRecoveredEnrollmentChoices": {}, "dagRecoveredDeviceInfo": {},
	"sealDAGRecoveredDevice":    {"expectedSequence", "recoveryHeadHash", "selections"},
	"retryDAGRecoveredDevice":   {"operationId", "contentHash"},
	"applyDAGRecoveredDevice":   {"operationId", "contentHash"},
	"restoreDAGRecoveredDevice": {}, "pullDAGRecoveredDevice": {},
	"dagRecoveryResolutionInfo":   {},
	"queryDAGRecoveryResolution":  {"operationId", "targetHash"},
	"closeDAGRecoveryOriginal":    {"operationId", "targetHash"},
	"openDAGRecoveryAfterClosure": {},
	"cancelDAGRecoveryOwner":      {}, // 只由native处理本slot RAM；ExecuteDAGRecovery不执行此非domain命令。
}

func parseNativeDAGCommand(raw string) (workflowCommand, error) {
	c := workflowCommand{fields: map[string]string{}}
	if len(raw) == 0 || len(raw) > maxWorkflowCommand || !utf8.ValidString(raw) {
		return c, errInput
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	t, e := dec.Token()
	if e != nil || t != json.Delim('{') {
		return c, errInput
	}
	seen := map[string]bool{}
	version := false
	for dec.More() {
		t, e = dec.Token()
		name, ok := t.(string)
		if e != nil || !ok || seen[name] {
			return c, errInput
		}
		seen[name] = true
		if name == "version" {
			var value int
			if dec.Decode(&value) != nil || value != 1 {
				return c, errInput
			}
			version = true
			continue
		}
		var value *string
		if dec.Decode(&value) != nil || value == nil {
			return c, errInput
		}
		switch name {
		case "endpoint":
			c.endpoint = *value
		case "operation":
			c.operation = *value
		default:
			c.fields[name] = *value
		}
	}
	if _, e = dec.Token(); e != nil {
		return c, errInput
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || !version || !seen["endpoint"] || !seen["operation"] {
		return c, errInput
	}
	canonical, e := validateEndpoint(c.endpoint)
	if e != nil || canonical != c.endpoint {
		return c, errInput
	}
	fields, ok := dagNativeFields[c.operation]
	if !ok || len(fields) != len(c.fields) {
		return c, errInput
	}
	for _, name := range fields {
		if _, ok = c.fields[name]; !ok {
			return c, errInput
		}
	}
	return c, nil
}
func codeRequired(operation string) bool {
	return operation == "openDAGRecoveryOwner" || operation == "sealDAGRecoveryTransition" || operation == "queryDAGRecoveryOriginal" || operation == "queryDAGRecoveryResolution" || operation == "closeDAGRecoveryOriginal" || operation == "openDAGRecoveryAfterClosure"
}

// ValidateDAGRecoveryCommand仅原生结构预检，不能凭其成功认为已认证/可信。
func ValidateDAGRecoveryCommand(raw string, codeLength int64) error {
	c, e := parseNativeDAGCommand(raw)
	if e != nil {
		return e
	}
	if codeRequired(c.operation) {
		if codeLength < 1 || codeLength > 512 {
			return errInput
		}
	} else if codeLength != 0 {
		return errInput
	}
	if e = validateNativeDAGRecoveredCommand(c); e != nil {
		return e
	}
	return validateNativeDAGResolutionCommand(c)
}
func nativeDAGInfo(x syncclient.DAGRecoveryInfo) (map[string]any, error) {
	if x.TrustedDevice {
		return nil, errInput
	}
	return map[string]any{"recoveryGeneration": x.RecoveryGeneration, "sequence": strconv.FormatUint(x.Sequence, 10), "environments": x.Environments, "rotationRequired": x.RotationRequired, "trustedDevice": false, "expiresAt": strconv.FormatInt(x.ExpiresAt, 10)}, nil
}
func nativeDAGPending(x mobileworkflow.RecoveryDAGPendingInfo) (map[string]any, error) {
	if x.TrustedDevice || x.Version != 1 || x.Profile != cryptox.RecoveryDAGCapability {
		return nil, errInput
	}
	return map[string]any{"version": 1, "profile": x.Profile, "state": x.State, "operationId": x.OperationID, "kind": x.Kind, "contentHash": x.ContentHash, "acceptance": x.Acceptance, "acceptedSequence": strconv.FormatUint(x.AcceptedSequence, 10), "originalApplied": x.OriginalApplied, "trustedDevice": false}, nil
}
func nativeDAGPreparation(x mobileworkflow.RecoveryDAGPreparationInfo) (map[string]any, error) {
	if x.TrustedDevice || x.Version != 1 || x.Profile != cryptox.RecoveryDAGCapability {
		return nil, errInput
	}
	return map[string]any{"version": 1, "profile": x.Profile, "state": x.State, "operationId": x.OperationID, "phase": x.Phase, "needsOriginalOwner": x.NeedsOriginalOwner, "trustedDevice": false}, nil
}
func nativeDAGQuery(x mobileworkflow.RecoveryDAGQueryResult) (map[string]any, error) {
	p, e := nativeDAGPending(x.Pending)
	if e != nil || x.TrustedDevice || x.Version != 1 || x.Profile != cryptox.RecoveryDAGCapability {
		return nil, errInput
	}
	return map[string]any{"version": 1, "profile": x.Profile, "pending": p, "observation": x.Observation, "confirmation": x.Confirmation, "rotationRequired": x.RotationRequired, "trustedDevice": false}, nil
}

// ExecuteDAGRecovery是封闭native-only typed分派，未添加MethodChannel/profile。
// registry只由AttachDAGRegistry安装；每次新的已认证AtomicWorkflow/snapshot必须再核。
// 码独立参数不进JSON，所有原签包/钥/token仍在成熟业务/原生密文边界。
func (v *VaultWorkflow) ExecuteDAGRecovery(raw string, completeCode []byte) (response string, err error) {
	defer clear(completeCode)
	if err = ValidateDAGRecoveryCommand(raw, int64(len(completeCode))); err != nil {
		return "", err
	}
	c, _ := parseNativeDAGCommand(raw)
	if c.operation == "cancelDAGRecoveryOwner" {
		return "", errInput
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.workflow == nil || len(v.key) != 32 || v.saveFailed.Load() || c.endpoint != v.binding.Endpoint {
		return "", errClosed
	}
	v.cancelMu.Lock()
	r := v.dagRegistry
	v.cancelMu.Unlock()
	if r == nil {
		return "", errClosed
	}
	id, ctx, e := r.reserve(context.Background())
	if e != nil {
		return "", e
	}
	v.cancelMu.Lock()
	v.cancel = func() { r.cancelRecorded(id) }
	v.cancelMu.Unlock()
	// finish在v.mu解锁及native drain之前；任何callback不会同步Close同一active记录。
	defer func() { r.finish(id); v.cancelMu.Lock(); v.cancel = nil; v.cancelMu.Unlock() }()
	defer func() {
		if err != nil {
			r.Invalidate()
		}
	}()
	if err = v.checkProtected(v.protectedSHA256); err != nil {
		return "", err
	}
	var data any
	var code string
	var operationErr error
	var metadataErr error
	trusted := false
	switch c.operation {
	case "openDAGRecoveryOwner":
		// 最新已审高层scope helper接入前，不能把RAM-only Login当持久跨认证scope。
		operationErr = v.openNativeDAGOwner(ctx, r, c, completeCode)
		if operationErr == nil {
			var info syncclient.DAGRecoveryInfo
			info, operationErr = v.workflow.RecoveryDAGOwnerInfo(ctx, r.domain, r.scope)
			if operationErr == nil {
				data, metadataErr = nativeDAGInfo(info)
				r.opened.Store(true)
			}
		}
	case "dagRecoveryOwnerInfo":
		var info syncclient.DAGRecoveryInfo
		info, operationErr = v.workflow.RecoveryDAGOwnerInfo(ctx, r.domain, r.scope)
		if operationErr == nil {
			data, metadataErr = nativeDAGInfo(info)
		}
	case "dagRecoveryPreparationInfo":
		var info mobileworkflow.RecoveryDAGPreparationInfo
		info, operationErr = v.workflow.RecoveryDAGPreparationInfo()
		if operationErr == nil {
			data, metadataErr = nativeDAGPreparation(info)
		}
	case "dagRecoveryPendingInfo":
		var info mobileworkflow.RecoveryDAGPendingInfo
		info, operationErr = v.workflow.RecoveryDAGPendingInfo()
		if operationErr == nil {
			data, metadataErr = nativeDAGPending(info)
		}
	case "beginDAGRecoveryTransition":
		code, operationErr = v.workflow.BeginDAGRecoveryTransition(ctx, r.domain, r.scope)
	case "sealDAGRecoveryTransition":
		var info mobileworkflow.RecoveryDAGPendingInfo
		info, operationErr = v.workflow.SealDAGRecoveryTransition(ctx, r.domain, r.scope, completeCode)
		if operationErr == nil {
			data, metadataErr = nativeDAGPending(info)
		}
	case "retryDAGRecoveryTransition":
		var info syncclient.DAGRecoveryInfo
		info, operationErr = v.workflow.RetryDAGRecoveryTransition(ctx, r.domain, r.scope)
		if operationErr == nil {
			data, metadataErr = nativeDAGInfo(info)
		}
	case "queryDAGRecoveryOriginal":
		if r.opened.Load() {
			return "", errNativeDAGBusy
		}
		var info mobileworkflow.RecoveryDAGQueryResult
		info, operationErr = v.workflow.QueryRecoveryDAGOriginal(ctx, completeCode)
		if operationErr == nil {
			data, metadataErr = nativeDAGQuery(info)
		}
	case "dagRecoveredEnrollmentChoices", "sealDAGRecoveredDevice", "retryDAGRecoveredDevice", "dagRecoveredDeviceInfo":
		data, operationErr, metadataErr = v.executeNativeDAGRecovered(ctx, r, c)
	case "dagRecoveryResolutionInfo", "queryDAGRecoveryResolution", "closeDAGRecoveryOriginal", "openDAGRecoveryAfterClosure":
		data, operationErr, metadataErr = v.executeNativeDAGResolution(ctx, r, c, completeCode)
	case "applyDAGRecoveredDevice", "restoreDAGRecoveredDevice", "pullDAGRecoveredDevice":
		data, operationErr, metadataErr = v.executeNativeDAGApplied(ctx, r, c)
		trusted = operationErr == nil && metadataErr == nil
	default:
		return "", errInput
	}
	if metadataErr != nil {
		return "", metadataErr
	}
	if ctx.Err() != nil || r.dead.Load() || v.saveFailed.Load() {
		return "", errClosed
	}
	if err = v.checkProtected(v.protectedSHA256); err != nil {
		return "", err
	}
	out := map[string]any{"version": 1, "profile": cryptox.RecoveryDAGCapability, "operation": c.operation, "trustedDevice": trusted, "ok": operationErr == nil}
	if operationErr != nil {
		if !nativeDAGSoftCandidate(c.operation, operationErr) {
			return "", operationErr
		}
		// 只允许成熟domain真实核验的活owner证明soft；不凭HTTP字符串/自己重建binding。
		info, liveErr := v.workflow.RecoveryDAGOwnerInfo(ctx, r.domain, r.scope)
		if liveErr != nil || ctx.Err() != nil || r.dead.Load() || v.saveFailed.Load() {
			return "", operationErr
		}
		projection, e := nativeDAGInfo(info)
		if e != nil {
			return "", e
		}
		fixed := "ORIGINAL_RETRY_REQUIRED"
		if errors.Is(operationErr, syncclient.ErrDAGNewCodeMismatch) {
			fixed = "NEW_CODE_REENTRY_REQUIRED"
		}
		if errors.Is(operationErr, mobileworkflow.ErrDAGCodeAlreadyPrepared) {
			fixed = "CODE_ALREADY_PREPARED"
		}
		out["error"] = map[string]any{"code": fixed, "ownerRetained": true, "retryOriginal": true}
		if c.operation == "sealDAGRecoveredDevice" || c.operation == "retryDAGRecoveredDevice" {
			projection, e = v.projectNativeDAGRecoveredState()
			if e != nil {
				return "", e
			}
		}
		out["data"] = projection
	} else {
		if data != nil {
			out["data"] = data
		}
		if code != "" {
			out["recoveryCode"] = code
		}
	}
	if ctx.Err() != nil || r.dead.Load() || v.saveFailed.Load() {
		return "", errClosed
	}
	return encode(out)
}

// 高层先CAS保存fresh/clean账号scope并更新自身SHA；已有DAG原包/准备记录不能重登录清除。
func (v *VaultWorkflow) openNativeDAGOwner(ctx context.Context, r *NativeDAGRegistry, c workflowCommand, code []byte) error {
	scope, e := v.workflow.LoginDAGAccountScope(ctx, c.fields["email"], c.fields["password"])
	if e != nil {
		return e
	}
	if scope.TrustedDevice || scope.AccountID != v.binding.AccountID || scope.AccountGeneration != v.binding.AccountGeneration || scope.DeviceID != v.binding.DeviceID {
		return errInput
	}
	if e = v.checkProtected(v.protectedSHA256); e != nil {
		return e
	}
	info, e := v.workflow.OpenDAGRecoveryOwner(ctx, r.domain, r.scope, code)
	if e == nil && info.TrustedDevice {
		return errInput
	}
	return e
}

// 与成熟 mobileworkflow.dagTransitionRetryable 的封闭操作合同一致；
// RAM仍活不能把认证/代际/权限/wire/存储错误改成soft。再核OwnerInfo只是第二道条件。
func nativeDAGSoftCandidate(operation string, err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, cryptox.ErrInvalidWire) || errors.Is(err, syncclient.ErrTrustInvalidated) || errors.Is(err, mobileworkflow.ErrDAGOwnerBinding) || errors.Is(err, mobileworkflow.ErrDAGProtectedState) || errors.Is(err, mobileworkflow.ErrDAGPersistence) {
		return false
	}
	var fault *syncclient.RequestError
	if errors.As(err, &fault) && (fault.Status == 401 || fault.Status == 403) {
		return false
	}
	if operation == "sealDAGRecoveryTransition" && errors.Is(err, syncclient.ErrDAGNewCodeMismatch) || operation == "beginDAGRecoveryTransition" && errors.Is(err, mobileworkflow.ErrDAGCodeAlreadyPrepared) {
		return fault == nil
	}
	if !(operation == "beginDAGRecoveryTransition" && errors.Is(err, syncclient.ErrDAGPreparationPending) || operation == "retryDAGRecoveryTransition" && errors.Is(err, syncclient.ErrEnrollmentPending) || operation == "sealDAGRecoveredDevice" && errors.Is(err, syncclient.ErrDAGPreparationPending) || operation == "retryDAGRecoveredDevice" && errors.Is(err, syncclient.ErrEnrollmentPending)) {
		return false
	}
	// 不复制domain的HTTP可重试规则。只有此typed sentinel可候选；
	// 成熟runDAGTransition已按其单一dagTransitionRetryable规则finish，
	// 后续OwnerInfo必须证明实际原owner仍活才允许投影。
	return true
}
