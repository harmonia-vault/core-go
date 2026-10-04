package mobilebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"github.com/harmonia-vault/core-go/syncclient"
)

var dagBusinessFields = map[string][]string{
	"putDAGVariable":    {"requestId", "environmentId", "name"},
	"deleteDAGVariable": {"requestId", "environmentId", "name"},
	"pendingDAGWrites":  {},
	"retryDAGWrite":     {"requestId"},
}

func parseDAGBusinessCommand(raw string) (workflowCommand, error) {
	c := workflowCommand{fields: map[string]string{}}
	if len(raw) == 0 || len(raw) > 4096 || !utf8.ValidString(raw) || cryptox.ValidateStrictJSON([]byte(raw), 4096) != nil {
		return c, errInput
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &fields) != nil {
		return c, errInput
	}
	var version int
	if json.Unmarshal(fields["version"], &version) != nil || version != 1 {
		return c, errInput
	}
	for name, value := range fields {
		if name == "version" {
			continue
		}
		var v *string
		if json.Unmarshal(value, &v) != nil || v == nil {
			return c, errInput
		}
		switch name {
		case "operation":
			c.operation = *v
		case "endpoint":
			c.endpoint = *v
		default:
			c.fields[name] = *v
		}
	}
	canonical, e := validateEndpoint(c.endpoint)
	names, ok := dagBusinessFields[c.operation]
	if e != nil || canonical != c.endpoint || !ok || len(fields) != len(names)+3 {
		return c, errInput
	}
	for _, name := range names {
		if _, ok = c.fields[name]; !ok {
			return c, errInput
		}
	}
	request := syncclient.WriteRequest{ID: c.fields["requestId"], EnvironmentID: c.fields["environmentId"], Name: c.fields["name"]}
	switch c.operation {
	case "putDAGVariable":
		request.Operation = "put"
	case "deleteDAGVariable":
		request.Operation = "delete"
	case "retryDAGWrite":
		request.Operation = "retry"
	case "pendingDAGWrites":
		return c, nil
	}
	if e = syncclient.ValidateWriteRequest(request); e != nil {
		return c, errInput
	}
	return c, nil
}

// 编译存在性投影，不是逐项SDK或产品验收证据；不扩大ordinary或DAGRecovery名单。
func DAGBusinessProfile() (string, error) {
	return encode(map[string]any{"version": 1, "profile": cryptox.RecoveryDAGCapability, "operations": []string{"deleteDAGVariable", "pendingDAGWrites", "putDAGVariable", "retryDAGWrite"}})
}
func ValidateDAGBusinessCommand(raw string) error { _, e := parseDAGBusinessCommand(raw); return e }

func nativeDAGWriteInfo(x syncclient.WriteOperationInfo) (map[string]any, error) {
	if !nativeDAGID.MatchString(x.RequestID) || !nativeDAGID.MatchString(x.EnvironmentID) || x.Operation != "put" && x.Operation != "delete" || x.Total != 1 || x.Accepted < 0 || x.Accepted > x.Total || len(x.Sequences) != x.Total || x.Applied && (x.Canceled || x.Accepted != x.Total) {
		return nil, errInput
	}
	seq := make([]string, len(x.Sequences))
	for i, n := range x.Sequences {
		if n > 9007199254740991 {
			return nil, errInput
		}
		seq[i] = strconv.FormatUint(n, 10)
	}
	return map[string]any{"requestId": x.RequestID, "operation": x.Operation, "environmentId": x.EnvironmentID, "total": x.Total, "accepted": x.Accepted, "applied": x.Applied, "canceled": x.Canceled, "sequences": seq}, nil
}
func nativeDAGWriteResult(x syncclient.WriteResult) (map[string]any, error) {
	if !nativeDAGID.MatchString(x.RequestID) || x.Total != 1 || x.Accepted < 0 || x.Accepted > x.Total || len(x.Sequences) != x.Total || x.Applied && x.Accepted != x.Total {
		return nil, errInput
	}
	seq := make([]string, len(x.Sequences))
	for i, n := range x.Sequences {
		if n > 9007199254740991 {
			return nil, errInput
		}
		seq[i] = strconv.FormatUint(n, 10)
	}
	return map[string]any{"requestId": x.RequestID, "total": x.Total, "accepted": x.Accepted, "applied": x.Applied, "sequences": seq}, nil
}

// 每个handle只排空自己的有界操作；领域网络不持原Workflow锁。value独立RAM缓冲被消费。
// 不接ordinary Execute/WorkflowProfile，不返回原签包/钥/session或用户指定存储路径。
func (v *VaultWorkflow) ExecuteDAGBusiness(raw string, value []byte) (response string, err error) {
	defer clear(value)
	c, e := parseDAGBusinessCommand(raw)
	if e != nil {
		return "", e
	}
	if c.operation == "putDAGVariable" {
		if len(value) > cryptox.MaxValueBytes || !utf8.Valid(value) || strings.ContainsRune(string(value), 0) {
			return "", errInput
		}
	} else if len(value) != 0 {
		return "", errInput
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.workflow == nil || len(v.key) != 32 || v.saveFailed.Load() || c.endpoint != v.binding.Endpoint {
		return "", errClosed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	v.cancelMu.Lock()
	v.cancel = cancel
	v.cancelMu.Unlock()
	defer func() { cancel(); v.cancelMu.Lock(); v.cancel = nil; v.cancelMu.Unlock() }()
	if e = v.checkProtected(v.protectedSHA256); e != nil {
		return "", e
	}
	var data any
	trusted := false
	var result mobileworkflow.DAGWriteResult
	if c.operation == "pendingDAGWrites" {
		var pending []syncclient.WriteOperationInfo
		pending, e = v.workflow.PendingDAGWrites()
		if e == nil {
			rows := make([]map[string]any, 0, len(pending))
			for _, x := range pending {
				var row map[string]any
				row, e = nativeDAGWriteInfo(x)
				if e != nil {
					break
				}
				rows = append(rows, row)
			}
			data = map[string]any{"pending": rows, "trustedDevice": false}
		}
	} else {
		switch c.operation {
		case "putDAGVariable":
			result, e = v.workflow.SetDAGVariable(ctx, c.fields["environmentId"], c.fields["name"], string(value), c.fields["requestId"])
		case "deleteDAGVariable":
			result, e = v.workflow.DeleteDAGVariable(ctx, c.fields["environmentId"], c.fields["name"], c.fields["requestId"])
		case "retryDAGWrite":
			result, e = v.workflow.RetryDAGWrite(ctx, c.fields["requestId"])
		}
		if e == nil {
			if result.View == nil || !result.Write.Applied {
				return "", errInput
			}
			var view map[string]any
			view, err = nativeDAGAppliedView(*result.View, v.binding)
			if err != nil {
				return "", err
			}
			var write map[string]any
			write, err = nativeDAGWriteResult(result.Write)
			if err != nil {
				return "", err
			}
			data = map[string]any{"write": write, "source": view}
			trusted = true
		}
	}
	if e != nil && (errors.Is(e, syncclient.ErrTrustInvalidated) || errors.Is(e, mobileworkflow.ErrDAGAuthorizationNotPersisted)) {
		// 失败可退休旧handle；只有原生仍确认精确captured旧密文才可请求清它。
		// 这里仅只读Check，不复开saveFailed，也不将未知IO当旧槽证明。
		if slot, ok := v.store.(AtomicSealedStateStore); ok && slot.CheckSealed(bytes.Clone(v.lastSealed)) == nil {
			v.deleteDevice = true
		}
		return "", e
	}
	if ctx.Err() != nil || v.saveFailed.Load() {
		return "", errClosed
	}
	if err = v.checkProtected(v.protectedSHA256); err != nil {
		return "", err
	}
	out := map[string]any{"version": 1, "profile": cryptox.RecoveryDAGCapability, "operation": c.operation, "ok": e == nil, "trustedDevice": trusted}
	if e != nil {
		if !errors.Is(e, syncclient.ErrWritePending) && !errors.Is(e, syncclient.ErrAcceptedNotApplied) {
			return "", e
		}
		pending, pe := v.workflow.PendingDAGWrites()
		if pe != nil {
			return "", e
		}
		var original map[string]any
		for _, item := range pending {
			if item.RequestID == c.fields["requestId"] {
				original, pe = nativeDAGWriteInfo(item)
				break
			}
		}
		if pe != nil || original == nil {
			return "", e
		}
		data = map[string]any{"original": original, "trustedDevice": false}
		out["error"] = map[string]any{"code": "ORIGINAL_RETRY_REQUIRED", "retryOriginal": true}
	}
	out["data"] = data
	if ctx.Err() != nil || v.saveFailed.Load() {
		return "", errClosed
	}
	return encode(out)
}
