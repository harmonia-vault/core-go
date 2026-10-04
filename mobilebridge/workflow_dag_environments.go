package mobilebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"github.com/harmonia-vault/core-go/syncclient"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var dagEnvironmentFields = map[string][]string{
	"createDAGEnvironment":   {"requestId", "authorityEnvironmentId"},
	"renameDAGEnvironment":   {"requestId", "environmentId"},
	"rotateDAGEnvironment":   {"requestId", "environmentId"},
	"deleteDAGEnvironment":   {"requestId", "environmentId"},
	"pendingDAGEnvironments": {},
	"retryDAGEnvironment":    {"requestId"},
}

func parseDAGEnvironmentCommand(raw string) (workflowCommand, error) {
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
	names, ok := dagEnvironmentFields[c.operation]
	if e != nil || canonical != c.endpoint || !ok || len(fields) != len(names)+3 {
		return c, errInput
	}
	for _, name := range names {
		v, ok := c.fields[name]
		if !ok || len(v) > 64 || !nativeDAGID.MatchString(v) {
			return c, errInput
		}
	}
	return c, nil
}
func ValidateDAGEnvironmentCommand(raw string) error {
	_, e := parseDAGEnvironmentCommand(raw)
	return e
}
func DAGEnvironmentProfile() (string, error) {
	return encode(map[string]any{"version": 1, "profile": cryptox.RecoveryDAGCapability, "operations": []string{"createDAGEnvironment", "deleteDAGEnvironment", "pendingDAGEnvironments", "renameDAGEnvironment", "retryDAGEnvironment", "rotateDAGEnvironment"}})
}
func nativeDAGEnvironmentInfo(x mobileworkflow.DAGEnvironmentInfo) (map[string]any, error) {
	if len(x.RequestID) > 64 || len(x.EnvironmentID) > 64 || !nativeDAGID.MatchString(x.RequestID) || !nativeDAGID.MatchString(x.EnvironmentID) || x.Operation != "create" && x.Operation != "rename" && x.Operation != "rotate" && x.Operation != "delete" || x.Sequence > 9007199254740991 || x.Applied && x.Sequence == 0 {
		return nil, errInput
	}
	return map[string]any{"requestId": x.RequestID, "operation": x.Operation, "environmentId": x.EnvironmentID, "sequence": strconv.FormatUint(x.Sequence, 10), "applied": x.Applied}, nil
}

// 独立typed入口；name只RAM消费，不扩大ordinary/DAGRecovery/variables operation集合。
func (v *VaultWorkflow) ExecuteDAGEnvironment(raw string, name []byte) (response string, err error) {
	defer clear(name)
	c, e := parseDAGEnvironmentCommand(raw)
	if e != nil {
		return "", e
	}
	if c.operation == "createDAGEnvironment" || c.operation == "renameDAGEnvironment" {
		normalized := strings.TrimSpace(string(name))
		if len(name) > 480 || !utf8.Valid(name) || normalized == "" || len([]rune(normalized)) > 120 || strings.ContainsRune(normalized, 0) {
			return "", errInput
		}
	} else if len(name) != 0 {
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
	if c.operation == "pendingDAGEnvironments" {
		var pending []mobileworkflow.DAGEnvironmentInfo
		pending, e = v.workflow.PendingDAGEnvironments()
		if e == nil {
			rows := []map[string]any{}
			for _, x := range pending {
				row, pe := nativeDAGEnvironmentInfo(x)
				if pe != nil {
					e = pe
					break
				}
				rows = append(rows, row)
			}
			data = map[string]any{"pending": rows, "trustedDevice": false}
		}
	} else {
		var result mobileworkflow.DAGEnvironmentResult
		switch c.operation {
		case "createDAGEnvironment":
			result, e = v.workflow.CreateDAGEnvironment(ctx, c.fields["authorityEnvironmentId"], string(name), c.fields["requestId"])
		case "renameDAGEnvironment":
			result, e = v.workflow.RenameDAGEnvironment(ctx, c.fields["environmentId"], string(name), c.fields["requestId"])
		case "rotateDAGEnvironment":
			result, e = v.workflow.RotateDAGEnvironment(ctx, c.fields["environmentId"], c.fields["requestId"])
		case "deleteDAGEnvironment":
			result, e = v.workflow.DeleteDAGEnvironment(ctx, c.fields["environmentId"], c.fields["requestId"])
		case "retryDAGEnvironment":
			result, e = v.workflow.RetryDAGEnvironment(ctx, c.fields["requestId"])
		}
		if e == nil {
			if result.View == nil || !result.Environment.Applied {
				return "", errInput
			}
			view, pe := nativeDAGAppliedView(*result.View, v.binding)
			if pe != nil {
				return "", pe
			}
			row, pe := nativeDAGEnvironmentInfo(result.Environment)
			if pe != nil {
				return "", pe
			}
			data = map[string]any{"environment": row, "source": view}
			trusted = true
		}
	}
	if e != nil && (errors.Is(e, syncclient.ErrTrustInvalidated) || errors.Is(e, mobileworkflow.ErrDAGAuthorizationNotPersisted)) {
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
		pending, pe := v.workflow.PendingDAGEnvironments()
		if pe != nil {
			return "", e
		}
		var original map[string]any
		for _, x := range pending {
			if x.RequestID == c.fields["requestId"] {
				original, pe = nativeDAGEnvironmentInfo(x)
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
