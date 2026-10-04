package mobilebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"github.com/harmonia-vault/core-go/syncclient"
)

var dagManagementFields = map[string][]string{
	"dagManagementDevices":  {"environmentId"},
	"prepareDAGDeviceGrant": {"requestId", "environmentId", "subjectDeviceId", "role", "expiresAt"},
	"dagManagementInfo":     {},
	"retryDAGManagement":    {"requestId"},
	"cancelDAGManagement":   {"requestId"},
}

func parseDAGManagementCommand(raw string) (workflowCommand, error) {
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
	endpoint, e := validateEndpoint(c.endpoint)
	names, ok := dagManagementFields[c.operation]
	if e != nil || endpoint != c.endpoint || !ok || len(fields) != len(names)+3 {
		return c, errInput
	}
	for _, name := range names {
		v, ok := c.fields[name]
		if !ok {
			return c, errInput
		}
		switch name {
		case "role":
			if v != "ro" && v != "rw" && v != "admin" && v != "none" {
				return c, errInput
			}
		case "expiresAt":
			n, e := nativeDAGDecimal(v, false)
			if e != nil || n > 253402300799 {
				return c, errInput
			}
		default:
			if len(v) > 64 || !nativeDAGID.MatchString(v) {
				return c, errInput
			}
		}
	}
	if c.fields["role"] == "none" && c.fields["expiresAt"] != "0" {
		return c, errInput
	}
	return c, nil
}
func ValidateDAGManagementCommand(raw string) error { _, e := parseDAGManagementCommand(raw); return e }
func DAGManagementProfile() (string, error) {
	return encode(map[string]any{"version": 1, "profile": cryptox.RecoveryDAGCapability, "operations": []string{"cancelDAGManagement", "dagManagementDevices", "dagManagementInfo", "prepareDAGDeviceGrant", "retryDAGManagement"}})
}

func nativeDAGManagementInfo(x mobileworkflow.DAGManagementInfo) (map[string]any, error) {
	if x.Sequence > 9007199254740991 || x.ExpiresAt < 0 || x.ExpiresAt > 253402300799 {
		return nil, errInput
	}
	if x.State == "none" {
		if x.RequestID != "" || x.EnvironmentID != "" || x.SubjectDeviceID != "" || x.Role != "" || x.ExpiresAt != 0 || x.Attempted || x.Sequence != 0 || x.Applied || x.Canceled {
			return nil, errInput
		}
	} else {
		for _, id := range []string{x.RequestID, x.EnvironmentID, x.SubjectDeviceID} {
			if len(id) > 64 || !nativeDAGID.MatchString(id) {
				return nil, errInput
			}
		}
		if x.Role != "ro" && x.Role != "rw" && x.Role != "admin" && x.Role != "none" || x.Role == "none" && x.ExpiresAt != 0 {
			return nil, errInput
		}
		switch x.State {
		case "prepared":
			if x.Attempted || x.Sequence != 0 || x.Applied || x.Canceled {
				return nil, errInput
			}
		case "pending":
			if !x.Attempted || x.Sequence != 0 || x.Applied || x.Canceled {
				return nil, errInput
			}
		case "accepted-not-applied":
			if !x.Attempted || x.Sequence == 0 || x.Applied || x.Canceled {
				return nil, errInput
			}
		case "applied":
			if !x.Attempted || x.Sequence == 0 || !x.Applied || x.Canceled {
				return nil, errInput
			}
		case "canceled":
			if x.Attempted || x.Sequence != 0 || x.Applied || !x.Canceled {
				return nil, errInput
			}
		default:
			return nil, errInput
		}
	}
	return map[string]any{"state": x.State, "requestId": x.RequestID, "environmentId": x.EnvironmentID, "subjectDeviceId": x.SubjectDeviceID, "role": x.Role, "expiresAt": strconv.FormatInt(x.ExpiresAt, 10), "attempted": x.Attempted, "sequence": strconv.FormatUint(x.Sequence, 10), "applied": x.Applied, "canceled": x.Canceled}, nil
}
func nativeDAGManagementDevices(rows []mobileworkflow.ManagementDevice) ([]map[string]any, error) {
	if rows == nil || len(rows) > 256 {
		return nil, errInput
	}
	out := make([]map[string]any, 0, len(rows))
	seen := map[string]bool{}
	for _, r := range rows {
		if len(r.DeviceID) > 64 || !nativeDAGID.MatchString(r.DeviceID) || seen[r.DeviceID] || r.ExpiresAt < 0 || r.ExpiresAt > 253402300799 {
			return nil, errInput
		}
		seen[r.DeviceID] = true
		if r.Role == "ungranted" {
			if r.KeyVersion != "" || r.GrantGeneration != "0" || r.ExpiresAt != 0 {
				return nil, errInput
			}
		} else {
			if r.Role != "ro" && r.Role != "rw" && r.Role != "admin" && r.Role != "none" {
				return nil, errInput
			}
			if _, e := nativeDAGDecimal(r.KeyVersion, true); e != nil {
				return nil, e
			}
			if _, e := nativeDAGDecimal(r.GrantGeneration, true); e != nil {
				return nil, e
			}
		}
		out = append(out, map[string]any{"deviceId": r.DeviceID, "role": r.Role, "expiresAt": strconv.FormatInt(r.ExpiresAt, 10), "keyVersion": r.KeyVersion, "grantGeneration": r.GrantGeneration})
	}
	return out, nil
}
func (v *VaultWorkflow) ExecuteDAGManagement(raw string) (response string, err error) {
	c, e := parseDAGManagementCommand(raw)
	if e != nil {
		return "", e
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
	var info mobileworkflow.DAGManagementInfo
	switch c.operation {
	case "dagManagementDevices":
		var rows []mobileworkflow.ManagementDevice
		rows, e = v.workflow.DAGManagementDevices(ctx, c.fields["environmentId"])
		if e == nil {
			var projected []map[string]any
			projected, e = nativeDAGManagementDevices(rows)
			data = map[string]any{"devices": projected, "trustedDevice": false}
		}
	case "prepareDAGDeviceGrant":
		expires, _ := strconv.ParseInt(c.fields["expiresAt"], 10, 64)
		info, e = v.workflow.PrepareDAGDeviceGrant(ctx, syncclient.GrantUpdateIntent{ID: c.fields["requestId"], EnvironmentID: c.fields["environmentId"], SubjectDeviceID: c.fields["subjectDeviceId"], Role: c.fields["role"], ExpiresAt: expires})
	case "dagManagementInfo":
		info, e = v.workflow.DAGManagementInfo()
	case "cancelDAGManagement":
		info, e = v.workflow.CancelDAGManagement(c.fields["requestId"])
	case "retryDAGManagement":
		var result mobileworkflow.DAGManagementResult
		result, e = v.workflow.RetryDAGManagement(ctx, c.fields["requestId"])
		info = result.Management
		if e == nil {
			if result.View == nil || !info.Applied {
				return "", errInput
			}
			source, pe := nativeDAGAppliedView(*result.View, v.binding)
			if pe != nil {
				return "", pe
			}
			row, pe := nativeDAGManagementInfo(info)
			if pe != nil {
				return "", pe
			}
			data = map[string]any{"management": row, "source": source}
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
		var fault *syncclient.RequestError
		if !errors.Is(e, mobileworkflow.ErrManagementPending) && !errors.Is(e, syncclient.ErrAcceptedNotApplied) || errors.Is(e, syncclient.ErrGrantUpdateConflict) || errors.Is(e, syncclient.ErrWritePermission) || errors.Is(e, mobileworkflow.ErrDAGProtectedState) || errors.As(e, &fault) && fault.Status < 500 {
			return "", e
		}
		original, pe := v.workflow.DAGManagementInfo()
		if pe != nil || original.RequestID != c.fields["requestId"] || original.State == "none" {
			return "", e
		}
		row, pe := nativeDAGManagementInfo(original)
		if pe != nil {
			return "", pe
		}
		data = map[string]any{"original": row, "trustedDevice": false}
		out["error"] = map[string]any{"code": "ORIGINAL_RETRY_REQUIRED", "retryOriginal": true}
	} else if data == nil {
		row, pe := nativeDAGManagementInfo(info)
		if pe != nil {
			return "", pe
		}
		data = map[string]any{"management": row, "trustedDevice": false}
	}
	out["data"] = data
	if ctx.Err() != nil || v.saveFailed.Load() {
		return "", errClosed
	}
	return encode(out)
}
