package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

func parsePendingPairingsCommand(raw string) (workflowCommand, error) {
	c := workflowCommand{fields: map[string]string{}}
	if len(raw) == 0 || len(raw) > 4096 || !utf8.ValidString(raw) || cryptox.ValidateStrictJSON([]byte(raw), 4096) != nil {
		return c, errInput
	}
	var wire struct {
		Version   int    `json:"version"`
		Endpoint  string `json:"endpoint"`
		Operation string `json:"operation"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &fields) != nil || len(fields) != 3 {
		return c, errInput
	}
	for _, name := range []string{"version", "endpoint", "operation"} {
		if _, ok := fields[name]; !ok {
			return c, errInput
		}
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&wire) != nil || dec.Decode(new(any)) != io.EOF || wire.Version != 1 {
		return c, errInput
	}
	canonical, e := validateEndpoint(wire.Endpoint)
	if e != nil || canonical != wire.Endpoint || wire.Operation != "pendingPairingRequestsV3" && wire.Operation != "pendingPairingRequestsV4" {
		return c, errInput
	}
	c.endpoint, c.operation = wire.Endpoint, wire.Operation
	return c, nil
}
func ValidatePendingPairingsCommand(raw string) error {
	_, e := parsePendingPairingsCommand(raw)
	return e
}
func nativePendingPairings(out syncclient.PendingPairingRequests, b stateBinding) (map[string]any, error) {
	if b.AccountClosed || !nativeDAGID.MatchString(b.AccountID) || !nativeDAGID.MatchString(b.DeviceID) || b.AccountGeneration != out.AccountGeneration {
		return nil, errInput
	}
	if _, e := nativeDAGDecimal(b.AccountGeneration, true); e != nil {
		return nil, e
	}
	expected := cryptox.EnvironmentOriginCapability
	if out.CertificateVersion == "4" {
		expected = cryptox.RecoveryAuthorityCapability
	} else if out.CertificateVersion != "3" {
		return nil, errInput
	}
	if len(out.Capabilities) != 1 || out.Capabilities[0] != expected || out.Requests == nil || len(out.Requests) > 64 {
		return nil, errInput
	}
	rows := make([]map[string]string, 0, len(out.Requests))
	seen := map[string]bool{}
	for _, r := range out.Requests {
		if !nativeDAGID.MatchString(r.IdempotencyKey) || !nativeDAGID.MatchString(r.InitiatorDeviceID) || seen[r.IdempotencyKey] || r.State != "pending" && r.State != "approved" {
			return nil, errInput
		}
		if _, e := nativeDAGDecimal(r.ExpiresAt, true); e != nil {
			return nil, e
		}
		seen[r.IdempotencyKey] = true
		rows = append(rows, map[string]string{"idempotencyKey": r.IdempotencyKey, "initiatorDeviceId": r.InitiatorDeviceID, "state": r.State, "expiresAt": r.ExpiresAt})
	}
	return map[string]any{"accountId": b.AccountID, "accountGeneration": b.AccountGeneration, "approverDeviceId": b.DeviceID, "certificateVersion": out.CertificateVersion, "capabilities": append([]string(nil), out.Capabilities...), "requests": rows, "authoritativeForApproval": false}, nil
}

// 只读封闭入口：未加ordinary Execute/opmap/WorkflowProfile或SDK capability。
func (v *VaultWorkflow) ExecutePendingPairings(raw string) (response string, err error) {
	c, e := parsePendingPairingsCommand(raw)
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
	var out syncclient.PendingPairingRequests
	if c.operation == "pendingPairingRequestsV3" {
		out, e = v.workflow.PendingPairingRequestsV3(ctx)
	} else {
		out, e = v.workflow.PendingPairingRequestsV4(ctx)
	}
	if e != nil {
		if errors.Is(e, syncclient.ErrTrustInvalidated) {
			v.deleteDevice = true
		}
		return "", e
	}
	if ctx.Err() != nil || v.saveFailed.Load() {
		return "", errClosed
	}
	if e = v.checkProtected(v.protectedSHA256); e != nil {
		return "", e
	}
	data, e := nativePendingPairings(out, v.binding)
	if e != nil {
		return "", e
	}
	if ctx.Err() != nil || v.saveFailed.Load() {
		return "", errClosed
	}
	return encode(map[string]any{"version": 1, "operation": c.operation, "ok": true, "data": data})
}
