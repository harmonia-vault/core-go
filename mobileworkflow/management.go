package mobileworkflow

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrManagementPending = errors.New("device management pending; resolve original request before other operations")
var ErrManagementConflict = errors.New("device management original intent or accepted history changed")
var ErrManagementLimit = errors.New("protected device management history limit reached")

type ManagementDevice struct {
	DeviceID        string `json:"deviceId"`
	Role            string `json:"role"`
	ExpiresAt       int64  `json:"expiresAt"`
	KeyVersion      string `json:"keyVersion"`
	GrantGeneration string `json:"grantGeneration"`
}
type ManagementInfo struct {
	State           string `json:"state"`
	ID              string `json:"id,omitempty"`
	Kind            string `json:"kind,omitempty"`
	EnvironmentID   string `json:"environmentId,omitempty"`
	SubjectDeviceID string `json:"subjectDeviceId,omitempty"`
	ExpiresAt       int64  `json:"expiresAt,omitempty"`
	Attempted       bool   `json:"attempted"`
	Sequence        uint64 `json:"sequence,omitempty"`
}
type ManagementResult struct {
	ID                string `json:"id"`
	Accepted          bool   `json:"accepted"`
	Applied           bool   `json:"applied"`
	Sequence          uint64 `json:"sequence,omitempty"`
	AcceptanceUnknown bool   `json:"acceptanceUnknown"`
	Canceled          bool   `json:"canceled,omitempty"`
}
type managementBound struct {
	Generation  uint64 `json:"generation"`
	Fingerprint string `json:"fingerprint"`
}
type managementRecord struct {
	Kind            string `json:"kind"`
	ID              string `json:"id"`
	EnvironmentID   string `json:"environmentId"`
	SubjectDeviceID string `json:"subjectDeviceId"`
	Packet          []byte `json:"packet"`
	ContentHash     string `json:"contentHash"`
	Attempted       bool   `json:"attempted"`
	Sequence        uint64 `json:"sequence,omitempty"`
}
type managementState struct {
	Pending *managementRecord                     `json:"pending,omitempty"`
	History map[string]ManagementResult           `json:"history"`
	Highest map[string]map[string]managementBound `json:"highest"`
}

func (w *Workflow) managementState() *managementState {
	if w.state.Management == nil {
		w.state.Management = &managementState{History: map[string]ManagementResult{}, Highest: map[string]map[string]managementBound{}}
	}
	return w.state.Management
}
func (w *Workflow) managementPending() bool {
	return w.state.Management != nil && w.state.Management.Pending != nil
}
func (w *Workflow) managementBase() error {
	if e := w.checkWithoutManagement(); e != nil {
		return e
	}
	if w.state.Root == nil {
		return ErrNotTrusted
	}
	if w.engine.State().Paused {
		return syncclient.ErrPaused
	}
	return nil
}
func (w *Workflow) managementRecordClient() (*syncclient.Client, *syncclient.PinnedVerifier, error) {
	v, e := w.originVerifier()
	if e != nil {
		return nil, nil, e
	}
	generation, e := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if e != nil {
		v.Close()
		return nil, nil, ErrNotTrusted
	}
	c, e := syncclient.NewForBoot(syncclient.Config{Endpoint: w.state.Endpoint, HTTPClient: w.http, AccountID: w.state.AccountID, AccountGeneration: generation, DeviceID: w.state.DeviceID, Engine: w.engine, Verifier: v, Now: w.now})
	if e != nil {
		v.Close()
		return nil, nil, e
	}
	return c, v, nil
}
func (w *Workflow) validateManagementState() error {
	s := w.state.Management
	if s == nil {
		return nil
	}
	if w.state.Root == nil || s.History == nil || s.Highest == nil || len(s.History) > 256 || len(s.Highest) > 256 {
		return ErrManagementConflict
	}
	count := 0
	for env, subjects := range s.Highest {
		if !identifier.MatchString(env) || len(subjects) > 256 {
			return ErrManagementConflict
		}
		for id, b := range subjects {
			count++
			if !identifier.MatchString(id) || b.Generation == 0 || !managementHash(b.Fingerprint) {
				return ErrManagementConflict
			}
		}
	}
	if count > 4096 {
		return ErrManagementLimit
	}
	for id, result := range s.History {
		if !identifier.MatchString(id) || len(id) > 64 || result.ID != id || result.AcceptanceUnknown || !result.Canceled && (!result.Accepted || !result.Applied || result.Sequence == 0) || result.Canceled && (result.Accepted || result.Applied || result.Sequence != 0) || result.Sequence > 9007199254740991 {
			return ErrManagementConflict
		}
	}
	r := s.Pending
	if r == nil {
		return nil
	}
	if len(s.History) >= 256 || s.History[r.ID].ID != "" || !identifier.MatchString(r.ID) || len(r.ID) > 64 || len(r.Packet) == 0 || len(r.Packet) > 2<<20 || !managementHash(r.ContentHash) || r.Sequence > 9007199254740991 || r.Sequence > 0 && !r.Attempted || len(w.state.SelfRevocation) > 0 || w.enrollmentPending() || w.approvalV5Pending() {
		return ErrManagementConflict
	}
	c, v, e := w.managementRecordClient()
	if e != nil {
		return e
	}
	defer v.Close()
	switch r.Kind {
	case "grant":
		t, e := c.RestoreGrantUpdate(r.Packet)
		if e != nil {
			return e
		}
		in := t.Intent()
		hash, e := t.ContentHash()
		if e != nil || t.ID() != r.ID || in.EnvironmentID != r.EnvironmentID || in.SubjectDeviceID != r.SubjectDeviceID || hash != r.ContentHash {
			return ErrManagementConflict
		}
		return nil
	case "revoke":
		t, e := c.RestoreOtherRevocation(r.Packet)
		if e != nil {
			return e
		}
		hash, e := t.ContentHash()
		if e != nil || t.ID() != r.ID || t.SubjectDeviceID() != r.SubjectDeviceID || t.ControlCheckpoint().EnvironmentID != r.EnvironmentID || hash != r.ContentHash {
			return ErrManagementConflict
		}
		return nil
	default:
		return ErrManagementConflict
	}
}
func managementHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (w *Workflow) checkManagementBounds(c syncclient.ManagementControl) error {
	if w.state.Management == nil {
		return nil
	}
	for _, row := range c.Subjects {
		bound := w.state.Management.Highest[c.EnvironmentID][row.DeviceID]
		gg, e := strconv.ParseUint(row.HighestGrantGeneration, 10, 64)
		if e != nil || gg < bound.Generation {
			return ErrManagementConflict
		}
		if gg == bound.Generation && gg != 0 {
			if row.CurrentGrant == nil {
				return ErrManagementConflict
			}
			hash, e := syncclient.GrantContentHash(*row.CurrentGrant)
			if e != nil || hash != bound.Fingerprint {
				return ErrManagementConflict
			}
		}
	}
	return nil
}
func (w *Workflow) rememberManagementControl(c syncclient.ManagementControl) error {
	if e := w.checkManagementBounds(c); e != nil {
		return e
	}
	s := w.managementState()
	candidate := clone(s.Highest)
	if candidate[c.EnvironmentID] == nil {
		if len(candidate) >= 256 {
			return ErrManagementLimit
		}
		candidate[c.EnvironmentID] = map[string]managementBound{}
	}
	for _, row := range c.Subjects {
		if row.CurrentGrant == nil {
			continue
		}
		gg, e := strconv.ParseUint(row.HighestGrantGeneration, 10, 64)
		if e != nil {
			return e
		}
		hash, e := syncclient.GrantContentHash(*row.CurrentGrant)
		if e != nil {
			return e
		}
		candidate[c.EnvironmentID][row.DeviceID] = managementBound{gg, hash}
	}
	count := 0
	for _, rows := range candidate {
		count += len(rows)
	}
	if count > 4096 {
		return ErrManagementLimit
	}
	s.Highest = candidate
	return nil
}

// ManagementDevices 仅返回管理元数据；公钥与封套仍在原生验证层。
func (w *Workflow) ManagementDevices(ctx context.Context, env string) (_ []ManagementDevice, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() { err = w.managementFault(err) }()
	if e := w.check(); e != nil {
		return nil, e
	}
	if e := w.managementBase(); e != nil {
		return nil, e
	}
	if e := w.refresh(ctx); e != nil {
		return nil, e
	}
	c, e := w.client.ManagementControl(ctx, env)
	if e != nil {
		return nil, e
	}
	if e = w.rememberManagementControl(c); e != nil {
		return nil, e
	}
	if e = w.persist(); e != nil {
		return nil, e
	}
	out := make([]ManagementDevice, 0, len(c.Subjects))
	for _, s := range c.Subjects {
		row := ManagementDevice{DeviceID: s.DeviceID, Role: "ungranted", GrantGeneration: s.HighestGrantGeneration}
		if s.CurrentGrant != nil {
			g := s.CurrentGrant.Grant
			row.Role = g.Role
			row.KeyVersion = g.KeyVersion
			row.ExpiresAt, _ = strconv.ParseInt(g.ExpiresAt, 10, 64)
		}
		out = append(out, row)
	}
	return out, nil
}
func (w *Workflow) managementUnusedID(id string) error {
	if !identifier.MatchString(id) || len(id) > 64 {
		return cryptox.ErrInvalidWire
	}
	s := w.managementState()
	if s.Pending != nil {
		return ErrManagementPending
	}
	if s.History[id].ID != "" {
		return ErrManagementConflict
	}
	if len(s.History) >= 256 {
		return ErrManagementLimit
	}
	return nil
}

// PrepareDeviceGrant 保存一个不可变签包；尚未调用 /grants。输入不含目录公钥或封套。
func (w *Workflow) PrepareDeviceGrant(ctx context.Context, in syncclient.GrantUpdateIntent) (_ ManagementInfo, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() { err = w.managementFault(err) }()
	if e := w.check(); e != nil {
		return ManagementInfo{}, e
	}
	if e := w.managementBase(); e != nil {
		return ManagementInfo{}, e
	}
	if e := w.managementUnusedID(in.ID); e != nil {
		return ManagementInfo{}, e
	}
	if e := w.refresh(ctx); e != nil {
		return ManagementInfo{}, e
	}
	t, e := w.client.PrepareGrantUpdate(ctx, in, w.signing)
	if e != nil {
		return ManagementInfo{}, e
	}
	if e = w.rememberManagementControl(t.ControlCheckpoint()); e != nil {
		return ManagementInfo{}, e
	}
	packet, e := t.ProtectedBytes()
	if e != nil {
		return ManagementInfo{}, e
	}
	hash, e := t.ContentHash()
	if e != nil {
		return ManagementInfo{}, e
	}
	w.state.Management.Pending = &managementRecord{Kind: "grant", ID: in.ID, EnvironmentID: in.EnvironmentID, SubjectDeviceID: in.SubjectDeviceID, Packet: packet, ContentHash: hash}
	if e = w.persist(); e != nil {
		return ManagementInfo{}, e
	}
	return w.managementInfo(), nil
}

// PrepareOtherDeviceRevocation 只撤销已验身份图中另一个设备；服务器另检查全环境 Admin。
func (w *Workflow) PrepareOtherDeviceRevocation(ctx context.Context, id, subject, environment string) (_ ManagementInfo, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() { err = w.managementFault(err) }()
	if e := w.check(); e != nil {
		return ManagementInfo{}, e
	}
	if e := w.managementBase(); e != nil {
		return ManagementInfo{}, e
	}
	if e := w.managementUnusedID(id); e != nil {
		return ManagementInfo{}, e
	}
	if e := w.refresh(ctx); e != nil {
		return ManagementInfo{}, e
	}
	t, e := w.client.PrepareOtherRevocation(ctx, id, subject, environment, w.signing)
	if e != nil {
		return ManagementInfo{}, e
	}
	if e = w.rememberManagementControl(t.ControlCheckpoint()); e != nil {
		return ManagementInfo{}, e
	}
	packet, e := t.ProtectedBytes()
	if e != nil {
		return ManagementInfo{}, e
	}
	hash, e := t.ContentHash()
	if e != nil {
		return ManagementInfo{}, e
	}
	w.state.Management.Pending = &managementRecord{Kind: "revoke", ID: id, EnvironmentID: environment, SubjectDeviceID: subject, Packet: packet, ContentHash: hash}
	if e = w.persist(); e != nil {
		return ManagementInfo{}, e
	}
	return w.managementInfo(), nil
}
func (w *Workflow) managementInfo() ManagementInfo {
	if !w.managementPending() {
		return ManagementInfo{State: "none"}
	}
	r := w.state.Management.Pending
	state := "prepared"
	if r.Attempted {
		state = "pending"
	}
	if r.Sequence > 0 {
		state = "accepted-not-applied"
	}
	out := ManagementInfo{State: state, ID: r.ID, Kind: r.Kind, EnvironmentID: r.EnvironmentID, SubjectDeviceID: r.SubjectDeviceID, Attempted: r.Attempted, Sequence: r.Sequence}
	if r.Kind == "revoke" {
		var data struct {
			Wire struct {
				Signed cryptox.SignedDeviceRevocation `json:"signed"`
			} `json:"wire"`
		}
		_ = json.Unmarshal(r.Packet, &data)
		out.ExpiresAt, _ = strconv.ParseInt(data.Wire.Signed.Revocation.ExpiresAt, 10, 64)
	}
	return out
}
func (w *Workflow) ManagementInfo() (ManagementInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ManagementInfo{}, ErrClosed
	}
	return w.managementInfo(), nil
}
func (w *Workflow) CancelManagement(id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if e := w.checkWithoutManagement(); e != nil {
		return e
	}
	if !w.managementPending() || w.state.Management.Pending.ID != id {
		if w.state.Management != nil && w.state.Management.History[id].Canceled {
			return w.persist()
		}
		return ErrManagementConflict
	}
	if w.state.Management.Pending.Attempted {
		return ErrManagementPending
	}
	s := w.state.Management
	clear(s.Pending.Packet)
	s.Pending = nil
	s.History[id] = ManagementResult{ID: id, Canceled: true}
	return w.persist()
}

// RetryManagement 从原密封请求恢复，先查精确接受回执；未知结果从不隐式换 ID 或签包。
func (w *Workflow) RetryManagement(ctx context.Context, id string) (_ ManagementResult, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() { err = w.managementFault(err) }()
	if e := w.checkWithoutManagement(); e != nil {
		return ManagementResult{}, e
	}
	if !w.managementPending() {
		if w.state.Management != nil {
			if done, ok := w.state.Management.History[id]; ok {
				if e := w.persist(); e != nil {
					done.Applied = false
					return done, errors.Join(syncclient.ErrAcceptedNotApplied, e)
				}
				return done, nil
			}
		}
		return ManagementResult{}, ErrManagementConflict
	}
	r := w.state.Management.Pending
	out := ManagementResult{ID: id, AcceptanceUnknown: r.Attempted}
	if r.ID != id {
		return out, ErrManagementConflict
	}
	if e := w.managementBase(); e != nil {
		return out, e
	}
	if e := w.refreshForApproval(ctx); e != nil {
		return out, e
	}
	barrier := func() error {
		was := r.Attempted
		r.Attempted = true
		if e := w.persist(); e != nil {
			r.Attempted = was
			return e
		}
		return nil
	}
	var status syncclient.GrantStatus
	var submit func(context.Context) (syncclient.Acceptance, error)
	var confirm func(context.Context, syncclient.Acceptance) (syncclient.SubmitResult, error)
	switch r.Kind {
	case "grant":
		t, e := w.client.RestoreGrantUpdate(r.Packet)
		if e != nil {
			return out, e
		}
		status, e = t.Status(ctx)
		if e != nil {
			return out, e
		}
		submit = func(ctx context.Context) (syncclient.Acceptance, error) { return t.SubmitWithBarrier(ctx, barrier) }
		confirm = t.Confirm
	case "revoke":
		t, e := w.client.RestoreOtherRevocation(r.Packet)
		if e != nil {
			return out, e
		}
		t.DiscardExpiredToken()
		r.Packet, e = t.ProtectedBytes()
		if e != nil {
			return out, e
		}
		if e = w.persist(); e != nil {
			return out, e
		}
		status, e = t.StatusThrough(ctx, w.client)
		if e != nil {
			return out, e
		}
		submit = func(ctx context.Context) (syncclient.Acceptance, error) { return t.SubmitWithBarrier(ctx, barrier) }
		confirm = func(ctx context.Context, a syncclient.Acceptance) (syncclient.SubmitResult, error) {
			return t.ConfirmThrough(ctx, w.client, a)
		}
	default:
		return out, ErrManagementConflict
	}
	if r.Sequence > 0 && (!status.Accepted || status.Sequence != r.Sequence) {
		return out, ErrManagementConflict
	}
	if status.Accepted {
		r.Sequence = status.Sequence
	} else {
		accepted, e := submit(ctx)
		out.AcceptanceUnknown = r.Attempted
		if e != nil {
			if r.Attempted {
				return out, errors.Join(ErrManagementPending, e)
			}
			return out, e
		}
		r.Sequence = accepted.Sequence
	}
	out.Accepted = true
	out.Sequence = r.Sequence
	out.AcceptanceUnknown = false
	if e := w.persist(); e != nil {
		return out, e
	}
	result, e := confirm(ctx, syncclient.Acceptance{Sequence: r.Sequence})
	if e != nil {
		return out, errors.Join(syncclient.ErrAcceptedNotApplied, e)
	}
	if !result.Applied {
		return out, syncclient.ErrAcceptedNotApplied
	}
	if e = w.refreshForApproval(ctx); e != nil {
		return out, errors.Join(syncclient.ErrAcceptedNotApplied, e)
	}
	// 能继续管理时保存签目录的新代际下界；自降权后仅原回执和 own signed pull 确认，不猜目标当前值。
	control, e := w.client.ManagementControl(ctx, r.EnvironmentID)
	if e == nil {
		if e = w.rememberManagementControl(control); e != nil {
			return out, e
		}
	} else {
		var fault *syncclient.RequestError
		current, exists := w.engine.State().Cloud.Environments[r.EnvironmentID]
		if errors.Is(e, syncclient.ErrTrustInvalidated) {
			return out, e
		}
		if !errors.As(e, &fault) || fault.Status != 403 || fault.Code != "admin_required" || exists && current.Role == localstate.Admin {
			return out, errors.Join(syncclient.ErrAcceptedNotApplied, e)
		}
	}
	out.Applied = true
	s := w.state.Management
	clear(r.Packet)
	s.Pending = nil
	s.History[id] = out
	if e = w.persist(); e != nil {
		out.Applied = false
		return out, errors.Join(syncclient.ErrAcceptedNotApplied, e)
	}
	return out, nil
}

// 授权失效可能发生在refresh之后的状态查询或POST中，必须同样清原生持久上下文。
func (w *Workflow) managementFault(err error) error {
	if errors.Is(err, syncclient.ErrTrustInvalidated) && !w.closed {
		return errors.Join(err, w.invalidateTrust())
	}
	return err
}
