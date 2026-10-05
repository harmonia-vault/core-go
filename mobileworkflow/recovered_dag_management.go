package mobileworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

// 每环境原授权包的独立业务journal。普通Management和恢复checkedjournal都不复用。
type dagManagementJournal struct {
	Version        int                        `json:"version"`
	Profile        string                     `json:"profile"`
	EnrollmentID   string                     `json:"enrollmentId"`
	EnrollmentHash string                     `json:"enrollmentHash"`
	Records        map[string]*dagGrantRecord `json:"records"`
}
type dagGrantRecord struct {
	Packet      []byte `json:"packet"`
	ContentHash string `json:"contentHash"`
	Attempted   bool   `json:"attempted"`
	Sequence    uint64 `json:"sequence"`
	Applied     bool   `json:"applied"`
	Canceled    bool   `json:"canceled"`
}

func (r *dagManagementJournal) UnmarshalJSON(raw []byte) error {
	if exactDAGObject(raw, "version", "profile", "enrollmentId", "enrollmentHash", "records") != nil {
		return ErrDAGProtectedState
	}
	type plain dagManagementJournal
	var out plain
	if decode(raw, &out) != nil {
		return ErrDAGProtectedState
	}
	*r = dagManagementJournal(out)
	return nil
}
func (r *dagGrantRecord) UnmarshalJSON(raw []byte) error {
	if exactDAGObject(raw, "packet", "contentHash", "attempted", "sequence", "applied", "canceled") != nil {
		return ErrDAGProtectedState
	}
	type plain dagGrantRecord
	var out plain
	if decode(raw, &out) != nil {
		return ErrDAGProtectedState
	}
	*r = dagGrantRecord(out)
	return nil
}

type DAGManagementInfo struct {
	State           string `json:"state"`
	RequestID       string `json:"requestId"`
	EnvironmentID   string `json:"environmentId"`
	SubjectDeviceID string `json:"subjectDeviceId"`
	Role            string `json:"role"`
	ExpiresAt       int64  `json:"expiresAt"`
	Attempted       bool   `json:"attempted"`
	Sequence        uint64 `json:"sequence"`
	Applied         bool   `json:"applied"`
	Canceled        bool   `json:"canceled"`
}
type DAGManagementResult struct {
	Management DAGManagementInfo
	Devices    []ManagementDevice
	View       *DAGRecoveredView
}

func (w *Workflow) dagManagementPending() bool {
	if j := w.state.DAGManagement; j != nil {
		for _, r := range j.Records {
			if r != nil && !r.Applied && !r.Canceled {
				return true
			}
		}
	}
	return false
}
func (w *Workflow) dagOtherBusinessPending() (bool, error) {
	if w.approvalV5Pending() {
		return true, nil
	}
	return w.dagDataPending()
}
func (w *Workflow) dagDataPending() (bool, error) {
	if j := w.state.DAGEnvironments; j != nil {
		for _, r := range j.Records {
			if r != nil && !r.Applied {
				return true, nil
			}
		}
	}
	if j := w.state.DAGWrites; j != nil {
		p, e := w.recoveredDAGOriginalLocked(w.state.RecoveredDAGDevice.Original)
		if e != nil {
			return false, e
		}
		writer, e := syncclient.NewWriter(w.state.AccountID, p.AccountGeneration, w.state.DeviceID, w.engine.State().SessionEpoch, w.signing, dagReadonlyWriteLog{j.Log})
		if e != nil {
			return false, e
		}
		defer writer.Close()
		rows, e := writer.PendingRequests()
		if e != nil {
			return false, e
		}
		for _, r := range rows {
			if !r.Canceled {
				return true, nil
			}
		}
	}
	return false, nil
}
func (w *Workflow) validateDAGManagementLocked() error {
	j := w.state.DAGManagement
	if j == nil {
		return nil
	}
	if w.state.RecoveredDAGDevice == nil || j.Version != 1 || j.Profile != cryptox.RecoveryDAGCapability || j.Records == nil || len(j.Records) == 0 || len(j.Records) > 32 || w.state.DAGEnvironments == nil {
		return ErrDAGProtectedState
	}
	raw, e := json.Marshal(j)
	if e != nil || len(raw) > 8<<20 {
		return ErrDAGProtectedState
	}
	p, e := w.recoveredDAGOriginalLocked(w.state.RecoveredDAGDevice.Original)
	if e != nil || j.EnrollmentID != p.OperationID || j.EnrollmentHash != p.ContentHash {
		return ErrDAGProtectedState
	}
	c, close, e := w.dagEnvironmentHistoryClient()
	if e != nil {
		return e
	}
	defer close()
	if _, e = w.verifyDAGReceiverHistory(c); e != nil {
		return e
	}
	active := 0
	acceptedSequences := map[uint64]bool{}
	for id, r := range j.Records {
		if r == nil || !identifier.MatchString(id) || len(id) > 64 || !validDAGDigest(r.ContentHash) || len(r.Packet) == 0 || len(r.Packet) > 2<<20 || r.Sequence > 9007199254740991 || r.Sequence > 0 && !r.Attempted || r.Applied && (r.Sequence == 0 || !r.Attempted || r.Canceled) || r.Canceled && (r.Attempted || r.Sequence > 0 || r.Applied) || r.Applied && w.engine.State().Cloud.Sequence < r.Sequence {
			return ErrDAGProtectedState
		}
		t, e := c.RestoreGrantUpdate(r.Packet)
		if e != nil {
			return e
		}
		hash, e := t.ContentHash()
		if e != nil || t.ID() != id || hash != r.ContentHash {
			return ErrDAGProtectedState
		}
		found := false
		for _, control := range w.state.DAGEnvironments.ReceiverControls {
			if sameJSONValue(control, t.ControlCheckpoint()) {
				found = true
				break
			}
		}
		if !found {
			return ErrDAGProtectedState
		}
		if r.Sequence > 0 {
			if r.Sequence <= t.ControlCheckpoint().Sequence || acceptedSequences[r.Sequence] {
				return ErrDAGProtectedState
			}
			acceptedSequences[r.Sequence] = true
		}
		if !r.Applied && !r.Canceled {
			active++
		}
	}
	if active > 1 {
		return ErrManagementPending
	}
	if active > 0 {
		pending, e := w.dagOtherBusinessPending()
		if e != nil {
			return e
		}
		if pending {
			return ErrManagementPending
		}
	}
	return nil
}
func dagGrantInfo(t *syncclient.GrantUpdateTransaction, r *dagGrantRecord) DAGManagementInfo {
	in := t.Intent()
	state := "prepared"
	if r.Attempted {
		state = "pending"
	}
	if r.Sequence > 0 {
		state = "accepted-not-applied"
	}
	if r.Applied {
		state = "applied"
	}
	if r.Canceled {
		state = "canceled"
	}
	return DAGManagementInfo{State: state, RequestID: in.ID, EnvironmentID: in.EnvironmentID, SubjectDeviceID: in.SubjectDeviceID, Role: in.Role, ExpiresAt: in.ExpiresAt, Attempted: r.Attempted, Sequence: r.Sequence, Applied: r.Applied, Canceled: r.Canceled}
}
func (w *Workflow) dagManagementInfoLocked(id string) (DAGManagementInfo, error) {
	j := w.state.DAGManagement
	if j == nil {
		if id != "" {
			return DAGManagementInfo{}, ErrManagementConflict
		}
		return DAGManagementInfo{State: "none"}, nil
	}
	var r *dagGrantRecord
	if id != "" {
		r = j.Records[id]
		if r == nil {
			return DAGManagementInfo{}, ErrManagementConflict
		}
	} else {
		for _, row := range j.Records {
			if !row.Applied && !row.Canceled {
				r = row
				break
			}
		}
	}
	if r == nil {
		return DAGManagementInfo{State: "none"}, nil
	}
	c, close, e := w.dagEnvironmentHistoryClient()
	if e != nil {
		return DAGManagementInfo{}, e
	}
	defer close()
	t, e := c.RestoreGrantUpdate(r.Packet)
	if e != nil {
		return DAGManagementInfo{}, e
	}
	return dagGrantInfo(t, r), nil
}
func (w *Workflow) DAGManagementInfo() (DAGManagementInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dagDeviceCancel != nil || w.dagOwnerCancel != nil || w.dagQueryCancel != nil {
		return DAGManagementInfo{}, ErrDAGQueryBusy
	}
	if w.state.RecoveredDAGDevice == nil {
		return DAGManagementInfo{}, ErrNotTrusted
	}
	if e := w.validateRecoveredDAGDeviceLocked(); e != nil {
		return DAGManagementInfo{}, e
	}
	return w.dagManagementInfoLocked("")
}

func (w *Workflow) commitDAGManagementControl(control syncclient.ManagementControl, commit *dagActiveWriteLog) error {
	if w.state.DAGEnvironments == nil {
		p, e := w.recoveredDAGOriginalLocked(w.state.RecoveredDAGDevice.Original)
		if e != nil {
			return e
		}
		w.state.DAGEnvironments = &dagEnvironmentJournal{Version: 1, Profile: cryptox.RecoveryDAGCapability, EnrollmentID: p.OperationID, EnrollmentHash: p.ContentHash, Records: map[string]*dagEnvironmentRecord{}, ReceiverControls: []syncclient.ManagementControl{}}
	}
	return w.commitDAGReceiverControl(control, commit)
}
func (w *Workflow) DAGManagementDevices(ctx context.Context, env string) ([]ManagementDevice, error) {
	if !identifier.MatchString(env) || len(env) > 64 {
		return nil, cryptox.ErrInvalidWire
	}
	out, e := w.runDAGManagement(ctx, func(c *Workflow, j *dagActiveWriteLog) (DAGManagementResult, error) {
		control, e := c.client.ManagementControl(j.ctx, env)
		if e != nil {
			return DAGManagementResult{}, e
		}
		if e = c.commitDAGManagementControl(control, j); e != nil {
			return DAGManagementResult{}, e
		}
		rows := make([]ManagementDevice, 0, len(control.Subjects))
		for _, s := range control.Subjects {
			row := ManagementDevice{DeviceID: s.DeviceID, Role: "ungranted", GrantGeneration: s.HighestGrantGeneration}
			if s.CurrentGrant != nil {
				g := s.CurrentGrant.Grant
				row.Role = g.Role
				row.KeyVersion = g.KeyVersion
				row.ExpiresAt, _ = strconv.ParseInt(g.ExpiresAt, 10, 64)
			}
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].DeviceID < rows[j].DeviceID })
		return DAGManagementResult{Devices: rows}, nil
	})
	return out.Devices, e
}
func (w *Workflow) PrepareDAGDeviceGrant(ctx context.Context, in syncclient.GrantUpdateIntent) (DAGManagementInfo, error) {
	out, e := w.runDAGManagement(ctx, func(c *Workflow, j *dagActiveWriteLog) (DAGManagementResult, error) {
		if !identifier.MatchString(in.ID) || len(in.ID) > 64 {
			return DAGManagementResult{}, cryptox.ErrInvalidWire
		}
		journal := c.state.DAGManagement
		if journal != nil {
			if r := journal.Records[in.ID]; r != nil {
				t, e := c.client.RestoreGrantUpdate(r.Packet)
				if e != nil {
					return DAGManagementResult{}, e
				}
				if r.Canceled || r.Applied || !sameJSONValue(t.Intent(), in) {
					return DAGManagementResult{}, ErrManagementConflict
				}
				return DAGManagementResult{Management: dagGrantInfo(t, r)}, nil
			}
		}
		if c.dagManagementPending() {
			return DAGManagementResult{}, ErrManagementPending
		}
		if journal != nil && len(journal.Records) >= 32 {
			return DAGManagementResult{}, ErrManagementLimit
		}
		t, e := c.client.PrepareDAGGrantUpdate(j.ctx, in, c.signing, func(control syncclient.ManagementControl) error { return c.commitDAGManagementControl(control, j) })
		if e != nil {
			return DAGManagementResult{}, e
		}
		packet, e := t.ProtectedBytes()
		if e != nil {
			return DAGManagementResult{}, e
		}
		hash, e := t.ContentHash()
		if e != nil {
			return DAGManagementResult{}, e
		}
		if journal == nil {
			p, e := c.recoveredDAGOriginalLocked(c.state.RecoveredDAGDevice.Original)
			if e != nil {
				return DAGManagementResult{}, e
			}
			journal = &dagManagementJournal{Version: 1, Profile: cryptox.RecoveryDAGCapability, EnrollmentID: p.OperationID, EnrollmentHash: p.ContentHash, Records: map[string]*dagGrantRecord{}}
			c.state.DAGManagement = journal
		}
		r := &dagGrantRecord{Packet: packet, ContentHash: hash}
		journal.Records[in.ID] = r
		if e = j.commitCandidate(); e != nil {
			return DAGManagementResult{}, e
		}
		return DAGManagementResult{Management: dagGrantInfo(t, r)}, nil
	})
	return out.Management, e
}

func (w *Workflow) CancelDAGManagement(id string) (DAGManagementInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !identifier.MatchString(id) || len(id) > 64 {
		return DAGManagementInfo{}, cryptox.ErrInvalidWire
	}
	if w.dagDeviceCancel != nil || w.dagOwnerCancel != nil || w.dagQueryCancel != nil {
		return DAGManagementInfo{}, ErrDAGQueryBusy
	}
	if w.state.RecoveredDAGDevice == nil {
		return DAGManagementInfo{}, ErrNotTrusted
	}
	if e := w.validateRecoveredDAGDeviceLocked(); e != nil {
		return DAGManagementInfo{}, e
	}
	if w.state.DAGManagement == nil || w.state.DAGManagement.Records[id] == nil {
		return DAGManagementInfo{}, ErrManagementConflict
	}
	r := w.state.DAGManagement.Records[id]
	if r.Applied || r.Attempted {
		return DAGManagementInfo{}, ErrManagementPending
	}
	if !r.Canceled {
		candidate := clone(w.state)
		candidate.DAGManagement.Records[id].Canceled = true
		if e := w.saveDAGCandidateLocked(candidate); e != nil {
			return DAGManagementInfo{}, e
		}
	}
	return w.dagManagementInfoLocked(id)
}
func (w *Workflow) RetryDAGManagement(ctx context.Context, id string) (DAGManagementResult, error) {
	if !identifier.MatchString(id) || len(id) > 64 {
		return DAGManagementResult{}, cryptox.ErrInvalidWire
	}
	return w.runDAGManagement(ctx, func(c *Workflow, j *dagActiveWriteLog) (out DAGManagementResult, err error) {
		if c.state.DAGManagement == nil || c.state.DAGManagement.Records[id] == nil {
			return out, ErrManagementConflict
		}
		r := c.state.DAGManagement.Records[id]
		if r.Canceled {
			return out, ErrManagementConflict
		}
		t, e := c.client.RestoreGrantUpdate(r.Packet)
		if e != nil {
			return out, e
		}
		defer func() {
			out.Management = dagGrantInfo(t, r)
			if err != nil {
				out.Management.Applied = false
			}
		}()
		status, e := t.Status(j.ctx)
		if e != nil {
			return out, e
		}
		if r.Sequence > 0 && (!status.Accepted || r.Sequence != status.Sequence) {
			return out, ErrManagementConflict
		}
		if status.Accepted {
			r.Sequence = status.Sequence
			r.Attempted = true
		} else {
			accepted, e := t.SubmitDAGWithControlBarrier(j.ctx, func(control syncclient.ManagementControl) error { return c.commitDAGManagementControl(control, j) }, func() error { r.Attempted = true; return j.commitCandidate() })
			if e != nil {
				if r.Attempted {
					return out, errors.Join(ErrManagementPending, e)
				}
				return out, e
			}
			r.Sequence = accepted.Sequence
		}
		if e = j.commitCandidate(); e != nil {
			return out, errors.Join(syncclient.ErrAcceptedNotApplied, receiverPersistenceFailure(j, e))
		}
		result, e := t.Confirm(j.ctx, syncclient.Acceptance{Sequence: r.Sequence})
		if e != nil || !result.Applied {
			return out, errors.Join(syncclient.ErrAcceptedNotApplied, e)
		}
		control, e := c.client.ManagementControl(j.ctx, t.Intent().EnvironmentID)
		if e == nil {
			if e = c.commitDAGManagementControl(control, j); e != nil {
				return out, e
			}
		} else {
			current, exists := c.engine.State().Cloud.Environments[t.Intent().EnvironmentID]
			if errors.Is(e, syncclient.ErrTrustInvalidated) {
				return out, e
			}
			if !dagSelfDowngradeReceiptException(t.Intent(), c.state.DeviceID, current, exists, e) {
				return out, errors.Join(syncclient.ErrAcceptedNotApplied, e)
			}
		}
		r.Applied = true
		if e = j.commitCandidate(); e != nil {
			r.Applied = false
			return out, errors.Join(syncclient.ErrAcceptedNotApplied, e)
		}
		return out, nil
	})
}

// 与公开变量/环境runner同一captured来源和CAS规则；只此handle的有界网络。
func (w *Workflow) runDAGManagement(ctx context.Context, run func(*Workflow, *dagActiveWriteLog) (DAGManagementResult, error)) (out DAGManagementResult, err error) {
	w.mu.Lock()
	if w.state.RecoveredDAGDevice == nil {
		w.mu.Unlock()
		return out, ErrNotTrusted
	}
	if w.dagDeviceCancel != nil || w.dagOwnerCancel != nil || w.dagQueryCancel != nil {
		w.mu.Unlock()
		return out, ErrDAGQueryBusy
	}
	if e := w.validateRecoveredDAGDeviceLocked(); e != nil {
		w.mu.Unlock()
		return out, e
	}
	if w.engine.State().Paused {
		w.mu.Unlock()
		return out, syncclient.ErrPaused
	}
	if pending, e := w.dagOtherBusinessPending(); e != nil || pending {
		w.mu.Unlock()
		return out, errors.Join(ErrManagementPending, e)
	}
	p, e := w.recoveredDAGOriginalLocked(w.state.RecoveredDAGDevice.Original)
	if e != nil {
		w.mu.Unlock()
		return out, e
	}
	state, hash, epoch := clone(w.state), w.protectedSHA256, w.engine.State().SessionEpoch
	signing, receiving := bytes.Clone(w.signing), bytes.Clone(w.receiving)
	networkCtx, cancel := context.WithCancel(ctx)
	w.dagDeviceCancel = cancel
	candidate := &Workflow{state: state, signing: signing, receiving: receiving, http: w.http, now: w.now}
	w.mu.Unlock()
	commit := &dagActiveWriteLog{owner: w, candidate: candidate, ctx: networkCtx, hash: hash, epoch: epoch}
	defer func() {
		err = errors.Join(err, commit.terminalCause)
		cancel()
		clear(signing)
		clear(receiving)
		if candidate.verifier != nil {
			candidate.verifier.Close()
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		w.dagDeviceCancel = nil
		if (errors.Is(err, syncclient.ErrTrustInvalidated) || errors.Is(err, ErrDAGAuthorizationNotPersisted)) && !w.closed && w.engine != nil && w.protectedSHA256 == commit.hash && w.engine.State().SessionEpoch == epoch {
			err = errors.Join(err, w.engine.Logout(), w.invalidateTrust())
		}
		if err != nil {
			out.View = nil
			out.Management.Applied = false
		}
	}()
	candidate.store = &memoryStore{state: clone(state.Cloud)}
	candidate.engine, err = localstate.New(candidate.store)
	if err != nil {
		return out, err
	}
	candidate.verifier, err = candidate.recoveredDAGVerifierLocked()
	if err != nil {
		return out, err
	}
	boot, e := syncclient.NewForBoot(syncclient.Config{Endpoint: state.Endpoint, ProtocolMajor: 2, HTTPClient: candidate.http, AccountID: state.AccountID, AccountGeneration: p.AccountGeneration, DeviceID: state.DeviceID, Verifier: candidate.verifier, Engine: candidate.engine, Now: candidate.now})
	if e != nil {
		return out, e
	}
	candidate.client, err = boot.BootDevice(networkCtx, signing)
	if err != nil {
		return out, err
	}
	candidate.client, err = candidate.client.WithVerifiedPullCommit(networkCtx, commit.commitVerifiedPull)
	if err != nil {
		return out, err
	}
	if err = candidate.pullDAGBusiness(networkCtx); err != nil {
		return out, err
	}
	out, err = run(candidate, commit)
	if err != nil {
		return out, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.engine == nil || w.dagPersistenceFailed || w.protectedSHA256 != commit.hash || w.engine.State().SessionEpoch != epoch || networkCtx.Err() != nil {
		return out, ErrDAGProtectedState
	}
	if err = w.validateRecoveredDAGDeviceLocked(); err != nil {
		return out, err
	}
	if out.Management.Applied {
		view, e := w.dagRecoveredViewLocked()
		if e != nil {
			return out, e
		}
		out.View = &view
	}
	return out, nil
}

// 只能在成熟Confirm/Pull已经成功之后调用；不为他人的grant或其它403提供例外。
func dagSelfDowngradeReceiptException(in syncclient.GrantUpdateIntent, device string, current localstate.Environment, exists bool, err error) bool {
	var fault *syncclient.RequestError
	return in.SubjectDeviceID == device && !errors.Is(err, syncclient.ErrTrustInvalidated) && errors.As(err, &fault) && fault.Status == 403 && fault.Code == "admin_required" && (!exists || current.Role != localstate.Admin)
}
