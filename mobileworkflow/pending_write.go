package mobileworkflow

import (
	"context"
	"errors"
	"sort"

	"github.com/harmonia-vault/core-go/syncclient"
)

// PendingBusinessInfo 是已保护原事务的有限元数据。Sequence 为最后已知接受序号，
// 只有 Applied 且本次调用无错误才表示同一验签下发及原生保存完成。
type PendingBusinessInfo struct {
	ID            string `json:"id"`
	Operation     string `json:"operation"`
	EnvironmentID string `json:"environmentId"`
	State         string `json:"state"`
	Sequence      uint64 `json:"sequence"`
	Applied       bool   `json:"applied"`
}

func writeBusinessInfo(r syncclient.WriteOperationInfo) PendingBusinessInfo {
	info := PendingBusinessInfo{ID: r.RequestID, Operation: r.Operation, EnvironmentID: r.EnvironmentID, State: "unknown", Applied: r.Applied}
	for _, sequence := range r.Sequences {
		if sequence > info.Sequence {
			info.Sequence = sequence
		}
	}
	if r.Canceled {
		info.State = "canceled"
		info.Applied = false
	} else if r.Applied {
		info.State = "applied"
	} else if r.Total > 0 && r.Accepted == r.Total {
		info.State = "accepted-not-applied"
	}
	return info
}
func environmentBusinessInfo(id string, r *environmentRecord) PendingBusinessInfo {
	info := PendingBusinessInfo{ID: id, Operation: r.Signed.Change.Operation, EnvironmentID: r.Signed.Change.EnvironmentID, State: "unknown", Sequence: r.Sequence, Applied: r.Applied}
	if r.Applied {
		info.State = "applied"
	} else if r.Sequence > 0 {
		info.State = "accepted-not-applied"
	}
	return info
}
func pendingBusinessFailure(info PendingBusinessInfo) PendingBusinessInfo {
	info.Applied = false
	if info.State != "canceled" {
		info.State = "unknown"
		if info.Sequence > 0 {
			info.State = "accepted-not-applied"
		}
	}
	return info
}

// PendingBusinessOperations 不联网，不能返回变量名、值、密文、签包或会话。
// 已取消项只有原ID墓碑，不提供重新提交资格。
func (w *Workflow) PendingBusinessOperations() ([]PendingBusinessInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return nil, err
	}
	if w.state.Root == nil {
		return nil, ErrNotTrusted
	}
	if err := w.ensureWriter(); err != nil {
		return nil, err
	}
	writes, err := w.writer.PendingRequests()
	if err != nil {
		return nil, err
	}
	if len(writes) > 32 || len(w.state.EnvironmentWrites) > 32 {
		return nil, syncclient.ErrWriteJournal
	}
	out := make([]PendingBusinessInfo, 0, len(writes)+len(w.state.EnvironmentWrites))
	for _, r := range writes {
		if w.state.EnvironmentWrites[r.RequestID] != nil {
			return nil, syncclient.ErrWriteConflict
		}
		out = append(out, writeBusinessInfo(r))
	}
	for id, r := range w.state.EnvironmentWrites {
		if !r.Applied {
			if _, err := w.writer.OperationInfo(id); err == nil {
				return nil, syncclient.ErrWriteConflict
			} else if !errors.Is(err, syncclient.ErrWriteConflict) {
				return nil, err
			}
			out = append(out, environmentBusinessInfo(id, r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// RetryBusinessOperationByID 只取本机原密封请求；Dart 不得提供新值或替代原签包。
// Writer 的 retry 请求除原ID与Operation外所有字段均为空。
func (w *Workflow) RetryBusinessOperationByID(ctx context.Context, id string) (PendingBusinessInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return PendingBusinessInfo{}, err
	}
	if w.state.Root == nil {
		return PendingBusinessInfo{}, ErrNotTrusted
	}
	if err := syncclient.ValidateWriteRequest(syncclient.WriteRequest{ID: id, Operation: "retry"}); err != nil {
		return PendingBusinessInfo{}, err
	}
	if err := w.ensureWriter(); err != nil {
		return PendingBusinessInfo{}, err
	}
	write, writeErr := w.writer.OperationInfo(id)
	if writeErr != nil && !errors.Is(writeErr, syncclient.ErrWriteConflict) {
		return PendingBusinessInfo{}, writeErr
	}
	env := w.state.EnvironmentWrites[id]
	if writeErr == nil && env != nil {
		return PendingBusinessInfo{}, syncclient.ErrWriteConflict
	}
	if writeErr != nil && env == nil {
		return PendingBusinessInfo{}, syncclient.ErrWriteConflict
	}
	var info PendingBusinessInfo
	if env != nil {
		info = environmentBusinessInfo(id, env)
	} else {
		info = writeBusinessInfo(write)
	}
	if err := w.refresh(ctx); err != nil {
		return pendingBusinessFailure(info), err
	}
	if env != nil {
		err := w.submitRecord(ctx, env)
		info = environmentBusinessInfo(id, env)
		if err != nil {
			return pendingBusinessFailure(info), w.businessWriteError(ctx, err)
		}
		return info, nil
	}
	_, err := w.writer.Execute(ctx, w.client, syncclient.WriteRequest{ID: id, Operation: "retry"})
	if current, currentErr := w.writer.OperationInfo(id); currentErr == nil {
		info = writeBusinessInfo(current)
	} else {
		err = errors.Join(err, currentErr)
	}
	if err != nil {
		return pendingBusinessFailure(info), w.businessWriteError(ctx, err)
	}
	if err = w.persist(); err != nil {
		return pendingBusinessFailure(info), err
	}
	return info, nil
}
func (w *Workflow) businessWriteError(ctx context.Context, err error) error {
	var fault *syncclient.RequestError
	if errors.As(err, &fault) && fault.Status == 401 && fault.Code == "unauthorized" {
		err = errors.Join(err, w.boot(ctx))
	}
	if errors.Is(err, syncclient.ErrTrustInvalidated) {
		return errors.Join(err, w.invalidateTrust())
	}
	return err
}
