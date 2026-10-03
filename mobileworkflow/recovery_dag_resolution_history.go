package mobileworkflow

import "github.com/harmonia-vault/core-go/syncclient"

func resolutionClosedCheckpoints(r *recoveryDAGResolutionState) []syncclient.DAGClosedOperationCheckpoint {
	if r == nil {
		return nil
	}
	out := make([]syncclient.DAGClosedOperationCheckpoint, len(r.Closed))
	for i, c := range r.Closed {
		out[i] = syncclient.DAGClosedOperationCheckpoint{OperationID: c.Target.OperationID, Sequence: c.Receipt.Sequence}
	}
	return out
}

// 所有完整DAG输入共用同一已保护下界；原包pin不能被closure或网络候选替换。
// 参数由持Workflow锁的调用者复制，返回值不引用live状态。
func withDAGResolutionHistory(c syncclient.DAGRecoveryConfig, r *recoveryDAGResolutionState) (syncclient.DAGRecoveryConfig, error) {
	if r == nil {
		return c, nil
	}
	copy := clone(*r)
	if c.Pin != nil && *c.Pin != copy.Baseline.Pin {
		return syncclient.DAGRecoveryConfig{}, ErrDAGProtectedState
	}
	c.Pin = &copy.Baseline.Pin
	c.PriorBundle = &copy.Baseline.DependencyBundle
	c.MinimumSequence = copy.Baseline.MinimumSequence
	c.ClosedOperations = resolutionClosedCheckpoints(&copy)
	return c, nil
}
