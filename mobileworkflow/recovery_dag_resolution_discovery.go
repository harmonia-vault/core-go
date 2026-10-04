package mobileworkflow

import (
	"github.com/harmonia-vault/core-go/syncclient"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
)

// 只说明已验证本机原操作的可达性；不证明服务器权限、RAM owner 或设备可信。
type RecoveryDAGResolutionDiscovery struct {
	Version       int    `json:"version"`
	Profile       string `json:"profile"`
	State         string `json:"state"`
	OperationID   string `json:"operationId"`
	TargetHash    string `json:"targetHash"`
	TrustedDevice bool   `json:"trustedDevice"`
}

func (w *Workflow) RecoveryDAGResolutionDiscoveryInfo() (RecoveryDAGResolutionDiscovery, error) {
	out := RecoveryDAGResolutionDiscovery{Version: 1, Profile: cryptox.RecoveryOperationClosureCapability, State: "none"}
	w.mu.Lock()
	defer w.mu.Unlock()
	if e := w.checkRecoveredDAGNativeLocked(); e != nil {
		return RecoveryDAGResolutionDiscovery{}, e
	}
	cloud := w.engine.State()
	if cloud.Synthetic || cloud.AccountClosed || (w.state.AccountID == "") != (w.state.AccountGeneration == "") {
		return RecoveryDAGResolutionDiscovery{}, ErrDAGProtectedState
	}
	if w.state.AccountID != "" {
		gen, e := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
		if e != nil || gen == 0 || strconv.FormatUint(gen, 10) != w.state.AccountGeneration || !identifier.MatchString(w.state.AccountID) {
			return RecoveryDAGResolutionDiscovery{}, ErrDAGProtectedState
		}
	}
	// 完整墓碑/accepted来源核验先于任何枚举成功；不得把失败当none。
	if e := w.validateDAGResolutionLocked(); e != nil {
		return RecoveryDAGResolutionDiscovery{}, e
	}
	if w.state.Root != nil || w.state.RecoveredDAGDevice != nil || w.state.Pending != nil || w.state.Recovery != nil || w.state.RecoveryAuthority != nil || w.state.RecoveredDevice != nil || w.state.EnrollmentV3 != nil || w.state.PendingApproval != nil || w.state.PendingApprovalV3 != nil || w.state.PendingApprovalV4 != nil || w.state.Management != nil || len(w.state.SelfRevocation) > 0 || len(w.state.WriteJournal) > 0 || len(w.state.EnvironmentWrites) > 0 || len(w.state.InitialAuthorities) > 0 || len(w.state.Grants) > 0 || len(w.state.Labels) > 0 || cloud.Cloud.AccountID != "" {
		out.State = "unsupported"
		return out, nil
	}
	if len(cloud.Cloud.Environments) > 0 || len(cloud.Originals) > 0 || len(cloud.Managed) > 0 {
		return RecoveryDAGResolutionDiscovery{}, ErrDAGProtectedState
	}
	if e := w.validateDAGStateLocked(); e != nil {
		return RecoveryDAGResolutionDiscovery{}, e
	}
	// 任一新准备记录优先于旧closed；不以历史墓碑宣称当前事务已经关闭。
	if w.state.RecoveryDAGPreparation != nil || w.state.RecoveryDAGRecoveredPreparation != nil {
		out.State = "unsupported"
		return out, nil
	}
	if j := w.state.RecoveryDAG; j != nil {
		b, e := w.dagBindingLocked()
		if e != nil {
			return RecoveryDAGResolutionDiscovery{}, e
		}
		p, e := syncclient.DecodeDAGJournal(b, j.Journal)
		if e != nil {
			return RecoveryDAGResolutionDiscovery{}, e
		}
		if p.Transition == nil {
			out.State = "unsupported"
			return out, nil
		}
		out.State = "supported-original"
	} else if r := w.state.RecoveryDAGResolution; r != nil && len(r.Closed) > 0 {
		out.State = "closed"
	} else {
		return out, nil
	}
	target, _, e := w.resolutionTargetLocked()
	if e != nil {
		return RecoveryDAGResolutionDiscovery{}, e
	}
	hash, e := target.Hash()
	if e != nil {
		return RecoveryDAGResolutionDiscovery{}, e
	}
	out.OperationID, out.TargetHash = target.OperationID, hash
	return out, nil
}
