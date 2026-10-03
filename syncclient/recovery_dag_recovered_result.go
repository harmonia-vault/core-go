package syncclient

import "github.com/harmonia-vault/core-go/cryptox"

// RecoveredDAGResultFromConfirmedOperation仅重验已密封且确认的原包，不访问服务器、不签新包。
// Applied在原journal仅表示原登记确认；调用者仍须正式Boot/Pull和最终原生CAS。
func RecoveredDAGResultFromConfirmedOperation(p ProtectedDAGOperation) (DAGRecoveredResult, error) {
	if err := validateProtectedDAGOperation(p); err != nil {
		return DAGRecoveredResult{}, err
	}
	if p.Kind != "recovered-v2" || p.Recovered == nil || !p.Attempted || p.AcceptedSequence == 0 || !p.Applied {
		return DAGRecoveredResult{}, ErrDAGRecoveryState
	}
	p = cloneDAGOperation(p)
	accepted := cryptox.AcceptedRecoveredDeviceV2{Submission: p.Recovered.Submission, Sequence: p.AcceptedSequence}
	bundle := p.Recovered.DependencyBundle
	bundle.Records = append(bundle.Records, cryptox.RecoveryDAGRecord{Kind: "recovered-v2", RecoveredV2: &accepted})
	evidence, err := buildRecoveredDAGEvidence(p.Pin, bundle, accepted)
	if err != nil {
		return DAGRecoveredResult{}, err
	}
	return DAGRecoveredResult{Accepted: accepted, Evidence: evidence, Pin: p.Pin}, nil
}
