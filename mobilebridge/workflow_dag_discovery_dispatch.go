package mobilebridge

import (
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
)

func nativeDAGResolutionDiscovery(x mobileworkflow.RecoveryDAGResolutionDiscovery) (map[string]any, error) {
	if x.Version != 1 || x.Profile != cryptox.RecoveryOperationClosureCapability || x.TrustedDevice {
		return nil, errInput
	}
	switch x.State {
	case "none", "unsupported":
		if x.OperationID != "" || x.TargetHash != "" {
			return nil, errInput
		}
	case "supported-original", "closed":
		if !nativeDAGID.MatchString(x.OperationID) || !nativeDAGHash.MatchString(x.TargetHash) {
			return nil, errInput
		}
	default:
		return nil, errInput
	}
	return map[string]any{"version": 1, "profile": x.Profile, "state": x.State, "operationId": x.OperationID, "targetHash": x.TargetHash, "trustedDevice": false}, nil
}
