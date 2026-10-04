package mobilebridge

import "github.com/harmonia-vault/core-go/cryptox"

// 编译投影，不是SDK验收、账号权限或capability开放。
// 原生RAM取消由平台处理器另行声明，不属于Go domain Execute。
func DAGWorkflowProfile() (string, error) {
	operations := []string{
		"applyDAGRecoveredDevice", "beginDAGRecoveryTransition", "closeDAGRecoveryOriginal",
		"dagRecoveredDeviceInfo", "dagRecoveredEnrollmentChoices", "dagRecoveryOwnerInfo",
		"dagRecoveryPendingInfo", "dagRecoveryPreparationInfo", "dagRecoveryResolutionDiscovery",
		"dagRecoveryResolutionInfo", "openDAGRecoveryAfterClosure", "openDAGRecoveryOwner",
		"pullDAGRecoveredDevice", "queryDAGRecoveryOriginal", "queryDAGRecoveryResolution",
		"restoreDAGRecoveredDevice", "retryDAGRecoveredDevice", "retryDAGRecoveryTransition",
		"sealDAGRecoveredDevice", "sealDAGRecoveryTransition",
	}
	return encode(map[string]any{"version": 1, "profile": cryptox.RecoveryDAGCapability, "experimental": true, "realVaultReady": false, "systemAuthenticationPerOperation": true, "dispatch": "executeDAGRecovery", "operations": operations})
}
