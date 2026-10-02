package cryptox

// VerifyHistoricalEnrollmentApprovalV2 检查受保护原审批包的身份与历史签名来源，
// 不检查当前时间或授予当前权限。调用端重试提交仍须独立检查挑战与当前精确授权。
func VerifyHistoricalEnrollmentApprovalV2(anchor ConfirmedEnrollmentAnchor, a EnrollmentApprovalV2) (*VerifiedIssuerProof, error) {
	return verifyEnrollmentIssuerProof(anchor, a, false)
}
