package syncclient

// VerifyManagementControl 复验完整签权/身份与原 pin。historical=true 只供
// 密封业务历史复验，不授予当前权限；false 仍检查当前序号、期限和 own target。
func (c *Client) VerifyManagementControl(out ManagementControl, historical ...bool) (VerifiedControlEvidence, error) {
	proof, _, err := c.verifyManagementControl(out, historical...)
	return proof, err
}
