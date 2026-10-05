package cryptox

// EnrollmentContext 是 HTTP 中公开冻结的上下文，不包含短码或本地秘密。
// 它与 pairing.Context 的字段一致；内核会额外检查短时期限与当前步骤。
type EnrollmentContext struct {
	AccountID                   string `json:"accountId"`
	AccountGeneration           string `json:"accountGeneration"`
	Purpose                     string `json:"purpose"`
	SessionID                   string `json:"sessionId"`
	ChallengeNonce              string `json:"challengeNonce"`
	ExpiresAt                   string `json:"expiresAt"`
	InitiatorDeviceID           string `json:"initiatorDeviceId"`
	InitiatorSigningPublicKey   string `json:"initiatorSigningPublicKey"`
	InitiatorReceivingPublicKey string `json:"initiatorReceivingPublicKey"`
	ApproverDeviceID            string `json:"approverDeviceId"`
	ApproverSigningPublicKey    string `json:"approverSigningPublicKey"`
	ApproverReceivingPublicKey  string `json:"approverReceivingPublicKey"`
}

// EnrollmentApproval 的 JSON 布局与服务器中继及入网接口一致。
// 先管理手机显式确认并签名，再由已确认 PAKE 的新设备签同一证书。
type EnrollmentApproval struct {
	Context            EnrollmentContext `json:"context"`
	PairingProfile     string            `json:"pairingProfile"`
	TranscriptHash     string            `json:"transcriptHash"`
	Grants             []SignedGrantWire `json:"grants"`
	ApproverSignature  string            `json:"approverSignature"`
	InitiatorSignature string            `json:"initiatorSignature,omitempty"`
}

func (a EnrollmentApproval) Certificate() (EnrollmentCertificate, error) {
	c := a.Context
	if c.Purpose != "enroll-device" {
		return EnrollmentCertificate{}, ErrInvalidWire
	}
	hash, err := EnrollmentGrantsHash(a.Grants)
	if err != nil {
		return EnrollmentCertificate{}, err
	}
	cert := EnrollmentCertificate{a.PairingProfile, c.AccountID, c.AccountGeneration, c.SessionID, c.ChallengeNonce, c.ExpiresAt, c.InitiatorDeviceID, c.InitiatorSigningPublicKey, c.InitiatorReceivingPublicKey, c.ApproverDeviceID, c.ApproverSigningPublicKey, c.ApproverReceivingPublicKey, a.TranscriptHash, hash}
	if _, err := cert.fields(); err != nil {
		return EnrollmentCertificate{}, err
	}
	return cert, nil
}

// PairingRelayRequest 是发送给服务器的有限中继请求；身份绑定由路由和冻结上下文重建。
type PairingRelayRequest struct {
	Side      string `json:"side"`
	Kind      string `json:"kind"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
