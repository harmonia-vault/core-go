package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/pairing"
)

// ApproverV5 保留现有设备绑定 Client 内的会话，不提供 token 导出接口。
// 一次 Confirm 内完成真实 manager PAKE；临时状态不能持久化。
type ApproverV5 struct {
	client                      *Client
	key                         ed25519.PrivateKey
	id                          string
	context                     *pairing.Context
	session                     *pairing.Session
	ownMessage, ownConfirmation string
	confirmed                   bool
}

func (c *Client) NewApproverV5(id string, key ed25519.PrivateKey) (*ApproverV5, error) {
	verifier, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || verifier.evidenceRoot == nil || verifier.initialDAGEvidence == nil || !enrollmentID.MatchString(id) || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), verifier.trust.DeviceSigningPublicKey) || c.config.Token == "" {
		return nil, errors.New("approval needs exact trusted manager and bound session")
	}
	return &ApproverV5{client: c, key: bytes.Clone(key), id: id}, nil
}
func (a *ApproverV5) Close() {
	if a.session != nil {
		a.session.Close()
		a.session = nil
	}
	clear(a.key)
	a.client = nil
}
func (a *ApproverV5) validate(s PairingStatusV5) error {
	if a.client == nil {
		return pairing.ErrState
	}
	v := a.client.config.Verifier.(*PinnedVerifier)
	c := s.Context
	if s.CertificateVersion != "5" || len(s.Capabilities) != 1 || s.Capabilities[0] != cryptox.RecoveryDAGCapability || s.IdempotencyKey != a.id || s.PairingProfile != pairing.Profile || c.AccountID != a.client.config.AccountID || c.AccountGeneration != strconv.FormatUint(a.client.config.AccountGeneration, 10) || c.ApproverDeviceID != a.client.config.DeviceID || c.ApproverSigningPublicKey != cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey) || c.ApproverReceivingPublicKey != v.receivingPublicKey {
		return errors.New("approval status does not bind exact local manager/version/capability")
	}
	if _, err := c.CanonicalBytes(); err != nil {
		return err
	}
	if a.context != nil && *a.context != c {
		return errors.New("approval context changed")
	}
	if s.State != "pending" && s.State != "approved" && s.State != "complete" {
		return errors.New("invalid approval state")
	}
	if s.State == "complete" {
		if s.Sequence == nil || *s.Sequence == 0 || *s.Sequence > 9007199254740991 || s.Approval == nil || s.Approval.InitiatorSignature == "" {
			return errors.New("invalid approval completion")
		}
	} else {
		if s.Sequence != nil || c.ValidateAt(a.client.config.Now()) != nil {
			return pairing.ErrExpired
		}
		if (s.State == "approved") != (s.Approval != nil) {
			return errors.New("invalid approval status")
		}
	}
	for _, m := range []map[string]string{s.Messages, s.Confirmations} {
		for side, p := range m {
			if side != "initiator" && side != "approver" {
				return pairing.ErrContext
			}
			if _, err := cryptox.DecodeBase64(p, 32, 32); err != nil {
				return err
			}
		}
	}
	if len(s.Confirmations) > 0 && (s.Messages["initiator"] == "" || s.Messages["approver"] == "") {
		return errors.New("confirmation lacks PAKE messages")
	}
	if a.ownMessage != "" && s.Messages["approver"] != a.ownMessage {
		return errors.New("own PAKE message changed")
	}
	if a.ownConfirmation != "" && s.Confirmations["approver"] != a.ownConfirmation {
		return errors.New("own confirmation changed")
	}
	if s.Approval != nil && (s.Approval.Context != cryptox.EnrollmentContext(c) || s.Approval.CertificateVersion != "5" || s.Approval.PairingProfile != s.PairingProfile) {
		return errors.New("approval envelope context changed")
	}
	if a.context == nil {
		copy := c
		a.context = &copy
	}
	return nil
}
func (a *ApproverV5) Query(ctx context.Context) (PairingStatusV5, error) {
	var s PairingStatusV5
	if a.client == nil {
		return s, pairing.ErrState
	}
	if err := a.client.request(ctx, "GET", a.client.endpointFor("/pairings-v5/"+a.id), nil, &s); err != nil {
		return s, err
	}
	return s, a.validate(s)
}
func (a *ApproverV5) relay(ctx context.Context, kind, payload string) (PairingStatusV5, error) {
	c := a.context
	if c == nil {
		return PairingStatusV5{}, pairing.ErrState
	}
	sig, err := cryptox.SignPairingRelay(cryptox.PairingRelay{AccountID: c.AccountID, AccountGeneration: c.AccountGeneration, SessionID: c.SessionID, ChallengeNonce: c.ChallengeNonce, Side: "approver", Kind: kind, Payload: payload}, a.key)
	if err != nil {
		return PairingStatusV5{}, err
	}
	wire := struct {
		Side      string `json:"side"`
		Kind      string `json:"kind"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{"approver", kind, payload, sig}
	var s PairingStatusV5
	if err = a.client.request(ctx, "POST", a.client.endpointFor("/pairings-v5/"+a.id+"/relay"), wire, &s); err != nil {
		return s, err
	}
	return s, a.validate(s)
}

// Confirm 不签任何环境授权；用户选择与根来源由上层强认证业务验证。
func (a *ApproverV5) Confirm(ctx context.Context, code []byte) (cryptox.ConfirmedEnrollmentAnchor, error) {
	var empty cryptox.ConfirmedEnrollmentAnchor
	if !pairing.NativeAvailable() {
		return empty, pairing.ErrUnavailable
	}
	if a.session != nil || a.confirmed {
		return empty, pairing.ErrState
	}
	s, err := a.Query(ctx)
	if err != nil {
		return empty, err
	}
	if s.State != "pending" || s.Approval != nil || s.Messages["approver"] != "" || s.Confirmations["approver"] != "" {
		return empty, errors.New("cannot resume discarded PAKE temporary state")
	}
	session, message, err := pairing.NewApprover(s.Context, code)
	if err != nil {
		return empty, err
	}
	a.session = session
	a.ownMessage = cryptox.EncodeBase64(message)
	clear(message)
	s, err = a.relay(ctx, "message", a.ownMessage)
	if err != nil {
		return empty, err
	}
	for {
		if s.State != "pending" {
			return empty, errors.New("approval arrived before own local confirmation")
		}
		if a.ownConfirmation == "" && s.Messages["initiator"] != "" {
			peer, _ := cryptox.DecodeBase64(s.Messages["initiator"], 32, 32)
			mac, e := session.Complete(peer)
			clear(peer)
			if e != nil {
				return empty, e
			}
			a.ownConfirmation = cryptox.EncodeBase64(mac)
			clear(mac)
			s, err = a.relay(ctx, "confirmation", a.ownConfirmation)
			if err != nil {
				return empty, err
			}
		}
		if a.ownConfirmation != "" && s.Confirmations["initiator"] != "" {
			mac, _ := cryptox.DecodeBase64(s.Confirmations["initiator"], 32, 32)
			err = session.VerifyPeerConfirmation(mac)
			clear(mac)
			if err != nil {
				return empty, err
			}
			hash, e := session.TranscriptHash()
			if e != nil {
				return empty, e
			}
			a.confirmed = true
			return cryptox.ConfirmedEnrollmentAnchor{Context: cryptox.EnrollmentContext(*a.context), TranscriptHash: hash}, nil
		}
		select {
		case <-ctx.Done():
			return empty, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
		s, err = a.Query(ctx)
		if err != nil {
			return empty, err
		}
	}
}

// BindProtectedApproval 仅接收原生AES认证解包的本地原签包，不能从服务器构造。
// 包必须由精确本机管理钥签署；此历史检查不赋当前管理权。
func (a *ApproverV5) BindProtectedApproval(value cryptox.EnrollmentApprovalV5) error {
	if a.client == nil || value.InitiatorSignature != "" {
		return pairing.ErrState
	}
	c := pairing.Context(value.Context)
	v := a.client.config.Verifier.(*PinnedVerifier)
	if c.AccountID != a.client.config.AccountID || c.AccountGeneration != strconv.FormatUint(a.client.config.AccountGeneration, 10) || c.ApproverDeviceID != a.client.config.DeviceID || c.ApproverSigningPublicKey != cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey) || c.ApproverReceivingPublicKey != v.receivingPublicKey {
		return errors.New("protected approval manager mismatch")
	}
	if v.evidenceRoot == nil {
		return errors.New("approval v5 requires a protected issuer origin root")
	}
	if _, err := cryptox.VerifyIssuerRecoveryDAG(*v.evidenceRoot, value.IssuerProof); err != nil {
		return err
	}
	if _, err := cryptox.VerifyEnrollmentApprovalV5(cryptox.ConfirmedEnrollmentAnchor{Context: value.Context, TranscriptHash: value.TranscriptHash}, value); err != nil {
		return err
	}
	if a.context != nil && *a.context != c {
		return errors.New("protected approval context changed")
	}
	a.context = &c
	return nil
}
func (a *ApproverV5) MatchApproval(s PairingStatusV5, value cryptox.EnrollmentApprovalV5) error {
	if err := a.validate(s); err != nil {
		return err
	}
	if s.Approval == nil {
		return errors.New("server has no accepted approval")
	}
	server := *s.Approval
	server.InitiatorSignature = ""
	if !sameJSON(server, value) {
		return errors.New("server approval differs from protected original package")
	}
	if s.State == "complete" {
		_, err := cryptox.VerifyCompletedEnrollmentV5(cryptox.ConfirmedEnrollmentAnchor{Context: value.Context, TranscriptHash: value.TranscriptHash}, *s.Approval)
		return err
	}
	return nil
}

// Submit 保留原包和签名；调用端须在本机AES真正成功后才能调用。
func (a *ApproverV5) Submit(ctx context.Context, value cryptox.EnrollmentApprovalV5) (PairingStatusV5, error) {
	var s PairingStatusV5
	if err := a.BindProtectedApproval(value); err != nil {
		return s, err
	}
	if a.context.ValidateAt(a.client.config.Now()) != nil {
		return s, pairing.ErrExpired
	}
	if _, err := cryptox.VerifyEnrollmentApprovalV5(cryptox.ConfirmedEnrollmentAnchor{Context: value.Context, TranscriptHash: value.TranscriptHash}, value); err != nil {
		return s, err
	}
	wire := struct {
		CertificateVersion string                    `json:"certificateVersion"`
		Capabilities       []string                  `json:"capabilities"`
		Grants             []cryptox.SignedGrantWire `json:"grants"`
		TranscriptHash     string                    `json:"transcriptHash"`
		IssuerProof        cryptox.IssuerRecoveryDAG `json:"issuerProof"`
		Signature          string                    `json:"signature"`
	}{"5", []string{cryptox.RecoveryDAGCapability}, value.Grants, value.TranscriptHash, value.IssuerProof, value.ApproverSignature}
	if err := a.client.request(ctx, "POST", a.client.endpointFor("/pairings-v5/"+a.id+"/approve"), wire, &s); err != nil {
		return s, err
	}
	return s, a.MatchApproval(s, value)
}

// PrepareApproval 只在本机双向 PAKE 已确认后签原包；Grants 是调用方按
// 明确选择签署并用该新设备接收钥封装的授权，本方法复验当前精确 Admin 和期限。
// 调用方必须在 Submit 前将返回原包真正加密持久化。
func (a *ApproverV5) PrepareApproval(grants []cryptox.SignedGrantWire) (cryptox.EnrollmentApprovalV5, error) {
	var empty cryptox.EnrollmentApprovalV5
	if a.client == nil || !a.confirmed || a.session == nil || a.context == nil || len(grants) == 0 || len(grants) > 16 {
		return empty, pairing.ErrState
	}
	if a.context.ValidateAt(a.client.config.Now()) != nil {
		return empty, pairing.ErrExpired
	}
	envs := make([]string, 0, len(grants))
	for _, g := range grants {
		envs = append(envs, g.Grant.EnvironmentID)
	}
	proof, _, e := a.client.PrepareEnrollmentProofV5(envs)
	if e != nil {
		return empty, e
	}
	transcript, e := a.session.TranscriptHash()
	if e != nil {
		return empty, e
	}
	value := cryptox.EnrollmentApprovalV5{CertificateVersion: "5", Capabilities: []string{cryptox.RecoveryDAGCapability}, Context: cryptox.EnrollmentContext(*a.context), PairingProfile: pairing.Profile, TranscriptHash: transcript, Grants: grants, IssuerProof: proof}
	cert, e := value.Certificate()
	if e != nil {
		return empty, e
	}
	value.ApproverSignature, e = cryptox.SignEnrollmentCertificateV5(cert, a.key)
	if e != nil {
		return empty, e
	}
	if _, e = cryptox.VerifyEnrollmentApprovalV5(cryptox.ConfirmedEnrollmentAnchor{Context: value.Context, TranscriptHash: value.TranscriptHash}, value); e != nil {
		return empty, e
	}
	for _, g := range grants {
		expiry, e := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
		if e != nil || expiry != 0 && expiry <= a.client.config.Now().Unix() {
			return empty, pairing.ErrExpired
		}
	}
	return value, nil
}
