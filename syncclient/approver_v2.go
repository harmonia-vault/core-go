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

// ApproverV2 保留现有设备绑定 Client 内的会话，不提供 token 导出接口。
// 一次 Confirm 内完成真实 manager PAKE；临时状态不能持久化。
type ApproverV2 struct {
	client                      *Client
	key                         ed25519.PrivateKey
	id                          string
	context                     *pairing.Context
	session                     *pairing.Session
	ownMessage, ownConfirmation string
	confirmed                   bool
}

func (c *Client) NewApproverV2(id string, key ed25519.PrivateKey) (*ApproverV2, error) {
	verifier, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || !enrollmentID.MatchString(id) || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), verifier.trust.DeviceSigningPublicKey) || c.config.Token == "" {
		return nil, errors.New("approval needs exact trusted manager and bound session")
	}
	return &ApproverV2{client: c, key: bytes.Clone(key), id: id}, nil
}
func (a *ApproverV2) Close() {
	if a.session != nil {
		a.session.Close()
		a.session = nil
	}
	clear(a.key)
	a.client = nil
}
func (a *ApproverV2) validate(s PairingStatusV2) error {
	if a.client == nil {
		return pairing.ErrState
	}
	v := a.client.config.Verifier.(*PinnedVerifier)
	c := s.Context
	if s.CertificateVersion != "2" || len(s.Capabilities) != 1 || s.Capabilities[0] != cryptox.IssuerProofCapability || s.IdempotencyKey != a.id || s.PairingProfile != pairing.Profile || c.AccountID != a.client.config.AccountID || c.AccountGeneration != strconv.FormatUint(a.client.config.AccountGeneration, 10) || c.ApproverDeviceID != a.client.config.DeviceID || c.ApproverSigningPublicKey != cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey) || c.ApproverReceivingPublicKey != v.receivingPublicKey {
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
	if s.Approval != nil && (s.Approval.Context != cryptox.EnrollmentContext(c) || s.Approval.CertificateVersion != "2" || s.Approval.PairingProfile != s.PairingProfile) {
		return errors.New("approval envelope context changed")
	}
	if a.context == nil {
		copy := c
		a.context = &copy
	}
	return nil
}
func (a *ApproverV2) Query(ctx context.Context) (PairingStatusV2, error) {
	var s PairingStatusV2
	if a.client == nil {
		return s, pairing.ErrState
	}
	if err := a.client.request(ctx, "GET", a.client.endpointFor("/pairings-v2/"+a.id), nil, &s); err != nil {
		return s, err
	}
	return s, a.validate(s)
}
func (a *ApproverV2) relay(ctx context.Context, kind, payload string) (PairingStatusV2, error) {
	c := a.context
	if c == nil {
		return PairingStatusV2{}, pairing.ErrState
	}
	sig, err := cryptox.SignPairingRelay(cryptox.PairingRelay{AccountID: c.AccountID, AccountGeneration: c.AccountGeneration, SessionID: c.SessionID, ChallengeNonce: c.ChallengeNonce, Side: "approver", Kind: kind, Payload: payload}, a.key)
	if err != nil {
		return PairingStatusV2{}, err
	}
	wire := struct {
		Side      string `json:"side"`
		Kind      string `json:"kind"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{"approver", kind, payload, sig}
	var s PairingStatusV2
	if err = a.client.request(ctx, "POST", a.client.endpointFor("/pairings-v2/"+a.id+"/relay"), wire, &s); err != nil {
		return s, err
	}
	return s, a.validate(s)
}

// Confirm 不签任何环境授权；用户选择与根来源由上层强认证业务验证。
func (a *ApproverV2) Confirm(ctx context.Context, code []byte) (cryptox.ConfirmedEnrollmentAnchor, error) {
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
func (a *ApproverV2) BindProtectedApproval(value cryptox.EnrollmentApprovalV2) error {
	if a.client == nil || value.InitiatorSignature != "" {
		return pairing.ErrState
	}
	c := pairing.Context(value.Context)
	v := a.client.config.Verifier.(*PinnedVerifier)
	if c.AccountID != a.client.config.AccountID || c.AccountGeneration != strconv.FormatUint(a.client.config.AccountGeneration, 10) || c.ApproverDeviceID != a.client.config.DeviceID || c.ApproverSigningPublicKey != cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey) || c.ApproverReceivingPublicKey != v.receivingPublicKey {
		return errors.New("protected approval manager mismatch")
	}
	if _, err := cryptox.VerifyHistoricalEnrollmentApprovalV2(cryptox.ConfirmedEnrollmentAnchor{Context: value.Context, TranscriptHash: value.TranscriptHash}, value); err != nil {
		return err
	}
	if a.context != nil && *a.context != c {
		return errors.New("protected approval context changed")
	}
	a.context = &c
	return nil
}
func (a *ApproverV2) MatchApproval(s PairingStatusV2, value cryptox.EnrollmentApprovalV2) error {
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
		_, err := cryptox.VerifyCompletedEnrollmentV2(cryptox.ConfirmedEnrollmentAnchor{Context: value.Context, TranscriptHash: value.TranscriptHash}, *s.Approval)
		return err
	}
	return nil
}

// Submit 保留原包和签名；调用端须在本机AES真正成功后才能调用。
func (a *ApproverV2) Submit(ctx context.Context, value cryptox.EnrollmentApprovalV2) (PairingStatusV2, error) {
	var s PairingStatusV2
	if err := a.BindProtectedApproval(value); err != nil {
		return s, err
	}
	if a.context.ValidateAt(a.client.config.Now()) != nil {
		return s, pairing.ErrExpired
	}
	if _, err := cryptox.VerifyEnrollmentApprovalV2(cryptox.ConfirmedEnrollmentAnchor{Context: value.Context, TranscriptHash: value.TranscriptHash}, value, a.client.config.Now()); err != nil {
		return s, err
	}
	wire := struct {
		CertificateVersion string                    `json:"certificateVersion"`
		Capabilities       []string                  `json:"capabilities"`
		Grants             []cryptox.SignedGrantWire `json:"grants"`
		TranscriptHash     string                    `json:"transcriptHash"`
		IssuerProof        cryptox.IssuerProof       `json:"issuerProof"`
		Signature          string                    `json:"signature"`
	}{"2", []string{cryptox.IssuerProofCapability}, value.Grants, value.TranscriptHash, value.IssuerProof, value.ApproverSignature}
	if err := a.client.request(ctx, "POST", a.client.endpointFor("/pairings-v2/"+a.id+"/approve"), wire, &s); err != nil {
		return s, err
	}
	return s, a.MatchApproval(s, value)
}
