package syncclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/pairing"
)

// PairingStatusV5 只用于独立 v5 路由；共同能力和证书版本每次响应均须明确。
type PairingStatusV5 struct {
	State              string                        `json:"state"`
	IdempotencyKey     string                        `json:"idempotencyKey"`
	CertificateVersion string                        `json:"certificateVersion"`
	Capabilities       []string                      `json:"capabilities"`
	PairingProfile     string                        `json:"pairingProfile"`
	Context            pairing.Context               `json:"context"`
	Messages           map[string]string             `json:"messages"`
	Confirmations      map[string]string             `json:"confirmations"`
	Approval           *cryptox.EnrollmentApprovalV5 `json:"approval"`
	Sequence           *uint64                       `json:"sequence"`
	Replayed           bool                          `json:"replayed,omitempty"`
}

// EnrollmentReceiptV5 不含短码、PAKE 临时私钥或登录凭据。持久化前已确认
// 双向 PAKE、精确本机双公钥、管理签证明与全部 HPKE 封套，并由本机双签。
type EnrollmentReceiptV5 struct {
	IdempotencyKey string                       `json:"idempotencyKey"`
	Approval       cryptox.EnrollmentApprovalV5 `json:"approval"`
}
type EnrollmentResultV5 struct {
	Receipt  EnrollmentReceiptV5
	Sequence uint64
	Verifier *PinnedVerifier
}

// DecodeEnrollmentReceiptV5 拒绝未知字段、额外 JSON 和超限；签名另由验证器检查。
func DecodeEnrollmentReceiptV5(data []byte) (EnrollmentReceiptV5, error) {
	var r EnrollmentReceiptV5
	if e := cryptox.ValidateStrictJSON(data, cryptox.MaxRecoveryAuthorityBytes+512); e != nil {
		return r, e
	}
	if len(data) == 0 || len(data) > cryptox.MaxRecoveryAuthorityBytes+512 {
		return r, cryptox.ErrInvalidWire
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF || !enrollmentID.MatchString(r.IdempotencyKey) {
		return r, cryptox.ErrInvalidWire
	}
	a, err := json.Marshal(r.Approval)
	if err != nil {
		return r, err
	}
	if _, err = cryptox.DecodeEnrollmentApprovalV5(a); err != nil {
		return r, err
	}
	return r, nil
}

type EnrollmentV5 struct {
	mu              sync.Mutex
	client          *Client
	key             ed25519.PrivateKey
	receiving       []byte
	receivingPublic string
	keyID           string
	context         pairing.Context
	session         *pairing.Session
	ownMessage      string
	ownConfirmation string
	confirmed       bool
	receipt         *EnrollmentReceiptV5
}

func NewEnrollmentV5(config EnrollmentConfig) (*EnrollmentV5, error) {
	if len(config.SigningKey) != ed25519.PrivateKeySize || len(config.LoginToken) == 0 || config.Engine == nil || config.Engine.State().Cloud.AccountID != "" {
		return nil, errors.New("enrollment requires an empty protected owner and independent device keys")
	}
	receive, err := ecdh.X25519().NewPrivateKey(config.ReceivingPrivateKey)
	if err != nil {
		return nil, errors.New("invalid enrollment receiving key")
	}
	signPublic := config.SigningKey.Public().(ed25519.PublicKey)
	if bytes.Equal(signPublic, receive.PublicKey().Bytes()) {
		return nil, errors.New("enrollment keys must be independent")
	}
	if _, err = cryptox.DecodeBase64(config.LoginToken, 32, 32); err != nil {
		return nil, errors.New("invalid random enrollment login session")
	}
	c, err := New(Config{Endpoint: config.Endpoint, HTTPClient: config.HTTPClient, ProtocolMajor: 2, AccountID: config.AccountID, AccountGeneration: config.AccountGeneration, DeviceID: config.DeviceID, Token: config.LoginToken, Verifier: deniedEnrollmentVerifier{}, Engine: config.Engine, Now: config.Now})
	if err != nil {
		return nil, err
	}
	return &EnrollmentV5{client: c, key: bytes.Clone(config.SigningKey), receiving: bytes.Clone(config.ReceivingPrivateKey), receivingPublic: cryptox.EncodeBase64(receive.PublicKey().Bytes())}, nil
}
func (e *EnrollmentV5) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session != nil {
		e.session.Close()
	}
	clear(e.key)
	clear(e.receiving)
	e.client = nil
}

// Begin 在默认构建立即失败；短码仅送入本机成熟原语，不进入任何 HTTP 对象。
func (e *EnrollmentV5) Begin(ctx context.Context, approverID, idempotencyKey string, shortCode []byte) (PairingStatusV5, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !pairing.NativeAvailable() {
		return PairingStatusV5{}, pairing.ErrUnavailable
	}
	if e.client == nil || e.session != nil || e.keyID != "" || !enrollmentID.MatchString(approverID) || !enrollmentID.MatchString(idempotencyKey) || approverID == e.client.config.DeviceID {
		return PairingStatusV5{}, pairing.ErrState
	}
	if len(shortCode) != 8 {
		return PairingStatusV5{}, pairing.ErrContext
	}
	for _, b := range shortCode {
		if b < '0' || b > '9' {
			return PairingStatusV5{}, pairing.ErrContext
		}
	}
	proposal := struct {
		IdempotencyKey     string   `json:"idempotencyKey"`
		DeviceID           string   `json:"deviceId"`
		SigningPublicKey   string   `json:"signingPublicKey"`
		ReceivingPublicKey string   `json:"receivingPublicKey"`
		ApproverDeviceID   string   `json:"approverDeviceId"`
		CertificateVersion string   `json:"certificateVersion"`
		Capabilities       []string `json:"capabilities"`
	}{idempotencyKey, e.client.config.DeviceID, cryptox.EncodeBase64(e.key.Public().(ed25519.PublicKey)), e.receivingPublic, approverID, "5", []string{cryptox.RecoveryDAGCapability}}
	var status PairingStatusV5
	if err := e.client.request(ctx, "POST", e.client.endpointFor("/pairings-v5"), proposal, &status); err != nil {
		return PairingStatusV5{}, err
	}
	c := status.Context
	if c.AccountID != e.client.config.AccountID || c.AccountGeneration != strconv.FormatUint(e.client.config.AccountGeneration, 10) || c.InitiatorDeviceID != proposal.DeviceID || c.InitiatorSigningPublicKey != proposal.SigningPublicKey || c.InitiatorReceivingPublicKey != proposal.ReceivingPublicKey || c.ApproverDeviceID != approverID || c.ValidateAt(e.client.config.Now()) != nil {
		return PairingStatusV5{}, errors.New("pairing context does not bind the exact local account/device/public keys")
	}
	e.keyID = idempotencyKey
	e.context = c
	if err := e.validateStatus(status); err != nil {
		return PairingStatusV5{}, err
	}
	if len(status.Messages) != 0 || len(status.Confirmations) != 0 || status.Approval != nil {
		return PairingStatusV5{}, errors.New("fresh local PAKE cannot resume old ephemeral messages")
	}
	session, message, err := pairing.NewInitiator(c, shortCode)
	if err != nil {
		return PairingStatusV5{}, err
	}
	e.session = session
	e.ownMessage = cryptox.EncodeBase64(message)
	clear(message)
	return e.relay(ctx, "message", e.ownMessage)
}
func (e *EnrollmentV5) validateStatus(s PairingStatusV5) error {
	if s.CertificateVersion != "5" || len(s.Capabilities) != 1 || s.Capabilities[0] != cryptox.RecoveryDAGCapability {
		return errors.New("pairing v5 capability/version missing or changed; downgrade forbidden")
	}
	if s.IdempotencyKey != e.keyID || s.PairingProfile != pairing.Profile || s.Context != e.context {
		return errors.New("pairing session identity/context changed")
	}
	if s.State != "pending" && s.State != "approved" && s.State != "complete" {
		return errors.New("invalid pairing state")
	}
	if s.State == "complete" {
		if s.Sequence == nil || *s.Sequence == 0 || *s.Sequence > 9007199254740991 || s.Approval == nil || s.Approval.InitiatorSignature == "" {
			return errors.New("invalid pairing completion checkpoint")
		}
	} else {
		if s.Sequence != nil || e.context.ValidateAt(e.client.config.Now()) != nil {
			return pairing.ErrExpired
		}
		if (s.State == "approved") != (s.Approval != nil) {
			return errors.New("invalid pairing approval state")
		}
	}
	for _, values := range []map[string]string{s.Messages, s.Confirmations} {
		for side, payload := range values {
			if side != "initiator" && side != "approver" {
				return errors.New("unknown pairing relay side")
			}
			if _, err := cryptox.DecodeBase64(payload, 32, 32); err != nil {
				return errors.New("invalid pairing relay payload")
			}
		}
	}
	if len(s.Confirmations) != 0 && (s.Messages["initiator"] == "" || s.Messages["approver"] == "") {
		return errors.New("confirmation without both PAKE messages")
	}
	if e.ownMessage != "" && s.Messages["initiator"] != e.ownMessage {
		return errors.New("server changed the local PAKE message")
	}
	if e.ownConfirmation != "" && s.Confirmations["initiator"] != e.ownConfirmation {
		return errors.New("server changed the local key confirmation")
	}
	return nil
}
func (e *EnrollmentV5) relay(ctx context.Context, kind, payload string) (PairingStatusV5, error) {
	proof := cryptox.PairingRelay{AccountID: e.context.AccountID, AccountGeneration: e.context.AccountGeneration, SessionID: e.context.SessionID, ChallengeNonce: e.context.ChallengeNonce, Side: "initiator", Kind: kind, Payload: payload}
	signature, err := cryptox.SignPairingRelay(proof, e.key)
	if err != nil {
		return PairingStatusV5{}, err
	}
	wire := struct {
		Side      string `json:"side"`
		Kind      string `json:"kind"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{"initiator", kind, payload, signature}
	var status PairingStatusV5
	if err = e.client.request(ctx, "POST", e.client.endpointFor("/pairings-v5/"+e.keyID+"/relay"), wire, &status); err != nil {
		return PairingStatusV5{}, err
	}
	return status, e.validateStatus(status)
}
func (e *EnrollmentV5) poll(ctx context.Context) (PairingStatusV5, error) {
	var status PairingStatusV5
	if e.client == nil || e.keyID == "" {
		return status, pairing.ErrState
	}
	if err := e.client.request(ctx, "GET", e.client.endpointFor("/pairings-v5/"+e.keyID), nil, &status); err != nil {
		return status, err
	}
	return status, e.validateStatus(status)
}
func (e *EnrollmentV5) Poll(ctx context.Context) (PairingStatusV5, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.poll(ctx)
}

// Advance 只依据经过本地绑定检查的中继推进单次 PAKE；收到管理批准也必须先
// 验证对端 HMAC，再验证证书/授权/环境封套。它不写 Engine 的云状态。
func (e *EnrollmentV5) Advance(ctx context.Context) (PairingStatusV5, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session == nil {
		return PairingStatusV5{}, pairing.ErrState
	}
	status, err := e.poll(ctx)
	if err != nil {
		return status, err
	}
	if status.Messages["approver"] != "" && e.ownConfirmation == "" {
		peer, _ := cryptox.DecodeBase64(status.Messages["approver"], 32, 32)
		confirmation, err := e.session.Complete(peer)
		clear(peer)
		if err != nil {
			return PairingStatusV5{}, err
		}
		e.ownConfirmation = cryptox.EncodeBase64(confirmation)
		clear(confirmation)
		status, err = e.relay(ctx, "confirmation", e.ownConfirmation)
		if err != nil {
			return status, err
		}
	} else if e.ownConfirmation != "" && status.Confirmations["initiator"] == "" {
		return PairingStatusV5{}, errors.New("local confirmation disappeared")
	}
	if !e.confirmed && status.Confirmations["approver"] != "" {
		mac, _ := cryptox.DecodeBase64(status.Confirmations["approver"], 32, 32)
		err = e.session.VerifyPeerConfirmation(mac)
		clear(mac)
		if err != nil {
			return PairingStatusV5{}, err
		}
		e.confirmed = true
	}
	if status.Approval != nil {
		if !e.confirmed {
			return PairingStatusV5{}, errors.New("manager approval arrived before local PAKE confirmation")
		}
		transcript, err := e.session.TranscriptHash()
		if err != nil {
			return PairingStatusV5{}, err
		}
		if status.Approval.TranscriptHash != transcript {
			return PairingStatusV5{}, errors.New("approval transcript does not match locally confirmed PAKE")
		}
		receipt := cloneReceiptV5(EnrollmentReceiptV5{IdempotencyKey: e.keyID, Approval: *status.Approval})
		verifier, cert, err := e.verifyReceipt(ctx, receipt, false)
		if err != nil {
			return PairingStatusV5{}, err
		}
		verifier.Close()
		signature, err := cryptox.SignEnrollmentCertificateV5(cert, e.key)
		if err != nil {
			return PairingStatusV5{}, err
		}
		receipt.Approval.InitiatorSignature = signature
		if e.receipt != nil && !sameJSON(*e.receipt, receipt) {
			return PairingStatusV5{}, errors.New("approval changed after local acceptance")
		}
		e.receipt = &receipt
	}
	return status, nil
}
func cloneReceiptV5(in EnrollmentReceiptV5) EnrollmentReceiptV5 {
	var out EnrollmentReceiptV5
	b, _ := json.Marshal(in)
	_ = json.Unmarshal(b, &out)
	return out
}
func (e *EnrollmentV5) Receipt() (EnrollmentReceiptV5, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.client == nil || e.receipt == nil {
		return EnrollmentReceiptV5{}, pairing.ErrState
	}
	return cloneReceiptV5(*e.receipt), nil
}

func (e *EnrollmentV5) verifyReceipt(ctx context.Context, r EnrollmentReceiptV5, requireOwnSignature bool) (*PinnedVerifier, cryptox.EnrollmentCertificateV5, error) {
	if r.IdempotencyKey != e.keyID || r.Approval.Context != cryptox.EnrollmentContext(e.context) || r.Approval.PairingProfile != pairing.Profile {
		return nil, cryptox.EnrollmentCertificateV5{}, errors.New("receipt context mismatch")
	}
	cert, err := r.Approval.Certificate()
	if err != nil {
		return nil, cert, err
	}
	anchor := cryptox.ConfirmedEnrollmentAnchor{Context: cryptox.EnrollmentContext(e.context), TranscriptHash: r.Approval.TranscriptHash}
	var proof *cryptox.VerifiedRecoveryDAG
	if requireOwnSignature {
		proof, err = cryptox.VerifyCompletedEnrollmentV5(anchor, r.Approval)
	} else {
		if !e.confirmed || e.session == nil {
			return nil, cert, errors.New("unconfirmed local PAKE")
		}
		transcript, e2 := e.session.TranscriptHash()
		if e2 != nil || transcript != anchor.TranscriptHash {
			return nil, cert, errors.New("unbound local PAKE transcript")
		}
		proof, err = cryptox.VerifyEnrollmentApprovalV5(anchor, r.Approval)
	}
	if err != nil {
		return nil, cert, err
	}
	verifier, err := newIssuerDAGPinnedVerifier(IssuerDAGPinnedTrust{AccountID: e.client.config.AccountID, AccountGeneration: e.client.config.AccountGeneration, DeviceID: e.client.config.DeviceID, DeviceSigningPublicKey: e.key.Public().(ed25519.PublicKey), ReceivingPrivateKey: e.receiving, Receipt: r, Now: e.client.config.Now}, proof)
	if err != nil {
		return nil, cert, err
	}
	// 审批阶段实际解开全部 HPKE 封套；历史完成/重启只恢复来源绑定，过期授权不复活。
	if !requireOwnSignature {
		grants := make([]SignedGrant, 0, len(r.Approval.Grants))
		for _, g := range r.Approval.Grants {
			grants = append(grants, SignedGrant{Grant: g.Grant, Signature: g.Signature})
		}
		verified, err := verifier.VerifyPull(ctx, Pull{Full: true, AccountID: e.context.AccountID, AccountGeneration: e.context.AccountGeneration, Grants: grants}, localstate.CloudSnapshot{})
		if err != nil || len(verified.Environments) != len(grants) {
			verifier.Close()
			if err != nil {
				return nil, cert, err
			}
			return nil, cert, errors.New("enrollment contains unavailable grants")
		}
	}
	return verifier, cert, nil
}

// ResumeEnrollment 仅重试已加密保存的双签 receipt，不恢复短码或 PAKE 临时
// 状态，也不能重新批准或改变任何证书字段。先查结果，再幂等提交原签名。
func ResumeEnrollmentV5(config EnrollmentConfig, receipt EnrollmentReceiptV5) (*EnrollmentV5, error) {
	e, err := NewEnrollmentV5(config)
	if err != nil {
		return nil, err
	}
	c := receipt.Approval.Context
	if _, err := pairing.Context(c).CanonicalBytes(); err != nil {
		e.Close()
		return nil, err
	}
	if !enrollmentID.MatchString(receipt.IdempotencyKey) || c.AccountID != config.AccountID || c.AccountGeneration != strconv.FormatUint(config.AccountGeneration, 10) || c.InitiatorDeviceID != config.DeviceID || c.InitiatorSigningPublicKey != cryptox.EncodeBase64(config.SigningKey.Public().(ed25519.PublicKey)) || c.InitiatorReceivingPublicKey != e.receivingPublic {
		e.Close()
		return nil, errors.New("pending receipt does not bind the protected local device")
	}
	e.keyID = receipt.IdempotencyKey
	e.context = pairing.Context(c)
	verified, _, err := e.verifyReceipt(context.Background(), receipt, true)
	if err != nil {
		e.Close()
		return nil, err
	}
	verified.Close()
	copyReceipt := cloneReceiptV5(receipt)
	e.receipt = &copyReceipt
	return e, nil
}
func (e *EnrollmentV5) Complete(ctx context.Context) (EnrollmentResultV5, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.client == nil || e.receipt == nil {
		return EnrollmentResultV5{}, pairing.ErrState
	}
	verifier, _, err := e.verifyReceipt(ctx, *e.receipt, true)
	if err != nil {
		return EnrollmentResultV5{}, err
	}
	keepVerifier := false
	defer func() {
		if !keepVerifier {
			verifier.Close()
		}
	}()
	status, err := e.poll(ctx)
	if err != nil {
		return EnrollmentResultV5{}, err
	}
	if status.State != "complete" {
		if status.Approval == nil {
			return EnrollmentResultV5{}, errors.New("manager approval required")
		}
		pending := *status.Approval
		pending.InitiatorSignature = e.receipt.Approval.InitiatorSignature
		if !sameJSON(pending, e.receipt.Approval) {
			return EnrollmentResultV5{}, errors.New("pending server approval/proof differs from saved receipt")
		}
		request := struct {
			Signature string `json:"signature"`
		}{e.receipt.Approval.InitiatorSignature}
		if err = e.client.request(ctx, "POST", e.client.endpointFor("/pairings-v5/"+e.keyID+"/complete"), request, &status); err != nil {
			return EnrollmentResultV5{}, errors.Join(ErrEnrollmentPending, err)
		}
		if err = e.validateStatus(status); err != nil {
			return EnrollmentResultV5{}, errors.Join(ErrEnrollmentPending, err)
		}
	}
	if status.State != "complete" || status.Approval == nil || !sameJSON(*status.Approval, e.receipt.Approval) {
		return EnrollmentResultV5{}, errors.Join(ErrEnrollmentPending, errors.New("completion does not acknowledge the exact dual-signed certificate"))
	}
	verifier.requireEvidence = true

	keepVerifier = true
	return EnrollmentResultV5{Receipt: cloneReceiptV5(*e.receipt), Sequence: *status.Sequence, Verifier: verifier}, nil
}
