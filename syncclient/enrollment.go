package syncclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/pairing"
)

var ErrEnrollmentPending = errors.New("enrollment result uncertain; query the same pairing before retrying")
var enrollmentID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type EnrollmentConfig struct {
	Endpoint            string
	HTTPClient          *http.Client
	AccountID           string
	AccountGeneration   uint64
	DeviceID            string
	LoginToken          string
	SigningKey          ed25519.PrivateKey
	ReceivingPrivateKey []byte
	Engine              *localstate.Engine
	Now                 func() time.Time
}
type EnrollmentApproval struct {
	Context            pairing.Context           `json:"context"`
	PairingProfile     string                    `json:"pairingProfile"`
	TranscriptHash     string                    `json:"transcriptHash"`
	Grants             []cryptox.SignedGrantWire `json:"grants"`
	ApproverSignature  string                    `json:"approverSignature"`
	InitiatorSignature string                    `json:"initiatorSignature,omitempty"`
}
type PairingStatus struct {
	State          string              `json:"state"`
	IdempotencyKey string              `json:"idempotencyKey"`
	PairingProfile string              `json:"pairingProfile"`
	Context        pairing.Context     `json:"context"`
	Messages       map[string]string   `json:"messages"`
	Confirmations  map[string]string   `json:"confirmations"`
	Approval       *EnrollmentApproval `json:"approval"`
	Sequence       *uint64             `json:"sequence"`
	Replayed       bool                `json:"replayed,omitempty"`
}

// EnrollmentReceipt 只能在真实 PAKE 双向确认、管理签授权和 HPKE 封套验证后
// 取得。后台把它加密持久化为待完成资料，不能用 pending receipt 启动同步。
// 不含短码、SPAKE2 临时私钥、密码或密码派生凭据。
type EnrollmentReceipt struct {
	IdempotencyKey string             `json:"idempotencyKey"`
	Approval       EnrollmentApproval `json:"approval"`
}
type EnrollmentResult struct {
	Receipt  EnrollmentReceipt
	Sequence uint64
	Verifier *PinnedVerifier
}
type deniedEnrollmentVerifier struct{}

func (deniedEnrollmentVerifier) VerifyPull(context.Context, Pull, localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	return localstate.CloudSnapshot{}, errors.New("unapproved device cannot synchronize")
}

type Enrollment struct {
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
	receipt         *EnrollmentReceipt
}

func NewEnrollment(config EnrollmentConfig) (*Enrollment, error) {
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
	c, err := New(Config{Endpoint: config.Endpoint, HTTPClient: config.HTTPClient, AccountID: config.AccountID, AccountGeneration: config.AccountGeneration, DeviceID: config.DeviceID, Token: config.LoginToken, Verifier: deniedEnrollmentVerifier{}, Engine: config.Engine, Now: config.Now})
	if err != nil {
		return nil, err
	}
	return &Enrollment{client: c, key: bytes.Clone(config.SigningKey), receiving: bytes.Clone(config.ReceivingPrivateKey), receivingPublic: cryptox.EncodeBase64(receive.PublicKey().Bytes())}, nil
}
func (e *Enrollment) Close() {
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
func (e *Enrollment) Begin(ctx context.Context, approverID, idempotencyKey string, shortCode []byte) (PairingStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !pairing.NativeAvailable() {
		return PairingStatus{}, pairing.ErrUnavailable
	}
	if e.client == nil || e.session != nil || e.keyID != "" || !enrollmentID.MatchString(approverID) || !enrollmentID.MatchString(idempotencyKey) || approverID == e.client.config.DeviceID {
		return PairingStatus{}, pairing.ErrState
	}
	if len(shortCode) != 8 {
		return PairingStatus{}, pairing.ErrContext
	}
	for _, b := range shortCode {
		if b < '0' || b > '9' {
			return PairingStatus{}, pairing.ErrContext
		}
	}
	proposal := struct {
		IdempotencyKey     string `json:"idempotencyKey"`
		DeviceID           string `json:"deviceId"`
		SigningPublicKey   string `json:"signingPublicKey"`
		ReceivingPublicKey string `json:"receivingPublicKey"`
		ApproverDeviceID   string `json:"approverDeviceId"`
	}{idempotencyKey, e.client.config.DeviceID, cryptox.EncodeBase64(e.key.Public().(ed25519.PublicKey)), e.receivingPublic, approverID}
	var status PairingStatus
	if err := e.client.request(ctx, "POST", e.client.endpointFor("/pairings"), proposal, &status); err != nil {
		return PairingStatus{}, err
	}
	c := status.Context
	if c.AccountID != e.client.config.AccountID || c.AccountGeneration != strconv.FormatUint(e.client.config.AccountGeneration, 10) || c.InitiatorDeviceID != proposal.DeviceID || c.InitiatorSigningPublicKey != proposal.SigningPublicKey || c.InitiatorReceivingPublicKey != proposal.ReceivingPublicKey || c.ApproverDeviceID != approverID || c.ValidateAt(e.client.config.Now()) != nil {
		return PairingStatus{}, errors.New("pairing context does not bind the exact local account/device/public keys")
	}
	e.keyID = idempotencyKey
	e.context = c
	if err := e.validateStatus(status); err != nil {
		return PairingStatus{}, err
	}
	if len(status.Messages) != 0 || len(status.Confirmations) != 0 || status.Approval != nil {
		return PairingStatus{}, errors.New("fresh local PAKE cannot resume old ephemeral messages")
	}
	session, message, err := pairing.NewInitiator(c, shortCode)
	if err != nil {
		return PairingStatus{}, err
	}
	e.session = session
	e.ownMessage = cryptox.EncodeBase64(message)
	clear(message)
	return e.relay(ctx, "message", e.ownMessage)
}
func (e *Enrollment) validateStatus(s PairingStatus) error {
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
func (e *Enrollment) relay(ctx context.Context, kind, payload string) (PairingStatus, error) {
	proof := cryptox.PairingRelay{AccountID: e.context.AccountID, AccountGeneration: e.context.AccountGeneration, SessionID: e.context.SessionID, ChallengeNonce: e.context.ChallengeNonce, Side: "initiator", Kind: kind, Payload: payload}
	signature, err := cryptox.SignPairingRelay(proof, e.key)
	if err != nil {
		return PairingStatus{}, err
	}
	wire := struct {
		Side      string `json:"side"`
		Kind      string `json:"kind"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{"initiator", kind, payload, signature}
	var status PairingStatus
	if err = e.client.request(ctx, "POST", e.client.endpointFor("/pairings/"+e.keyID+"/relay"), wire, &status); err != nil {
		return PairingStatus{}, err
	}
	return status, e.validateStatus(status)
}
func (e *Enrollment) poll(ctx context.Context) (PairingStatus, error) {
	var status PairingStatus
	if e.client == nil || e.keyID == "" {
		return status, pairing.ErrState
	}
	if err := e.client.request(ctx, "GET", e.client.endpointFor("/pairings/"+e.keyID), nil, &status); err != nil {
		return status, err
	}
	return status, e.validateStatus(status)
}
func (e *Enrollment) Poll(ctx context.Context) (PairingStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.poll(ctx)
}

// Advance 只依据经过本地绑定检查的中继推进单次 PAKE；收到管理批准也必须先
// 验证对端 HMAC，再验证证书/授权/环境封套。它不写 Engine 的云状态。
func (e *Enrollment) Advance(ctx context.Context) (PairingStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session == nil {
		return PairingStatus{}, pairing.ErrState
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
			return PairingStatus{}, err
		}
		e.ownConfirmation = cryptox.EncodeBase64(confirmation)
		clear(confirmation)
		status, err = e.relay(ctx, "confirmation", e.ownConfirmation)
		if err != nil {
			return status, err
		}
	} else if e.ownConfirmation != "" && status.Confirmations["initiator"] == "" {
		return PairingStatus{}, errors.New("local confirmation disappeared")
	}
	if !e.confirmed && status.Confirmations["approver"] != "" {
		mac, _ := cryptox.DecodeBase64(status.Confirmations["approver"], 32, 32)
		err = e.session.VerifyPeerConfirmation(mac)
		clear(mac)
		if err != nil {
			return PairingStatus{}, err
		}
		e.confirmed = true
	}
	if status.Approval != nil {
		if !e.confirmed {
			return PairingStatus{}, errors.New("manager approval arrived before local PAKE confirmation")
		}
		transcript, err := e.session.TranscriptHash()
		if err != nil {
			return PairingStatus{}, err
		}
		if status.Approval.TranscriptHash != transcript {
			return PairingStatus{}, errors.New("approval transcript does not match locally confirmed PAKE")
		}
		receipt := cloneReceipt(EnrollmentReceipt{IdempotencyKey: e.keyID, Approval: *status.Approval})
		verifier, cert, err := e.verifyReceipt(ctx, receipt, false)
		if err != nil {
			return PairingStatus{}, err
		}
		verifier.Close()
		signature, err := cryptox.SignEnrollmentCertificate(cert, e.key)
		if err != nil {
			return PairingStatus{}, err
		}
		receipt.Approval.InitiatorSignature = signature
		if e.receipt != nil && !sameJSON(*e.receipt, receipt) {
			return PairingStatus{}, errors.New("approval changed after local acceptance")
		}
		e.receipt = &receipt
	}
	return status, nil
}
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func cloneReceipt(in EnrollmentReceipt) EnrollmentReceipt {
	var out EnrollmentReceipt
	b, _ := json.Marshal(in)
	_ = json.Unmarshal(b, &out)
	return out
}
func (e *Enrollment) Receipt() (EnrollmentReceipt, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.receipt == nil {
		return EnrollmentReceipt{}, pairing.ErrState
	}
	return cloneReceipt(*e.receipt), nil
}

// Certificate 构造确定性证书内容；调用方仍须检查PAKE确认和双方签名。
func (a EnrollmentApproval) Certificate() (cryptox.EnrollmentCertificate, error) {
	return certificate(a)
}
func certificate(a EnrollmentApproval) (cryptox.EnrollmentCertificate, error) {
	h, err := cryptox.EnrollmentGrantsHash(a.Grants)
	if err != nil {
		return cryptox.EnrollmentCertificate{}, err
	}
	c := a.Context
	return cryptox.EnrollmentCertificate{PairingProfile: a.PairingProfile, AccountID: c.AccountID, AccountGeneration: c.AccountGeneration, SessionID: c.SessionID, Nonce: c.ChallengeNonce, ExpiresAt: c.ExpiresAt, InitiatorDeviceID: c.InitiatorDeviceID, InitiatorSigningPublicKey: c.InitiatorSigningPublicKey, InitiatorReceivingPublicKey: c.InitiatorReceivingPublicKey, ApproverDeviceID: c.ApproverDeviceID, ApproverSigningPublicKey: c.ApproverSigningPublicKey, ApproverReceivingPublicKey: c.ApproverReceivingPublicKey, TranscriptHash: a.TranscriptHash, GrantsHash: h}, nil
}
func (e *Enrollment) verifyReceipt(ctx context.Context, r EnrollmentReceipt, requireOwnSignature bool) (*PinnedVerifier, cryptox.EnrollmentCertificate, error) {
	if r.IdempotencyKey != e.keyID || r.Approval.Context != e.context || r.Approval.PairingProfile != pairing.Profile {
		return nil, cryptox.EnrollmentCertificate{}, errors.New("receipt context mismatch")
	}
	c, err := certificate(r.Approval)
	if err != nil {
		return nil, c, err
	}
	pub, err := cryptox.DecodeBase64(e.context.ApproverSigningPublicKey, 32, 32)
	if err != nil {
		return nil, c, err
	}
	manager := ed25519.PublicKey(pub)
	if err = cryptox.VerifyEnrollmentCertificate(c, r.Approval.ApproverSignature, manager); err != nil {
		return nil, c, err
	}
	if err = cryptox.VerifyEnrollmentGrants(c, r.Approval.Grants, manager); err != nil {
		return nil, c, err
	}
	if requireOwnSignature {
		if err = cryptox.VerifyEnrollmentCertificate(c, r.Approval.InitiatorSignature, e.key.Public().(ed25519.PublicKey)); err != nil {
			return nil, c, err
		}
	}
	verifier, err := NewPinnedVerifier(PinnedTrust{AccountID: e.client.config.AccountID, AccountGeneration: e.client.config.AccountGeneration, DeviceID: e.client.config.DeviceID, DeviceSigningPublicKey: e.key.Public().(ed25519.PublicKey), ReceivingPrivateKey: e.receiving, Managers: map[string]ed25519.PublicKey{e.context.ApproverDeviceID: manager}, Now: e.client.config.Now})
	if err != nil {
		return nil, c, err
	}
	grants := make([]SignedGrant, 0, len(r.Approval.Grants))
	for _, g := range r.Approval.Grants {
		grants = append(grants, SignedGrant{Grant: g.Grant, Signature: g.Signature})
	}
	verified, err := verifier.VerifyPull(ctx, Pull{Full: true, AccountID: e.context.AccountID, AccountGeneration: e.context.AccountGeneration, Grants: grants}, localstate.CloudSnapshot{})
	if err != nil {
		verifier.Close()
		return nil, c, err
	}
	if len(verified.Environments) != len(grants) {
		verifier.Close()
		return nil, c, errors.New("enrollment contains unavailable or expired grants")
	}
	return verifier, c, nil
}

// ResumeEnrollment 仅重试已加密保存的双签 receipt，不恢复短码或 PAKE 临时
// 状态，也不能重新批准或改变任何证书字段。先查结果，再幂等提交原签名。
func ResumeEnrollment(config EnrollmentConfig, receipt EnrollmentReceipt) (*Enrollment, error) {
	e, err := NewEnrollment(config)
	if err != nil {
		return nil, err
	}
	c := receipt.Approval.Context
	if _, err := c.CanonicalBytes(); err != nil {
		e.Close()
		return nil, err
	}
	if !enrollmentID.MatchString(receipt.IdempotencyKey) || c.AccountID != config.AccountID || c.AccountGeneration != strconv.FormatUint(config.AccountGeneration, 10) || c.InitiatorDeviceID != config.DeviceID || c.InitiatorSigningPublicKey != cryptox.EncodeBase64(config.SigningKey.Public().(ed25519.PublicKey)) || c.InitiatorReceivingPublicKey != e.receivingPublic {
		e.Close()
		return nil, errors.New("pending receipt does not bind the protected local device")
	}
	e.keyID = receipt.IdempotencyKey
	e.context = c
	verified, _, err := e.verifyReceipt(context.Background(), receipt, true)
	if err != nil {
		e.Close()
		return nil, err
	}
	verified.Close()
	copyReceipt := cloneReceipt(receipt)
	e.receipt = &copyReceipt
	return e, nil
}
func (e *Enrollment) Complete(ctx context.Context) (EnrollmentResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.receipt == nil {
		return EnrollmentResult{}, pairing.ErrState
	}
	verifier, _, err := e.verifyReceipt(ctx, *e.receipt, true)
	if err != nil {
		return EnrollmentResult{}, err
	}
	keepVerifier := false
	defer func() {
		if !keepVerifier {
			verifier.Close()
		}
	}()
	status, err := e.poll(ctx)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if status.State != "complete" {
		if status.Approval == nil {
			return EnrollmentResult{}, errors.New("manager approval required")
		}
		if !sameJSON(status.Approval.Context, e.receipt.Approval.Context) || status.Approval.ApproverSignature != e.receipt.Approval.ApproverSignature || status.Approval.TranscriptHash != e.receipt.Approval.TranscriptHash || !sameJSON(status.Approval.Grants, e.receipt.Approval.Grants) {
			return EnrollmentResult{}, errors.New("pending server approval differs from saved receipt")
		}
		request := struct {
			Signature string `json:"signature"`
		}{e.receipt.Approval.InitiatorSignature}
		if err = e.client.request(ctx, "POST", e.client.endpointFor("/pairings/"+e.keyID+"/complete"), request, &status); err != nil {
			return EnrollmentResult{}, errors.Join(ErrEnrollmentPending, err)
		}
		if err = e.validateStatus(status); err != nil {
			return EnrollmentResult{}, errors.Join(ErrEnrollmentPending, err)
		}
	}
	if status.State != "complete" || status.Approval == nil || !sameJSON(*status.Approval, e.receipt.Approval) {
		return EnrollmentResult{}, errors.Join(ErrEnrollmentPending, errors.New("completion does not acknowledge the exact dual-signed certificate"))
	}
	keepVerifier = true
	return EnrollmentResult{Receipt: cloneReceipt(*e.receipt), Sequence: *status.Sequence, Verifier: verifier}, nil
}
