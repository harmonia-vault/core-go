package syncclient

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
)

// IssuerPinnedTrust 只接受本机已签的受保护完整回执，不能传全局 Managers。
// 新设备签名证明本机已确认该 PAKE 锚；账号登录/服务器目录不能替代它。
type IssuerPinnedTrust struct {
	AccountID              string
	AccountGeneration      uint64
	DeviceID               string
	DeviceSigningPublicKey ed25519.PublicKey
	ReceivingPrivateKey    []byte
	Receipt                EnrollmentReceiptV2
	Now                    func() time.Time
}

func NewPinnedVerifierV2(t IssuerPinnedTrust) (*PinnedVerifier, error) {
	a := t.Receipt.Approval
	anchor := cryptox.ConfirmedEnrollmentAnchor{Context: a.Context, TranscriptHash: a.TranscriptHash}
	proof, err := cryptox.VerifyCompletedEnrollmentV2(anchor, a)
	if err != nil {
		return nil, err
	}
	return newIssuerPinnedVerifier(t, proof)
}
func newIssuerPinnedVerifier(t IssuerPinnedTrust, p *cryptox.VerifiedIssuerProof) (*PinnedVerifier, error) {
	if p == nil || t.AccountID == "" || t.AccountGeneration == 0 || t.DeviceID == "" || len(t.DeviceSigningPublicKey) != ed25519.PublicKeySize || !enrollmentID.MatchString(t.Receipt.IdempotencyKey) {
		return nil, errors.New("incomplete v2 trusted context")
	}
	sk, err := ecdh.X25519().NewPrivateKey(t.ReceivingPrivateKey)
	if err != nil {
		return nil, err
	}
	c := t.Receipt.Approval.Context
	receiving := cryptox.EncodeBase64(sk.PublicKey().Bytes())
	if c.AccountID != t.AccountID || c.AccountGeneration != strconv.FormatUint(t.AccountGeneration, 10) || c.InitiatorDeviceID != t.DeviceID || c.InitiatorSigningPublicKey != cryptox.EncodeBase64(t.DeviceSigningPublicKey) || c.InitiatorReceivingPublicKey != receiving || t.Receipt.Approval.CertificateVersion != "2" {
		return nil, errors.New("v2 receipt does not bind exact protected local account/device keys")
	}
	if t.Now == nil {
		t.Now = time.Now
	}
	return &PinnedVerifier{trust: PinnedTrust{AccountID: t.AccountID, AccountGeneration: t.AccountGeneration, DeviceID: t.DeviceID, DeviceSigningPublicKey: bytes.Clone(t.DeviceSigningPublicKey), ReceivingPrivateKey: bytes.Clone(t.ReceivingPrivateKey), Now: t.Now}, receivingPublicKey: receiving, issuerProof: p}, nil
}

// IssuerBindings 返回历史逐环境来源副本，不提供当前管理权限或恢复授权锚。
func (v *PinnedVerifier) IssuerBindings() []cryptox.IssuerBinding {
	if v.issuerProof == nil {
		return nil
	}
	return v.issuerProof.IssuerBindings()
}
