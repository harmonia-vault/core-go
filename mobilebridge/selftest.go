package mobilebridge

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/pairing"
	"strconv"
	"time"
)

// NativeSelfTest 仅使用新生成的合成钥匙，在实际 Go/Android 原生库内验证密码学。
// 原生 SPAKE2 未链接时失败，不把编译能力伪装为可信手机就绪。
func NativeSelfTest() (string, error) {
	if !pairing.NativeAvailable() {
		return "", pairing.ErrUnavailable
	}
	digest, _ := Hash256([]byte("abc"))
	if cryptox.EncodeBase64(digest) != "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		return "", errors.New("SHA256 vector failed")
	}
	a, err := NewDevice()
	if err != nil {
		return "", err
	}
	defer a.Close()
	b, err := NewDevice()
	if err != nil {
		return "", err
	}
	defer b.Close()
	if err = checkCrypto(a.signing, a.receiving); err != nil {
		return "", err
	}
	ar, _ := ecdh.X25519().NewPrivateKey(a.receiving)
	br, _ := ecdh.X25519().NewPrivateKey(b.receiving)
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	c := pairing.Context{AccountID: "native-check", AccountGeneration: "1", Purpose: pairing.PurposeEnrollment, SessionID: "native-selftest", ChallengeNonce: cryptox.EncodeBase64(nonce), ExpiresAt: strconv.FormatInt(time.Now().Unix()+90, 10), InitiatorDeviceID: "new-device", InitiatorSigningPublicKey: cryptox.EncodeBase64(a.signing.Public().(ed25519.PublicKey)), InitiatorReceivingPublicKey: cryptox.EncodeBase64(ar.PublicKey().Bytes()), ApproverDeviceID: "admin-device", ApproverSigningPublicKey: cryptox.EncodeBase64(b.signing.Public().(ed25519.PublicKey)), ApproverReceivingPublicKey: cryptox.EncodeBase64(br.PublicKey().Bytes())}
	code, err := pairing.GenerateShortCode()
	if err != nil {
		return "", err
	}
	defer clear(code)
	initiator, ma, err := pairing.NewInitiator(c, code)
	if err != nil {
		return "", err
	}
	defer initiator.Close()
	approver, mb, err := pairing.NewApprover(c, code)
	if err != nil {
		return "", err
	}
	defer approver.Close()
	ca, err := initiator.Complete(mb)
	if err != nil {
		return "", err
	}
	cb, err := approver.Complete(ma)
	if err != nil {
		return "", err
	}
	if key, err := initiator.SessionKey(); err == nil {
		clear(key)
		return "", errors.New("unconfirmed pairing key exposed")
	}
	if err = initiator.VerifyPeerConfirmation(cb); err != nil {
		return "", err
	}
	if err = approver.VerifyPeerConfirmation(ca); err != nil {
		return "", err
	}
	ka, err := initiator.SessionKey()
	if err != nil {
		return "", err
	}
	defer clear(ka)
	kb, err := approver.SessionKey()
	if err != nil {
		return "", err
	}
	defer clear(kb)
	if len(ka) != 32 || !bytes.Equal(ka, kb) {
		return "", errors.New("native pairing check failed")
	}
	if err = initiator.VerifyPeerConfirmation(cb); err == nil {
		return "", errors.New("pairing confirmation replay accepted")
	}
	return encode(map[string]any{"version": 1, "sha256": true, "ed25519": true, "hpke": true, "aead": true, "spake2": true, "tamperingRejected": true, "confirmationGate": true, "synthetic": true, "realVaultReady": false})
}
