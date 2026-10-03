package mobileworkflow

import (
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

func (w *Workflow) recoveryEnvironmentMode() bool {
	return w.state.RecoveredDevice != nil && w.state.RecoveredDevice.Applied
}

// 本机历史 journal 重验不需要发 HTTP，也不建立当前会话或权限。
func (w *Workflow) environmentJournalClient() (*syncclient.Client, func(), error) {
	verifier, err := w.originVerifier()
	if err != nil {
		return nil, nil, err
	}
	generation, err := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if err != nil {
		verifier.Close()
		return nil, nil, err
	}
	client, err := syncclient.NewForBoot(syncclient.Config{Endpoint: w.state.Endpoint, HTTPClient: w.http, AccountID: w.state.AccountID, AccountGeneration: generation, DeviceID: w.state.DeviceID, Verifier: verifier, Engine: w.engine, Now: w.now})
	if err != nil {
		verifier.Close()
		return nil, nil, err
	}
	return client, verifier.Close, nil
}

// 新恢复公钥只能取自完整已验证并受保护保存的当前账本。
// 原 Root 设备 pin 和原双签初始化从未由 HTTP 目录替换。
func (w *Workflow) environmentRecoveryRecipient() (cryptox.TrustRoot, error) {
	if w.state.Root == nil {
		return cryptox.TrustRoot{}, ErrNotTrusted
	}
	if !w.recoveryEnvironmentMode() {
		return *w.state.Root, nil
	}
	client := w.client
	if client == nil {
		var close func()
		var err error
		client, close, err = w.environmentJournalClient()
		if err != nil {
			return cryptox.TrustRoot{}, err
		}
		defer close()
	}
	proof, err := client.CurrentIssuerRecoveryEvidence()
	if err != nil {
		return cryptox.TrustRoot{}, err
	}
	pin := w.state.RecoveredDevice.Pin
	root := proof.TrustRoot
	if proof.AccountID != pin.AccountID || proof.AccountGeneration != pin.AccountGeneration || root.RootDeviceID != pin.DeviceID || root.RootSigningPublicKey != pin.SigningPublicKey || root.RootReceivingPublicKey != pin.ReceivingPublicKey {
		return cryptox.TrustRoot{}, ErrRecoveryEvidence
	}
	return root, nil
}
