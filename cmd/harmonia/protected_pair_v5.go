package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/pairing"
	"github.com/harmonia-vault/core-go/syncclient"
)

func saveReceiptV5(vault *localkeys.Vault, session localkeys.LoginSession, keys localkeys.DeviceKeys, receipt syncclient.EnrollmentReceiptV5, accepted bool) error {
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	defer clear(data)
	// 保存前复验本机双方签名；不允许仅从服务器目录构造受保护来源。
	verifier, err := syncclient.NewPinnedVerifierV5(syncclient.IssuerDAGPinnedTrust{AccountID: session.AccountID, AccountGeneration: session.AccountGeneration, DeviceID: keys.DeviceID, DeviceSigningPublicKey: keys.SigningPublic, ReceivingPrivateKey: keys.ReceivingPrivate, Receipt: receipt})
	if err != nil {
		return err
	}
	verifier.Close()
	return vault.SaveTrustContext(localkeys.TrustContext{Endpoint: session.Endpoint, AccountID: session.AccountID, AccountGeneration: session.AccountGeneration, DeviceID: keys.DeviceID, SigningPublic: keys.SigningPublic, ReceivingPublic: keys.ReceivingPublic, CertificateVersion: "5", PairingProfile: pairing.Profile, EnrollmentCertificate: data, EnrollmentKey: receipt.IdempotencyKey, Accepted: accepted})
}

// 新 pair 明确使用 v5；已有 v1 待完成资料仍由旧入口以原证书恢复。
// 不支持 v5 的服务器会失败，不能悄悄降级至 v1 或扩展 Managers。
func protectedPairV5(ctx context.Context, o protectedOptions, r commandRuntime, out io.Writer, vault *localkeys.Vault, engine *localstate.Engine, session localkeys.LoginSession, keys localkeys.DeviceKeys, config syncclient.EnrollmentConfig, trust localkeys.TrustContext, hasTrust bool) error {
	if err := syncclient.CheckDAGCapability(ctx, config.Endpoint, config.HTTPClient); err != nil {
		return err
	}
	var enrollment *syncclient.EnrollmentV5
	var err error
	if hasTrust {
		if trust.Accepted {
			return errors.New("本机已经完成受保护入网；不重复生成短码")
		}
		receipt, err := syncclient.DecodeEnrollmentReceiptV5(trust.EnrollmentCertificate)
		if err != nil {
			return err
		}
		if trust.EnrollmentKey != receipt.IdempotencyKey {
			return errors.New("待完成 v5 收据与受保护上下文不匹配")
		}
		enrollment, err = syncclient.ResumeEnrollmentV5(config, receipt)
		if err != nil {
			return err
		}
		_, _ = io.WriteString(out, "正在查询同一待完成 v5 配对结果。\n")
	} else {
		if o.approver == "" {
			return errors.New("首次 pair 需要 --approver 既有可信管理手机设备ID")
		}
		enrollment, err = syncclient.NewEnrollmentV5(config)
		if err != nil {
			return err
		}
		code, err := pairing.GenerateShortCode()
		if err != nil {
			enrollment.Close()
			return err
		}
		defer clear(code)
		key, err := randomLocalID("pair-")
		if err != nil {
			enrollment.Close()
			return err
		}
		if r.pairingProgress != nil {
			r.pairingProgress(key, code)
		}
		if _, err = enrollment.Begin(ctx, o.approver, key, code); err != nil {
			enrollment.Close()
			return err
		}
		_, _ = fmt.Fprintf(out, "配对申请：%s\n请在管理手机输入本机短码：%s\n由手机确认环境、角色和期限；使用 issuer-recovery-dag-v1。\n", key, string(code))
		for {
			if _, err = enrollment.Advance(ctx); err != nil {
				enrollment.Close()
				return err
			}
			receipt, receiptErr := enrollment.Receipt()
			if receiptErr == nil {
				if err = saveReceiptV5(vault, session, keys, receipt, false); err != nil {
					enrollment.Close()
					return err
				}
				break
			}
			select {
			case <-ctx.Done():
				enrollment.Close()
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	defer enrollment.Close()
	result, err := enrollment.Complete(ctx)
	if err != nil {
		return err
	}
	defer result.Verifier.Close()
	if err = engine.CompleteEnrollmentAtEpoch(protectedEnrollmentEpoch(engine, r)); err != nil {
		return err
	}
	if err = saveReceiptV5(vault, session, keys, result.Receipt, true); err != nil {
		return err
	}
	if err = vault.Delete("session-v1"); err != nil {
		return err
	}
	_, err = io.WriteString(out, "设备 v5 配对已完成并加密保存；共享配置将经持钥会话与逐环境验签拉取下发。\n")
	return err
}
