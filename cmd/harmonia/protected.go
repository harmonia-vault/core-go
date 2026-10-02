package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/pairing"
	"github.com/harmonia-vault/core-go/syncclient"
	"golang.org/x/term"
)

type commandRuntime struct {
	input      io.Reader
	httpClient *http.Client
	now        func() time.Time
	provider   localstate.Provider
}
type protectedOptions struct {
	command, directory, server, email, approver, userID, serviceSID string
	passwordStdin                                                   bool
}

func protectedStore(o protectedOptions) (*localkeys.StateStore, error) {
	absolute, err := filepath.Abs(o.directory)
	if err != nil || absolute == "" {
		return nil, errors.New("必须明确受保护本地目录")
	}
	if o.userID == "" {
		o.userID, err = localkeys.CurrentUserID()
		if err != nil {
			return nil, err
		}
	}
	return localkeys.OpenEncryptedStateStore(localkeys.Config{Directory: absolute, UserID: o.userID, ServiceSID: o.serviceSID})
}
func readLoginPassword(input io.Reader, stdin bool, errOut io.Writer) ([]byte, error) {
	if stdin {
		if input == nil {
			return nil, errors.New("--password-stdin 需要明确标准输入")
		}
		// 一行密码，删除行结束符；不接收命令行或环境变量中的密码。
		reader := bufio.NewReader(io.LimitReader(input, 65538))
		line, err := reader.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return nil, errors.New("无法读取密码标准输入")
		}
		line = []byte(strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"))
		if len(line) == 0 || len(line) > 65536 || strings.ContainsAny(string(line), "\x00\r\n") {
			clear(line)
			return nil, errors.New("无效密码输入")
		}
		return line, nil
	}
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil, errors.New("交互登录需要终端，管道输入须明确 --password-stdin")
	}
	_, _ = io.WriteString(errOut, "密码：")
	password, err := term.ReadPassword(int(file.Fd()))
	_, _ = io.WriteString(errOut, "\n")
	if err != nil {
		return nil, errors.New("终端密码输入失败")
	}
	if len(password) == 0 || len(password) > 65536 {
		clear(password)
		return nil, errors.New("无效密码长度")
	}
	return password, nil
}
func randomLocalID(prefix string) (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return prefix + cryptox.EncodeBase64(data), nil
}
func decodeReceipt(data []byte) (syncclient.EnrollmentReceipt, error) {
	var receipt syncclient.EnrollmentReceipt
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&receipt) != nil || decoder.Decode(&extra) != io.EOF {
		return receipt, errors.New("受保护入网收据格式错误")
	}
	return receipt, nil
}
func saveReceipt(vault *localkeys.Vault, session localkeys.LoginSession, keys localkeys.DeviceKeys, receipt syncclient.EnrollmentReceipt, accepted bool) error {
	manager, err := cryptox.DecodeBase64(receipt.Approval.Context.ApproverSigningPublicKey, 32, 32)
	if err != nil {
		return err
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	defer clear(data)
	return vault.SaveTrustContext(localkeys.TrustContext{Endpoint: session.Endpoint, AccountID: session.AccountID, AccountGeneration: session.AccountGeneration, DeviceID: keys.DeviceID, SigningPublic: keys.SigningPublic, ReceivingPublic: keys.ReceivingPublic, Managers: map[string][]byte{receipt.Approval.Context.ApproverDeviceID: manager}, PairingProfile: pairing.Profile, EnrollmentCertificate: data, EnrollmentKey: receipt.IdempotencyKey, Accepted: accepted})
}
func protectedAccountCommand(ctx context.Context, o protectedOptions, r commandRuntime, out, errOut io.Writer) error {
	if o.command == "pair" && !pairing.NativeAvailable() {
		return pairing.ErrUnavailable
	}
	store, err := protectedStore(o)
	if err != nil {
		return err
	}
	defer store.Close()
	engine, err := localstate.New(store)
	if err != nil {
		return err
	}
	vault := store.Vault()
	if o.command == "login" {
		if o.server == "" || o.email == "" {
			return errors.New("login 需要 --server HTTPS地址 和 --email")
		}
		if _, err := vault.LoadTrustContext(); err == nil {
			return errors.New("已有入网或待完成收据；先完成配对或退出账号，不能覆盖账号上下文")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if engine.State().Cloud.AccountID != "" || len(engine.State().Originals) != 0 {
			return errors.New("旧托管配置尚未恢复，不能切换账号")
		}
		password, err := readLoginPassword(r.input, o.passwordStdin, errOut)
		if err != nil {
			return err
		}
		defer clear(password)
		hash := cryptox.PasswordCredential(string(password))
		result, err := syncclient.Login(ctx, syncclient.LoginConfig{Endpoint: o.server, HTTPClient: r.httpClient, Email: o.email, Credential: hex.EncodeToString(hash[:]), Now: r.now})
		clear(hash[:])
		if err != nil {
			return err
		}
		generation, _ := strconv.ParseUint(result.AccountGeneration, 10, 64)
		session := localkeys.LoginSession{Endpoint: o.server, AccountID: result.AccountID, AccountGeneration: generation, Token: result.Token, ExpiresAt: time.Unix(result.ExpiresAt, 0).UTC().Format(time.RFC3339)}
		if previous, err := vault.LoadSession(); err == nil && (previous.Endpoint != session.Endpoint || previous.AccountID != session.AccountID || previous.AccountGeneration != session.AccountGeneration) {
			return errors.New("本地已有其它登录上下文；先明确退出，不覆盖已有资料")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err = vault.SaveSession(session); err != nil {
			return err
		}
		_, err = io.WriteString(out, "登录会话已加密保存；此设备尚未可信。\n")
		return err
	}
	if o.command != "pair" {
		return errors.New("受保护账号入口仅接受 login/pair")
	}
	session, err := vault.LoadSession()
	if err != nil {
		return err
	}
	now := time.Now()
	if r.now != nil {
		now = r.now()
	}
	expires, err := time.Parse(time.RFC3339, session.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return errors.New("登录会话已到期；不能用过期会话完成入网")
	}
	keys, err := vault.LoadDeviceKeys()
	if errors.Is(err, os.ErrNotExist) {
		id, e := randomLocalID("device-")
		if e != nil {
			return e
		}
		keys, err = localkeys.GenerateDeviceKeys(id)
		if err != nil {
			return err
		}
		if err = vault.SaveDeviceKeys(keys); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	defer clear(keys.SigningSeed)
	defer clear(keys.ReceivingPrivate)
	signing := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer clear(signing)
	config := syncclient.EnrollmentConfig{Endpoint: session.Endpoint, HTTPClient: r.httpClient, AccountID: session.AccountID, AccountGeneration: session.AccountGeneration, DeviceID: keys.DeviceID, LoginToken: session.Token, SigningKey: signing, ReceivingPrivateKey: keys.ReceivingPrivate, Engine: engine, Now: r.now}
	var enrollment *syncclient.Enrollment
	trust, trustErr := vault.LoadTrustContext()
	if errors.Is(trustErr, os.ErrNotExist) || trustErr == nil && trust.CertificateVersion == "2" {
		return protectedPairV2(ctx, o, r, out, vault, engine, session, keys, config, trust, trustErr == nil)
	}
	if trustErr == nil {
		if trust.Accepted {
			return errors.New("本机已经完成受保护入网；不重复生成短码")
		}
		receipt, err := decodeReceipt(trust.EnrollmentCertificate)
		if err != nil {
			return err
		}
		if trust.EnrollmentKey != receipt.IdempotencyKey {
			return errors.New("待完成收据与受保护上下文不匹配")
		}
		enrollment, err = syncclient.ResumeEnrollment(config, receipt)
		if err != nil {
			return err
		}
		_, _ = io.WriteString(out, "正在查询同一待完成配对结果。\n")
	} else if errors.Is(trustErr, os.ErrNotExist) {
		if o.approver == "" {
			return errors.New("首次 pair 需要 --approver 既有可信管理手机设备ID")
		}
		enrollment, err = syncclient.NewEnrollment(config)
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
		if _, err = enrollment.Begin(ctx, o.approver, key, code); err != nil {
			enrollment.Close()
			return err
		}
		_, _ = fmt.Fprintf(out, "配对申请：%s\n请在管理手机输入本机短码：%s\n由手机确认环境、角色和期限。\n", key, string(code))
		for {
			if _, err = enrollment.Advance(ctx); err != nil {
				enrollment.Close()
				return err
			}
			receipt, receiptErr := enrollment.Receipt()
			if receiptErr == nil {
				if err = saveReceipt(vault, session, keys, receipt, false); err != nil {
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
	} else {
		return trustErr
	}
	defer enrollment.Close()
	result, err := enrollment.Complete(ctx)
	if err != nil {
		return err
	}
	defer result.Verifier.Close()
	// Complete已确认双方签证与服务器ack；unknown/pending分支不会到此。
	if err = engine.CompleteEnrollmentAtEpoch(engine.State().SessionEpoch); err != nil {
		return err
	}
	if err = saveReceipt(vault, session, keys, result.Receipt, true); err != nil {
		return err
	}
	if err = vault.Delete("session-v1"); err != nil {
		return err
	}
	// 尚未应用共享值；启动可信后台后持钥 boot，再走同一验签 pull 下发流。
	_, err = io.WriteString(out, "设备配对已完成并加密保存；共享配置将经持钥会话与验签拉取下发。\n")
	return err
}
