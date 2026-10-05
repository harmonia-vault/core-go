package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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
	input           io.Reader
	httpClient      *http.Client
	now             func() time.Time
	provider        localstate.Provider
	environment     importEnvironment
	loginCredential []byte
	pairingProgress func(string, []byte)
	enrollmentEpoch *uint64
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
func protectedAccountCommand(ctx context.Context, o protectedOptions, r commandRuntime, out, errOut io.Writer) error {
	if runtime.GOOS == "windows" {
		return errors.New("Windows 登录与配对须通过专用系统服务；当前用户账号 IPC 尚未验收，不能直接打开 Vault")
	}
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
	return protectedAccountOnOwner(ctx, o, r, out, errOut, store, engine)
}

// owner只借用已经独占打开的Store/Engine；不再打开第二份Vault。
func protectedAccountOnOwner(ctx context.Context, o protectedOptions, r commandRuntime, out, errOut io.Writer, store *localkeys.StateStore, engine *localstate.Engine) error {
	if o.command == "pair" && !pairing.NativeAvailable() {
		return pairing.ErrUnavailable
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
		var hash [32]byte
		if r.loginCredential != nil {
			if len(r.loginCredential) != len(hash) {
				return errors.New("无效本机登录凭据")
			}
			copy(hash[:], r.loginCredential)
		} else {
			password, err := readLoginPassword(r.input, o.passwordStdin, errOut)
			if err != nil {
				return err
			}
			defer clear(password)
			hash = cryptox.PasswordCredential(string(password))
		}
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
	trust, trustErr := vault.LoadTrustContext()
	if trustErr != nil && !errors.Is(trustErr, os.ErrNotExist) {
		return trustErr
	}
	if trustErr == nil && trust.CertificateVersion != "5" {
		return errors.New("配对资料无法使用，请重新配对")
	}
	return protectedPairV5(ctx, o, r, out, vault, engine, session, keys, config, trust, trustErr == nil)
}
