package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"runtime"

	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
)

// 此检查只证明本地材料可核验；正式启动仍须在线 Boot 验证当前授权。
func protectedEnrollmentCheck(ctx context.Context, directory, userID string, out io.Writer) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return errors.New("此平台的本机入网检查尚未实现")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	current, e := localkeys.CurrentUserID()
	if e != nil || current == "0" || userID == "" || userID != current {
		return localkeys.ErrIdentity
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return localkeys.ErrPermission
	}
	store, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: directory, UserID: userID})
	if e != nil {
		return e
	}
	return checkAndCloseLocalEnrollment(ctx, store, out)
}

type enrollmentStore interface {
	localstate.Store
	Vault() *localkeys.Vault
	Close() error
}

func checkAndCloseLocalEnrollment(ctx context.Context, store enrollmentStore, out io.Writer) (err error) {
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, store.Close())
		}
	}()
	if err = ctx.Err(); err != nil {
		return err
	}
	engine, e := localstate.New(store)
	if e != nil {
		return e
	}
	state := engine.State()
	if state.AccountClosed {
		return errors.New("本机账号已退出；需要重新授权")
	}
	trust, e := store.Vault().LoadTrustContext()
	if e != nil {
		return e
	}
	keys, e := store.Vault().LoadDeviceKeys()
	defer clear(keys.SigningSeed)
	defer clear(keys.ReceivingPrivate)
	if e != nil {
		return e
	}
	verifier, e := verifiedStoredContext(trust, keys, state.Cloud)
	if e != nil {
		return e
	}
	verifier.Close()
	clear(keys.SigningSeed)
	clear(keys.ReceivingPrivate)
	if e = ctx.Err(); e != nil {
		return e
	}
	closed = true
	if e = store.Close(); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(struct {
		Version  int  `json:"version"`
		Verified bool `json:"localEnrollmentVerified"`
	}{Version: 1, Verified: true})
}
