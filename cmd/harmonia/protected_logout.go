package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"time"

	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/platform"
)

func protectedLocalLogout(ctx context.Context, directory, userID string, out io.Writer) (err error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return errors.New("此平台的受保护离线退出尚未实现")
	}
	if err = ctx.Err(); err != nil {
		return err
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
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, store.Close())
		}
	}()
	engine, e := localstate.New(store)
	if e != nil {
		return e
	}
	// 关闭状态先持久化；再次执行只完成剩余恢复，不重复推进 epoch。
	if !engine.State().AccountClosed {
		if e = engine.Logout(); e != nil {
			return e
		}
	}
	if e = wipeAccountSlots(store.Vault()); e != nil {
		return e
	}
	provider, e := platform.NewSecurePOSIXLogoutProvider(filepath.Join(directory, "environment.sh"), store.Vault())
	if e != nil {
		return e
	}
	if e = completeLocalRestoration(ctx, engine, provider, time.Now()); e != nil {
		return e
	}
	closed = true
	if e = store.Close(); e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(struct {
		Version  int  `json:"version"`
		Complete bool `json:"localLogoutComplete"`
	}{Version: 1, Complete: true})
}

type localLogoutProvider interface {
	localstate.Provider
	ValidateTrackedKeys([]string) error
	Finalize(context.Context) error
}

func completeLocalRestoration(ctx context.Context, engine *localstate.Engine, provider localLogoutProvider, now time.Time) error {
	state := engine.State()
	keys := make([]string, 0, len(state.Originals))
	for key := range state.Originals {
		keys = append(keys, key)
	}
	if err := provider.ValidateTrackedKeys(keys); err != nil {
		return err
	}
	if err := engine.Reconcile(ctx, provider, now); err != nil {
		return err
	}
	state = engine.State()
	if !state.AccountClosed || state.Cloud.AccountID != "" || state.Cloud.AccountGeneration != 0 || len(state.Cloud.Environments) != 0 || len(state.Active) != 0 || len(state.Overrides) != 0 || len(state.Managed) != 0 || len(state.Originals) != 0 || len(state.SafetyKeys) != 0 {
		return errors.New("本机退出或逐变量恢复尚未完成；保留材料")
	}
	return provider.Finalize(ctx)
}
