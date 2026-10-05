//go:build windows

// 此命令仅验收新合成账号的原生 provider；不能据此授予云设备信任。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"

	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/platform"
	"github.com/harmonia-vault/core-go/windowsservice"
	"golang.org/x/sys/windows/svc"
)

type probe struct {
	c          windowsservice.Config
	resultPath string
}

func (p probe) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.Running, Accepts: 0}
	ctx := context.Background()
	stage := p.check(ctx)
	result := map[string]any{"scope": "native-provider-only", "stage": stage, "pass": stage == "complete"}
	b, _ := json.Marshal(result)
	if os.WriteFile(p.resultPath, b, 0600) != nil {
		return true, 2
	}
	if stage != "complete" {
		return true, 1
	}
	return false, 0
}
func (p probe) check(ctx context.Context) string {
	store, err := windowsservice.NewProfileClient(ctx, p.c)
	if err != nil {
		return "client-identity"
	}
	// 新 profile 的这三个固定合成 key 必须为空；不会枚举或读取其它环境。
	for _, n := range []string{"HARMONIA_NATIVE_ORIGINAL", "HARMONIA_NATIVE_ADDED", "HARMONIA_NATIVE_UNRELATED"} {
		_, exists, e := store.Read(n)
		if e != nil {
			return "initial-read"
		}
		if exists {
			return "preexisting-test-key"
		}
	}
	original := platform.RegistryValue{Value: "%HARMONIA_SYNTHETIC_BASE%\\literal", Expand: true}
	if store.Set("HARMONIA_NATIVE_ORIGINAL", original) != nil || store.Set("HARMONIA_NATIVE_UNRELATED", platform.RegistryValue{Value: "synthetic-unrelated"}) != nil {
		return "seed"
	}
	directory := filepath.Dir(p.resultPath)
	config := localkeys.Config{Directory: directory, UserID: p.c.TargetSID, ServiceSID: p.c.SyncServiceSID}
	vault, e := localkeys.Open(config)
	if e != nil {
		return "dpapi-open"
	}
	provider, e := platform.NewSecureWindowsProvider(p.c.TargetSID, store, vault)
	if e != nil {
		vault.Close()
		return "provider-open"
	}
	cloud := "synthetic-cloud"
	changes := []localstate.Change{{Name: "HARMONIA_NATIVE_ORIGINAL", Value: &cloud}, {Name: "HARMONIA_NATIVE_ADDED", Value: &cloud}}
	if provider.Apply(ctx, changes) != nil {
		vault.Close()
		return "provider-apply"
	}
	if value, exists, e := store.Read("HARMONIA_NATIVE_ORIGINAL"); e != nil || !exists || value.Value != cloud || value.Expand {
		vault.Close()
		return "cloud-readback"
	}
	if vault.Close() != nil {
		return "dpapi-close"
	}
	vault, e = localkeys.Open(config)
	if e != nil {
		return "dpapi-reopen"
	}
	defer vault.Close()
	provider, e = platform.NewSecureWindowsProvider(p.c.TargetSID, store, vault)
	if e != nil {
		return "provider-reopen"
	}
	if provider.Apply(ctx, []localstate.Change{{Name: "HARMONIA_NATIVE_ORIGINAL", Release: true}, {Name: "HARMONIA_NATIVE_ADDED", Release: true}}) != nil {
		return "release"
	}
	if value, exists, e := store.Read("HARMONIA_NATIVE_ORIGINAL"); e != nil || !exists || value != original {
		return "original-type-restore"
	}
	if _, exists, e := store.Read("HARMONIA_NATIVE_ADDED"); e != nil || exists {
		return "added-delete"
	}
	if value, exists, e := store.Read("HARMONIA_NATIVE_UNRELATED"); e != nil || !exists || value.Value != "synthetic-unrelated" {
		return "unrelated-preserve"
	}
	// 第二次接管重新采集被外部显式改动的类型，不能恢复前一次旧 metadata。
	next := platform.RegistryValue{Value: "synthetic-second-original"}
	if store.Set("HARMONIA_NATIVE_ORIGINAL", next) != nil {
		return "second-original"
	}
	if provider.Apply(ctx, []localstate.Change{{Name: "HARMONIA_NATIVE_ORIGINAL", Value: &cloud}}) != nil || provider.Apply(ctx, []localstate.Change{{Name: "HARMONIA_NATIVE_ORIGINAL", Release: true}}) != nil {
		return "second-release"
	}
	if value, exists, e := store.Read("HARMONIA_NATIVE_ORIGINAL"); e != nil || !exists || value != next {
		return "second-type-restore"
	}
	return "complete"
}
func main() {
	cpath := flag.String("config", "", "受保护的合成测试配置")
	flag.Parse()
	if *cpath == "" || flag.NArg() != 0 {
		os.Exit(2)
	}
	locked, e := windowsservice.LoadConfig(*cpath)
	if e != nil {
		os.Exit(3)
	}
	defer locked.Close()
	if ok, e := svc.IsWindowsService(); e != nil || !ok {
		os.Exit(4)
	}
	result := filepath.Join(filepath.Dir(*cpath), "vault", "result.json")
	if svc.Run(locked.Config.SyncServiceName(), probe{c: locked.Config, resultPath: result}) != nil {
		os.Exit(5)
	}
}
