// harmonia 首版 CLI 的云端信任入口仍关闭；隔离 fixture 用于验证本地行为。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/platform"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "harmonia:", err)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("用法：harmonia <status|activate|deactivate|override-set|override-remove|pause|resume|reconcile|logout|export|exec|daemon|fixture-load|import-preview|shell-hook> --state <私有状态文件>")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	statePath := flags.String("state", "", "当前用户的私有状态文件")
	providerPath := flags.String("provider-file", "", "仅用于隔离测试的 JSON 环境文件")
	fixture := flags.Bool("fixture", false, "显式启用合成测试；禁止作为设备 enrollment")
	input := flags.String("input", "", "合成 cloud snapshot JSON")
	environment := flags.String("environment", "", "环境 ID")
	name := flags.String("name", "", "变量名")
	value := flags.String("value", "", "本机 override 值")
	priority := flags.Int("priority", 0, "更大的优先级覆盖同名变量")
	interval := flags.Duration("interval", 2*time.Second, "daemon 本地收敛间隔")
	once := flags.Bool("once", false, "daemon 仅执行一次测试收敛")
	localUser := flags.String("local-user", "", "服务明确绑定的本地 uid/SID")
	fragment := flags.String("platform-fragment", "", "明确指定的隔离 POSIX fragment")
	windowsService := flags.String("windows-service", "", "Windows SCM 服务名")
	from := flags.String("from", "", "待选变量 JSON 文件；不会扫描宿主环境")
	selected := flags.String("select", "", "明确选择的逗号分隔变量名")
	shell := flags.String("shell", "sh", "sh/bash/zsh hook")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if command == "shell-hook" {
		hook, err := platform.RenderShellHook(*shell, *fragment)
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, hook)
		return err
	}
	if command == "import-preview" {
		var candidates map[string]string
		if err := decodeFile(*from, &candidates); err != nil {
			return err
		}
		var selections []string
		if *selected != "" {
			selections = strings.Split(*selected, ",")
		}
		preview, err := localstate.SelectImport(candidates, selections)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(preview)
	}
	if command == "put" || command == "delete" || command == "import" || command == "login" || command == "pair" {
		return errors.New("可信设备 enrollment 与受保护凭据存储尚未完成；正式云端命令保持关闭，不能离线共享写入")
	}
	if *statePath == "" {
		return errors.New("必须明确指定 --state；不会读取宿主默认目录")
	}
	store, err := localstate.OpenFileStore(*statePath)
	if err != nil {
		return err
	}
	defer store.Close()
	engine, err := localstate.New(store)
	if err != nil {
		return err
	}
	if engine.State().Synthetic && !*fixture {
		return errors.New("该状态仅含合成 fixture；必须明确 --fixture")
	}
	makeProvider := func() (localstate.Provider, error) {
		if !*fixture || !engine.State().Synthetic {
			return nil, errors.New("正式系统下发需可信 enrollment、机器保护和用户隔离；当前只接受明确合成 fixture")
		}
		if *providerPath != "" && *fragment != "" {
			return nil, errors.New("一次只能选择一个 provider")
		}
		if *providerPath != "" {
			absolute, err := filepath.Abs(*providerPath)
			if err != nil {
				return nil, err
			}
			return &localstate.FileProvider{Path: absolute}, nil
		}
		if *fragment != "" {
			return platform.NewPOSIXProvider(*fragment, nil)
		}
		return nil, errors.New("必须指定隔离 --provider-file 或 --platform-fragment")
	}
	now := time.Now()
	switch command {
	case "status":
		s := engine.State()
		return json.NewEncoder(out).Encode(struct {
			Version            int                     `json:"version"`
			Synthetic          bool                    `json:"synthetic"`
			AccountGeneration  uint64                  `json:"accountGeneration"`
			Sequence           uint64                  `json:"sequence"`
			Environments       int                     `json:"environments"`
			Active             []localstate.Activation `json:"active"`
			Paused             bool                    `json:"paused"`
			PendingRestoration int                     `json:"pendingRestoration"`
		}{s.Version, s.Synthetic, s.Cloud.AccountGeneration, s.Cloud.Sequence, len(s.Cloud.Environments), s.Active, s.Paused, len(s.Originals)})
	case "fixture-load":
		if !*fixture {
			return errors.New("fixture-load 需要 --fixture")
		}
		if s := engine.State(); s.Cloud.AccountID != "" && !s.Synthetic {
			return errors.New("不能覆盖非 fixture 状态")
		}
		var cloud localstate.CloudSnapshot
		if err = decodeFile(*input, &cloud); err != nil {
			return err
		}
		if err = engine.EnableSyntheticFixtures(); err != nil {
			return err
		}
		err = engine.AcceptSnapshot(cloud, now)
	case "activate":
		err = engine.Activate(*environment, *priority, now)
	case "deactivate":
		err = engine.Deactivate(*environment)
	case "override-set":
		err = engine.SetOverride(*environment, *name, *value, now)
	case "override-remove":
		err = engine.RemoveOverride(*environment, *name)
	case "pause":
		err = engine.SetPaused(true)
	case "resume":
		err = engine.SetPaused(false)
	case "logout":
		err = engine.Logout()
	case "reconcile":
		provider, providerErr := makeProvider()
		if providerErr != nil {
			return providerErr
		}
		return engine.Reconcile(ctx, provider, now)
	case "export":
		effective, err := engine.Effective(now)
		if err != nil {
			return err
		}
		keys := sortedKeys(effective)
		for _, key := range keys {
			quote, err := platform.ShellQuote(effective[key])
			if err != nil {
				return err
			}
			if _, err = fmt.Fprintf(out, "export %s=%s\n", key, quote); err != nil {
				return err
			}
		}
		return nil
	case "exec":
		effective, err := engine.Effective(now)
		if err != nil {
			return err
		}
		remaining := flags.Args()
		if len(remaining) == 0 {
			return errors.New("exec 后需要 -- <程序> [参数]")
		}
		child := exec.CommandContext(ctx, remaining[0], remaining[1:]...)
		child.Env = composeEnvironment(os.Environ(), effective, engine.State().Originals)
		child.Stdout = out
		child.Stderr = errOut
		child.Stdin = os.Stdin
		return child.Run()
	case "daemon":
		if !*fixture {
			return errors.New("正式开机服务尚缺可信设备 enrollment、机器保护与本地 IPC；保持关闭")
		}
		if *localUser != "" {
			if strings.ContainsAny(*localUser, "\x00\r\n") {
				return errors.New("invalid local identity")
			}
		}
		if *interval < 10*time.Millisecond {
			return errors.New("interval 至少 10ms")
		}
		provider, providerErr := makeProvider()
		if providerErr != nil {
			return providerErr
		}
		loop := func(runCtx context.Context) error {
			if err := engine.Reconcile(runCtx, provider, time.Now()); err != nil {
				return err
			}
			if *once {
				return nil
			}
			ticker := time.NewTicker(*interval)
			defer ticker.Stop()
			for {
				select {
				case <-runCtx.Done():
					return nil
				case now := <-ticker.C:
					if err := engine.Reconcile(runCtx, provider, now); err != nil {
						return err
					}
				}
			}
		}
		daemonCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if *windowsService != "" {
			return platform.RunWindowsService(daemonCtx, *windowsService, loop)
		}
		return loop(daemonCtx)
	default:
		return fmt.Errorf("未知命令 %s", command)
	}
	if err != nil {
		return err
	}
	if *providerPath != "" || *fragment != "" {
		provider, err := makeProvider()
		if err != nil {
			return err
		}
		return engine.Reconcile(ctx, provider, time.Now())
	}
	return nil
}
func decodeFile(path string, value any) error {
	if path == "" {
		return errors.New("必须指定输入文件")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 16<<20))
	dec.DisallowUnknownFields()
	if err = dec.Decode(value); err != nil {
		return err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("只接受一个 JSON 对象")
	}
	return nil
}
func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func composeEnvironment(base []string, desired map[string]string, originals map[string]localstate.Original) []string {
	// 只替换托管名称；其它 inherited 项保持原样。此处不做导入/上传。
	values := map[string]string{}
	for _, entry := range base {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	for key, original := range originals {
		if _, active := desired[key]; !active {
			if original.Present {
				values[key] = original.Value
			} else {
				delete(values, key)
			}
		}
	}
	for key, value := range desired {
		values[key] = value
	}
	keys := sortedKeys(values)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+values[key])
	}
	return out
}
