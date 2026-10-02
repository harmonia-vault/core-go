// harmonia CLI 的共享数据只经可信入网、受保护状态与验签下发；fixture 单独隔离。
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
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/harmonia-vault/core-go/localipc"
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
	return runWithRuntime(ctx, args, out, errOut, commandRuntime{input: os.Stdin})
}
func runWithRuntime(ctx context.Context, args []string, out, errOut io.Writer, runtimeOptions commandRuntime) error {
	if len(args) == 0 {
		return errors.New("用法：harmonia <login|pair|daemon|status|activate|priority|deactivate|override-set|override-remove|pause|resume|logout|export|exec> --local-directory <受保护目录>；合成测试另用 --fixture --state")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	statePath := flags.String("state", "", "当前用户的私有 fixture 状态文件")
	localDirectory := flags.String("local-directory", "", "受保护机器状态目录；与明文fixture互斥")
	serverAddress := flags.String("server", "", "用户明确指定的自托管 HTTPS 地址")
	email := flags.String("email", "", "邮箱登录账号")
	approver := flags.String("approver", "", "既有可信管理手机的设备 ID")
	importStdin := flags.Bool("import-stdin", false, "从标准输入读取候选JSON，只导入select选中项")
	valueStdin := flags.Bool("value-stdin", false, "明确从标准输入读取完整UTF8值，不使用argv")
	requestID := flags.String("request-id", "", "本机共享写幂等ID；可用于write-retry")
	caFile := flags.String("ca-file", "", "用户明确指定的自托管PEM CA；保留标准HTTPS验证")
	passwordStdin := flags.Bool("password-stdin", false, "明确从标准输入读取一行密码，绝不从环境或参数读取")
	providerPath := flags.String("provider-file", "", "仅用于隔离测试的 JSON 环境文件")
	fixture := flags.Bool("fixture", false, "显式启用合成测试；禁止作为设备 enrollment")
	input := flags.String("input", "", "合成 cloud snapshot JSON")
	environment := flags.String("environment", "", "环境 ID")
	name := flags.String("name", "", "变量名")
	value := flags.String("value", "", "本机 override 值")
	priority := flags.Int("priority", 0, "更大的优先级覆盖同名变量")
	interval := flags.Duration("interval", 2*time.Second, "daemon 本地收敛间隔")
	syncInterval := flags.Duration("sync-interval", 15*time.Second, "后台在线验证/拉取间隔，暂停仅刷新授权")
	once := flags.Bool("once", false, "daemon 仅执行一次测试收敛")
	localUser := flags.String("local-user", "", "服务明确绑定的本地 uid/SID")
	fragment := flags.String("platform-fragment", "", "明确指定的隔离 POSIX fragment")
	ipcDirectory := flags.String("ipc-dir", "", "后台 IPC 私有目录；CLI 连接时不打开状态文件")
	ipcServiceSID := flags.String("ipc-service-sid", "", "Windows 后台虚拟服务 SID；fixture 默认当前用户")
	windowsService := flags.String("windows-service", "", "Windows SCM 服务名")
	from := flags.String("from", "", "待选变量 JSON 文件；不会扫描宿主环境")
	selected := flags.String("select", "", "明确选择的逗号分隔变量名")
	shell := flags.String("shell", "sh", "sh/bash/zsh hook")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *caFile != "" && runtimeOptions.httpClient == nil {
		client, err := clientWithCA(*caFile)
		if err != nil {
			return err
		}
		runtimeOptions.httpClient = client
	}
	valueArgument := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "value" {
			valueArgument = true
		}
	})
	protectedIPC := false
	if *localDirectory != "" {
		if *fixture || *statePath != "" || *providerPath != "" || *input != "" {
			return errors.New("受保护目录不能混用明文 fixture/state/provider-file 输入")
		}
		if command == "login" || command == "pair" {
			return protectedAccountCommand(ctx, protectedOptions{command: command, directory: *localDirectory, server: *serverAddress, email: *email, approver: *approver, userID: *localUser, serviceSID: *ipcServiceSID, passwordStdin: *passwordStdin}, runtimeOptions, out, errOut)
		}
		if command == "daemon" {
			return protectedDaemon(ctx, daemonOptions{directory: *localDirectory, userID: *localUser, serviceSID: *ipcServiceSID, ipcDirectory: *ipcDirectory, fragment: *fragment, windowsService: *windowsService, interval: *interval, syncInterval: *syncInterval, once: *once}, runtimeOptions, out, errOut)
		}
		if *ipcDirectory == "" {
			absolute, err := filepath.Abs(*localDirectory)
			if err != nil {
				return err
			}
			*ipcDirectory = filepath.Join(absolute, "ipc")
		}
		protectedIPC = true
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
	if command == "login" || command == "pair" {
		return errors.New("login/pair须明确 --local-directory；正式共享写入CLI尚未接线，不能离线共享写入")
	}
	if *ipcDirectory != "" && command != "daemon" {
		if !*fixture && !protectedIPC {
			return errors.New("IPC CLI 需要明确 --local-directory 或隔离 --fixture")
		}
		endpoint, err := ipcEndpoint(*ipcDirectory, *localUser, *ipcServiceSID)
		if err != nil {
			return err
		}
		request := localipc.Request{Command: command}
		switch command {
		case "activate", "priority":
			request.EnvironmentID = *environment
			request.Priority = priority
		case "deactivate":
			request.EnvironmentID = *environment
		case "put", "delete", "import", "write-retry":
			if !protectedIPC {
				return errors.New("共享写入仅允许受保护后台，不接受fixture")
			}
			if valueArgument {
				return errors.New("共享变量值不能通过--value参数传入；请明确--value-stdin")
			}
			request, err = sharedCLIRequest(command, *environment, *name, *requestID, *valueStdin, *importStdin, *from, *selected, runtimeOptions.input)
			if err != nil {
				return err
			}
			if _, err = fmt.Fprintf(out, "共享请求ID：%s\n", request.RequestID); err != nil {
				return err
			}
		case "override-set":
			if protectedIPC {
				if valueArgument || !*valueStdin {
					return errors.New("受保护override值仅接受明确--value-stdin，不能使用--value argv")
				}
				inputValue, err := readSharedInput(runtimeOptions.input)
				if err != nil {
					return err
				}
				value = &inputValue
			}
			request.EnvironmentID = *environment
			request.Name = *name
			request.Value = value
		case "override-remove":
			request.EnvironmentID = *environment
			request.Name = *name
		case "status", "export", "pause", "resume", "logout":
		case "exec":
			request.Command = "export"
		default:
			return errors.New("此命令不在后台 IPC 白名单中")
		}
		response, err := localipc.Call(ctx, endpoint, request)
		if err != nil {
			return err
		}
		if response.Write != nil {
			if err = json.NewEncoder(out).Encode(response.Write); err != nil {
				return err
			}
		}
		if !response.OK {
			return fmt.Errorf("后台本地操作失败：%s", response.Code)
		}
		if command == "status" {
			return json.NewEncoder(out).Encode(response.Status)
		}
		if command == "export" {
			return renderExports(out, response.Values)
		}
		if command == "exec" {
			remaining := flags.Args()
			if len(remaining) == 0 {
				return errors.New("exec 后需要 -- <程序> [参数]")
			}
			child := exec.CommandContext(ctx, remaining[0], remaining[1:]...)
			child.Env = composeEnvironment(os.Environ(), response.Values, nil)
			child.Stdout = out
			child.Stderr = errOut
			child.Stdin = os.Stdin
			return child.Run()
		}
		return nil
	}
	if command == "put" || command == "delete" || command == "import" || command == "write-retry" {
		return errors.New("共享写入需要--local-directory与正在运行的受保护后台")
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
	case "priority":
		found := false
		for _, a := range engine.State().Active {
			if a.EnvironmentID == *environment {
				found = true
				break
			}
		}
		if !found {
			return errors.New("环境尚未激活")
		}
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
		return renderExports(out, effective)
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
			return errors.New("正式开机服务尚缺可信设备 enrollment、受保护同步编排及原生服务验收；保持关闭")
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
			if *once {
				return engine.Reconcile(runCtx, provider, time.Now())
			}
			directory := *ipcDirectory
			if directory == "" {
				absolute, err := filepath.Abs(*statePath)
				if err != nil {
					return err
				}
				directory = filepath.Join(filepath.Dir(absolute), "ipc")
			}
			endpoint, err := ipcEndpoint(directory, *localUser, *ipcServiceSID)
			if err != nil {
				return err
			}
			background, err := localipc.Listen(localipc.Config{Endpoint: endpoint, Engine: engine, Provider: provider})
			if err != nil {
				return err
			}
			serveCtx, stop := context.WithCancel(runCtx)
			done := make(chan error, 1)
			go func() { defer close(done); done <- background.Serve(serveCtx) }()
			defer func() {
				stop()
				_ = background.Close()
				for range done {
				}
			}()
			if err = background.Reconcile(runCtx, time.Now()); err != nil {
				return err
			}
			ticker := time.NewTicker(*interval)
			defer ticker.Stop()
			for {
				select {
				case <-runCtx.Done():
					return nil
				case err := <-done:
					return err
				case now := <-ticker.C:
					if err := background.Reconcile(runCtx, now); err != nil {
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

func ipcEndpoint(directory, userID, serviceSID string) (localipc.Endpoint, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return localipc.Endpoint{}, err
	}
	if runtime.GOOS != "windows" {
		// 解析 /tmp、/var 等系统链接，随后由原生层拒绝目录内链接及身份混淆。
		if canonical, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
			absolute = canonical
		} else if errors.Is(resolveErr, os.ErrNotExist) {
			parent, parentErr := filepath.EvalSymlinks(filepath.Dir(absolute))
			if parentErr != nil {
				return localipc.Endpoint{}, parentErr
			}
			absolute = filepath.Join(parent, filepath.Base(absolute))
		} else {
			return localipc.Endpoint{}, resolveErr
		}
	}
	if userID == "" {
		userID, err = localipc.CurrentUserID()
		if err != nil {
			return localipc.Endpoint{}, err
		}
	}
	if serviceSID == "" && strings.HasPrefix(userID, "S-") {
		serviceSID = userID
	}
	return localipc.Endpoint{Directory: absolute, UserID: userID, ServiceSID: serviceSID}, nil
}
func renderExports(out io.Writer, values map[string]string) error {
	for _, key := range sortedKeys(values) {
		quoted, err := platform.ShellQuote(values[key])
		if err != nil {
			return err
		}
		if _, err = fmt.Fprintf(out, "export %s=%s\n", key, quoted); err != nil {
			return err
		}
	}
	return nil
}
