package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type syntheticImportEnvironment struct {
	names       []string
	values      map[string]string
	insensitive bool
	namesCalls  int
	lookedUp    []string
}

func (s *syntheticImportEnvironment) Names() []string {
	s.namesCalls++
	return append([]string(nil), s.names...)
}
func (s *syntheticImportEnvironment) Lookup(name string) (string, bool) {
	s.lookedUp = append(s.lookedUp, name)
	value, ok := s.values[name]
	return value, ok
}
func (s *syntheticImportEnvironment) CaseInsensitive() bool { return s.insensitive }
func syntheticProcessImportSource() *syntheticImportEnvironment {
	return &syntheticImportEnvironment{
		names:  []string{"TOKEN", "EMPTY", "MULTILINE", "NOT_CHOSEN", "__harmonia_private", "INVALID-NAME", "=C:"},
		values: map[string]string{"TOKEN": "synthetic-chosen", "EMPTY": "", "MULTILINE": "synthetic'\n$literal\n", "NOT_CHOSEN": "SYNTHETIC_SECRET_UNSELECTED", "__harmonia_private": "SYNTHETIC_RESERVED_VALUE"},
	}
}

type forbiddenImportNetwork struct{ calls int }

func (n *forbiddenImportNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	n.calls++
	return nil, io.ErrClosedPipe
}
func TestProcessImportPreviewOnlyListsNamesAndNeverUsesLookupOrNetwork(t *testing.T) {
	for _, selection := range []string{"", "TOKEN"} {
		source := syntheticProcessImportSource()
		network := &forbiddenImportNetwork{}
		var out, errOut bytes.Buffer
		directory := filepath.Join(t.TempDir(), "not-created")
		args := []string{"import-preview", "--current-env", "--local-directory", directory, "--server", "https://synthetic.invalid", "--ca-file", "nonexistent-synthetic-ca"}
		if selection != "" {
			args = append(args, "--select", selection)
		}
		err := runWithRuntime(context.Background(), args, &out, &errOut, commandRuntime{environment: source, httpClient: &http.Client{Transport: network}})
		if err != nil {
			t.Fatal("仅名称预览失败")
		}
		var names []string
		if json.Unmarshal(out.Bytes(), &names) != nil {
			t.Fatal("预览不是名称数组")
		}
		wanted := []string{"EMPTY", "MULTILINE", "NOT_CHOSEN", "TOKEN"}
		if selection != "" {
			wanted = []string{"TOKEN"}
		}
		if !reflect.DeepEqual(names, wanted) || source.namesCalls != 1 || len(source.lookedUp) != 0 || network.calls != 0 {
			t.Fatal("预览取值、联网或列名错误")
		}
		if strings.Contains(out.String()+errOut.String(), "synthetic-chosen") || strings.Contains(out.String()+errOut.String(), "SYNTHETIC_SECRET") {
			t.Fatal("名称预览泄露值")
		}
		if _, err = os.Stat(directory); !os.IsNotExist(err) {
			t.Fatal("名称预览打开了账号状态目录")
		}
	}
	empty := &syntheticImportEnvironment{}
	var out bytes.Buffer
	if previewProcessImport(empty, "", &out) != nil || out.String() != "[]\n" {
		t.Fatal("空环境预览不确定")
	}
}
func TestProcessImportReadsOnlySelectedValuesAndPreservesBytes(t *testing.T) {
	source := syntheticProcessImportSource()
	request, err := processImportRequest(source, "env", "scan-id", "TOKEN,EMPTY,MULTILINE")
	if err != nil {
		t.Fatal("显式选择导入失败")
	}
	if request.Command != "import" || request.RequestID != "scan-id" || request.EnvironmentID != "env" || !reflect.DeepEqual(source.lookedUp, []string{"EMPTY", "MULTILINE", "TOKEN"}) {
		t.Fatal("请求或selected-only Lookup错误")
	}
	if request.Selected["EMPTY"] != "" || request.Selected["MULTILINE"] != "synthetic'\n$literal\n" || request.Selected["TOKEN"] != "synthetic-chosen" || len(request.Selected) != 3 {
		t.Fatal("选中值字节改变")
	}
	data, _ := json.Marshal(request)
	if bytes.Contains(data, []byte("NOT_CHOSEN")) || bytes.Contains(data, []byte("SYNTHETIC_SECRET")) {
		t.Fatal("未选项进入IPC")
	}
	source.values["NOT_CHOSEN"] = "SYNTHETIC_SECRET_DIRECT_EXTERNAL_CHANGE"
	request, err = processImportRequest(source, "env", "scan-id", "TOKEN")
	if err != nil || len(request.Selected) != 1 || request.Selected["TOKEN"] != "synthetic-chosen" {
		t.Fatal("外改未选中变量被采集")
	}
}
func TestProcessImportSelectionValidationPrecedesAnyLookup(t *testing.T) {
	for _, selection := range []string{"", "TOKEN,TOKEN", "TOKEN,UNKNOWN", "TOKEN,__HaRmOnIa_private", "TOKEN,INVALID-NAME", "TOKEN, TOKEN", ",TOKEN", "TOKEN,"} {
		source := syntheticProcessImportSource()
		_, err := processImportRequest(source, "env", "scan-id", selection)
		if err == nil || len(source.lookedUp) != 0 {
			t.Fatal("无效选择取值或未拒绝")
		}
		if strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
			t.Fatal("错误泄露值")
		}
	}
	source := &syntheticImportEnvironment{}
	var names []string
	for i := range 17 {
		names = append(names, "VAR"+string(rune('A'+i)))
	}
	source.names = names
	if _, err := processImportRequest(source, "env", "scan-id", strings.Join(names, ",")); err == nil || len(source.lookedUp) != 0 {
		t.Fatal("超过选择上限仍取值")
	}
	source.names = make([]string, 4097)
	if _, err := processImportRequest(source, "env", "scan-id", "TOKEN"); err == nil || len(source.lookedUp) != 0 {
		t.Fatal("列名上限未生效")
	}
}
func TestProcessImportRejectsMissingAndInvalidSelectedValues(t *testing.T) {
	for _, value := range []string{string([]byte{255}), "SYNTHETIC_SECRET\x00bad", strings.Repeat("x", 65537)} {
		source := &syntheticImportEnvironment{names: []string{"TOKEN"}, values: map[string]string{"TOKEN": value}}
		if _, err := processImportRequest(source, "env", "scan-id", "TOKEN"); err == nil || strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
			t.Fatal("无效值被接受或泄露")
		}
	}
	source := &syntheticImportEnvironment{names: []string{"TOKEN"}}
	if _, err := processImportRequest(source, "env", "scan-id", "TOKEN"); err == nil {
		t.Fatal("列名之后消失的值被导入")
	}
	source = &syntheticImportEnvironment{names: []string{"A", "B"}, values: map[string]string{"A": strings.Repeat("a", 32769), "B": strings.Repeat("b", 32768)}}
	if _, err := processImportRequest(source, "env", "scan-id", "A,B"); err == nil {
		t.Fatal("选中总字节上限未生效")
	}
}
func TestProcessImportTargetPlatformNameSemantics(t *testing.T) {
	windows := &syntheticImportEnvironment{names: []string{"Path", "TOKEN", "__hArMoNiA_internal", "=C:"}, values: map[string]string{"Path": "synthetic-path"}, insensitive: true}
	request, err := processImportRequest(windows, "env", "scan-id", "pAtH")
	if err != nil || len(request.Selected) != 1 || request.Selected["Path"] != "synthetic-path" || !reflect.DeepEqual(windows.lookedUp, []string{"Path"}) {
		t.Fatal("Windows名称选择语义错误")
	}
	windows.lookedUp = nil
	if _, err = processImportRequest(windows, "env", "scan-id", "PATH,path"); err == nil || len(windows.lookedUp) != 0 {
		t.Fatal("Windows重复选择未拒绝")
	}
	windows.names = append(windows.names, "PATH")
	if _, err = processImportRequest(windows, "env", "scan-id", "TOKEN"); err == nil || len(windows.lookedUp) != 0 {
		t.Fatal("Windows源大小写歧义未拒绝")
	}
	posix := &syntheticImportEnvironment{names: []string{"Path", "PATH"}, values: map[string]string{"Path": "synthetic-mixed", "PATH": "synthetic-upper"}}
	request, err = processImportRequest(posix, "env", "scan-id", "Path,PATH")
	if err != nil || len(request.Selected) != 2 || request.Selected["Path"] == request.Selected["PATH"] {
		t.Fatal("POSIX不同大小写被折叠")
	}
}
func TestProcessImportFlagsDoNotMixSourcesOrEnableOtherCommands(t *testing.T) {
	cases := [][]string{
		{"status", "--current-env"},
		{"daemon", "--current-env", "--local-directory", "synthetic"},
		{"write-retry", "--current-env", "--request-id", "scan-id"},
		{"import", "--current-env", "--import-stdin", "--select", "TOKEN"},
		{"import", "--current-env", "--value-stdin", "--select", "TOKEN"},
		{"import-preview", "--current-env", "--from", "synthetic.json"},
		{"import-preview", "--current-env", "--value", "SYNTHETIC_SECRET_ARGV"},
		{"import", "--current-env", "--fixture", "--state", "synthetic-state", "--select", "TOKEN"},
	}
	for _, args := range cases {
		source := syntheticProcessImportSource()
		var out, errOut bytes.Buffer
		err := runWithRuntime(context.Background(), args, &out, &errOut, commandRuntime{environment: source, input: strings.NewReader(`{"TOKEN":"synthetic-stdin"}`)})
		if err == nil || source.namesCalls != 0 || len(source.lookedUp) != 0 {
			t.Fatal("无效入口触发扫描")
		}
		if strings.Contains(err.Error()+out.String()+errOut.String(), "SYNTHETIC_SECRET") {
			t.Fatal("参数错误回显值")
		}
	}
}
func TestProcessImportExistingStdinAndFilePreviewRemainExplicit(t *testing.T) {
	request, err := sharedCLIRequest("import", "env", "", "stdin-id", false, true, "", "CHOSEN", strings.NewReader(`{"CHOSEN":"synthetic-selected","OTHER":"synthetic-other"}`))
	if err != nil || len(request.Selected) != 1 || request.Selected["CHOSEN"] != "synthetic-selected" {
		t.Fatal("原stdin导入兼容性改变")
	}
	source := syntheticProcessImportSource()
	var out, errOut bytes.Buffer
	path := filepath.Join(t.TempDir(), "candidates.json")
	if os.WriteFile(path, []byte(`{"CHOSEN":"synthetic-selected","OTHER":"synthetic-other"}`), 0600) != nil {
		t.Fatal("合成候选文件写入失败")
	}
	err = runWithRuntime(context.Background(), []string{"import-preview", "--from", path, "--select", "CHOSEN"}, &out, &errOut, commandRuntime{environment: source})
	if err != nil || source.namesCalls != 0 || len(source.lookedUp) != 0 || strings.Contains(out.String(), "OTHER") {
		t.Fatal("原文件预览扫描进程环境或选择错误")
	}
}

// 子进程只有下方显式合成 Env；父测试进程不会调用默认扫描源。
func TestProcessImportSyntheticProcessHelper(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "harmonia-synthetic-import-helper" {
		return
	}
	err := runWithRuntime(context.Background(), []string{"import-preview", "--current-env"}, os.Stdout, io.Discard, commandRuntime{})
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
func TestProcessImportDefaultSourceUsesOnlySyntheticChildEnvironment(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestProcessImportSyntheticProcessHelper$", "--", "harmonia-synthetic-import-helper")
	// Windows 的 os/exec 会补缺省 SystemRoot；原生 ARM64 子进程还出现了
	// PROCESSOR_ARCHITECTURE。两项均显式提供合成值，各平台使用同一 Env。
	command.Env = []string{"TOKEN=SYNTHETIC_SECRET_VALUE", "EMPTY=", "NOT_CHOSEN=SYNTHETIC_SECRET_OTHER", "__HaRmOnIa_internal=SYNTHETIC_RESERVED", "SYSTEMROOT=SYNTHETIC_SYSTEM_ROOT", "PROCESSOR_ARCHITECTURE=SYNTHETIC_PROCESSOR_ARCHITECTURE"}
	var out, errOut bytes.Buffer
	command.Stdout = &out
	command.Stderr = &errOut
	if command.Run() != nil {
		t.Fatal("合成Env子进程扫描失败")
	}
	// 在名称诊断前检查所有合成值标记，避免错误实现将值伪装为名称时回显。
	if strings.Contains(out.String()+errOut.String(), "SYNTHETIC_") {
		t.Fatal("子进程名称扫描输出值")
	}
	var names []string
	if err := json.Unmarshal(out.Bytes(), &names); err != nil {
		// 不打印原 stdout/stderr；解析失败时其中可能含有变量值。
		t.Fatal("合成Env子进程名称响应不是JSON数组")
	}
	if !reflect.DeepEqual(names, []string{"EMPTY", "NOT_CHOSEN", "PROCESSOR_ARCHITECTURE", "SYSTEMROOT", "TOKEN"}) {
		// 仅打印已解析的名称，保留严格期望以定位平台差异，不输出值。
		t.Fatalf("真实默认源未只输出合成名称：names=%q", names)
	}
}
