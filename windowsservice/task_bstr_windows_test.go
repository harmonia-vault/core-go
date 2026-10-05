//go:build windows

package windowsservice

import (
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/internal/wincom"
	"golang.org/x/sys/windows"
)

var nativeTaskFixture = flag.String("harmonia-synthetic-task-config", "", "显式提供受保护的合成账号配置；此测试不创建任务")

// 原生 BSTR 传输边界回归：系统 parser 为 oracle，不以字符串相等代替真实 XML 校验。
// 只有显式合成配置且 SYSTEM 执行时运行；前后必须无任务，永远 TASK_VALIDATE_ONLY=1。
func TestNativeTaskXMLBSTRBoundary(t *testing.T) {
	if *nativeTaskFixture == "" {
		t.Skip("需要显式合成配置和原生 Windows；默认不读取用户配置")
	}
	if !tokenUser(windows.GetCurrentProcessToken(), "S-1-5-18") {
		t.Fatal("合成原生验证需要 SYSTEM")
	}
	locked, e := LoadConfig(*nativeTaskFixture)
	if e != nil {
		t.Fatal("合成配置校验失败")
	}
	defer locked.Close()
	c := locked.Config
	generated, e := c.TaskXML()
	if e != nil {
		t.Fatal("生成失败")
	}
	scheduler, e := wincom.Open()
	if e != nil {
		t.Fatal("原生 COM 连接失败")
	}
	defer scheduler.Close()
	folder, e := scheduler.Object(scheduler.Root, "GetFolder", c.TaskFolder())
	if e != nil {
		t.Fatal("合成任务目录不存在")
	}
	zeroCount := func() {
		tasks, e := scheduler.Object(folder, "GetTasks", 1)
		if e != nil {
			t.Fatal("任务查询失败")
		}
		n, e := scheduler.Number(tasks, "Count")
		if e != nil || n != 0 {
			t.Fatal("合成目录必须包含零任务")
		}
	}
	zeroCount()
	defer zeroCount()
	// 与真实注册使用完全相同的 BSTR/principal/action 参数，仅 flags=1 禁止创建。
	if _, e = scheduler.Call(folder, "RegisterTask", "Token", generated, 1, c.TargetSID, nil, 2, nil); e != nil {
		var native *wincom.Failure
		if errors.As(e, &native) {
			t.Fatalf("生成的 XML 被原生 parser 拒绝: hresult=%08x scode=%08x", native.HRESULT, native.ExceptionSCODE)
		}
		t.Fatal("生成的 XML 被原生 parser 拒绝")
	}
	// 重建真实旧错误声明，验证同一系统会拒绝它，避免回归被 Go 的 UTF8 byte parser 掩盖。
	legacy := strings.Replace(generated, `<?xml version="1.0"?>`, `<?xml version="1.0" encoding="UTF-8"?>`, 1)
	if legacy == generated {
		t.Fatal("无法构造旧传输边界")
	}
	_, e = scheduler.Call(folder, "RegisterTask", "Token", legacy, 1, c.TargetSID, nil, 2, nil)
	var native *wincom.Failure
	if !errors.As(e, &native) || !native.CodeRecorded || native.ExceptionSCODE != 0x8004131a {
		t.Fatal("旧声明没有触发已验证的 MALFORMEDXML 边界")
	}
	zeroCount()
}
