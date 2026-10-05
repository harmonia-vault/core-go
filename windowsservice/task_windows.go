//go:build windows

package windowsservice

import (
	"context"
	"errors"
	"github.com/harmonia-vault/core-go/internal/wincom"
	"golang.org/x/sys/windows"
)

func runVerifiedTask(ctx context.Context, c Config) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	scheduler, e := wincom.Open()
	if e != nil {
		return ErrConfiguration
	}
	defer scheduler.Close()
	folder, e := scheduler.Object(scheduler.Root, "GetFolder", c.TaskFolder())
	if e != nil {
		return ErrConfiguration
	}
	task, e := scheduler.Object(folder, "GetTask", "Token")
	if e != nil {
		return ErrConfiguration
	}
	doc, e := scheduler.PropertyString(task, "Xml")
	if e != nil || c.ValidateTask([]byte(doc)) != nil {
		return ErrConfiguration
	}
	for _, entry := range []struct {
		object  string
		readers map[string]bool
	}{{"task", map[string]bool{c.TargetSID: true}}, {"folder", map[string]bool{c.TargetSID: true}}, {"root", nil}, {"top", nil}} {
		object := task
		switch entry.object {
		case "folder":
			object = folder
		case "root":
			object, e = scheduler.Object(scheduler.Root, "GetFolder", `\Harmonia`)
		case "top":
			object, e = scheduler.Object(scheduler.Root, "GetFolder", `\`)
		}
		if e != nil {
			return ErrConfiguration
		}
		descriptor, err := scheduler.String(object, "GetSecurityDescriptor", 7)
		if err != nil {
			return ErrConfiguration
		}
		sd, err := windows.SecurityDescriptorFromString(descriptor)
		if err != nil {
			return ErrConfiguration
		}
		if entry.object == "top" {
			if schedulerTopACL(sd) != nil {
				return ErrConfiguration
			}
		} else if immutableACL(sd, entry.readers) != nil {
			return ErrConfiguration
		}
	}
	// 使用已验证并持有的同一 task COM 对象，不能再 GetTask 替换 query→run 目标。
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, e = scheduler.Call(task, "Run", nil); e != nil {
		return ErrUnavailable
	}
	return nil
}

// RegistrationFailure 只公开固定阶段及纯数值原生诊断；不保存 COM 描述或任意底层文本。
type RegistrationFailure struct {
	Stage          string
	CodeRecorded   bool
	HRESULT        uint32
	ExceptionSCODE uint32
	ExceptionWCode uint16
	class          error
}

func (e *RegistrationFailure) Error() string { return e.class.Error() }
func (e *RegistrationFailure) Unwrap() error { return e.class }
func registrationFailure(stage string, class, cause error) error {
	out := &RegistrationFailure{Stage: stage, class: class}
	var native *wincom.Failure
	if errors.As(cause, &native) {
		out.CodeRecorded = native.CodeRecorded
		out.HRESULT = native.HRESULT
		out.ExceptionSCODE = native.ExceptionSCODE
		out.ExceptionWCode = native.ExceptionWCode
	}
	return out
}

// RegisterOwnTask 仅当前 exact target 用户自注册 S4U；installer 后续必须核对并锁 task/folder DACL。
// 不要求密码、不授予 Batch、不更新已有 task，也不调用 PowerShell。
func RegisterOwnTask(ctx context.Context, configPath string) error {
	locked, e := LoadConfig(configPath)
	if e != nil {
		return registrationFailure("config-load", ErrConfiguration, e)
	}
	defer locked.Close()
	c := locked.Config
	if ctx.Err() != nil {
		return registrationFailure("context", ctx.Err(), nil)
	}
	if !tokenUser(windows.GetCurrentProcessToken(), c.TargetSID) {
		return registrationFailure("current-user", ErrIdentity, nil)
	}
	doc, e := c.TaskXML()
	if e != nil {
		return registrationFailure("task-xml", ErrConfiguration, nil)
	}
	scheduler, e := wincom.Open()
	if e != nil {
		return registrationFailure("com-open", ErrUnavailable, e)
	}
	defer scheduler.Close()
	folder, e := scheduler.Object(scheduler.Root, "GetFolder", c.TaskFolder())
	if e != nil {
		return registrationFailure("folder-open", ErrConfiguration, e)
	}
	if ctx.Err() != nil {
		return registrationFailure("context", ctx.Err(), nil)
	}
	if _, e = scheduler.Call(folder, "RegisterTask", "Token", doc, 2, c.TargetSID, nil, 2, nil); e != nil {
		return registrationFailure("register-task", ErrUnavailable, e)
	}
	return nil
}
