//go:build windows

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type rejectedWindowsPasswordReader struct{ read bool }

func (r *rejectedWindowsPasswordReader) Read([]byte) (int, error) { r.read = true; return 0, io.EOF }

func TestWindowsCurrentUserCannotOpenVaultBeforeOwnerIPC(t *testing.T) {
	for _, command := range []string{"login", "pair"} {
		t.Run(command, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "must-not-open")
			reader := &rejectedWindowsPasswordReader{}
			var out, errOut bytes.Buffer
			err := protectedAccountCommand(context.Background(), protectedOptions{command: command, directory: directory, passwordStdin: true}, commandRuntime{input: reader}, &out, &errOut)
			if err == nil {
				t.Fatal("尚未验收的 Windows 当前用户账号入口开放")
			}
			if reader.read {
				t.Fatal("系统身份检查前读取了密码输入")
			}
			if out.Len() != 0 || errOut.Len() != 0 {
				t.Fatal("关闭入口输出了账号资料")
			}
			if _, err = os.Stat(directory); !os.IsNotExist(err) {
				t.Fatal("关闭入口触及用户 Vault 路径")
			}
		})
	}
}
