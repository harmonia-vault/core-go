//go:build !windows

package main

import (
	"context"
	"errors"
	"github.com/harmonia-vault/core-go/localipc"
	"io"
)

func windowsClientEndpoint(string) (localipc.Endpoint, error) {
	return localipc.Endpoint{}, errors.New("当前平台不接受Windows固定服务配置")
}
func protectedWindowsAccount(context.Context, string, protectedOptions, string, commandRuntime, io.Writer, io.Writer) error {
	return errors.New("当前平台不接受Windows账号IPC")
}
func protectedWindowsDaemon(context.Context, string, daemonOptions, commandRuntime, io.Writer, io.Writer) error {
	return errors.New("当前平台不接受Windows服务配置")
}
