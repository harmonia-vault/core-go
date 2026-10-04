//go:build !windows

package main

import (
	"context"
	"errors"
	"github.com/harmonia-vault/core-go/localipc"
	"io"
)

func restoreAccountServiceLocal(context.Context, string) error {
	return errors.New("当前平台不接受Windows账号服务")
}

func accountClientEndpoint(string) (localipc.Endpoint, error) {
	return localipc.Endpoint{}, errors.New("当前平台不接受Windows账号服务配置")
}
func protectedAccountServiceAccount(context.Context, string, protectedOptions, string, commandRuntime, io.Writer, io.Writer) error {
	return errors.New("当前平台不接受Windows账号服务")
}
func protectedAccountServiceDaemon(context.Context, string, commandRuntime) error {
	return errors.New("当前平台不接受Windows账号服务")
}
