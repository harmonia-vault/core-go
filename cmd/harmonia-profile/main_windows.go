//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/harmonia-vault/core-go/windowsservice"
	"os"
	"os/signal"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "需要 broker 或 token 子命令")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("harmonia-profile", flag.ContinueOnError)
	config := flags.String("config", "", "管理员保护的固定配置文件")
	if flags.Parse(os.Args[2:]) != nil || *config == "" || flags.NArg() != 0 {
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var e error
	switch os.Args[1] {
	case "broker":
		e = windowsservice.RunSCMBroker(ctx, *config)
	case "self-register":
		e = windowsservice.RegisterOwnTask(ctx, *config)
	case "token":
		e = windowsservice.RunTokenHelper(ctx, *config)
	default:
		e = windowsservice.ErrConfiguration
	}
	if e != nil {
		var registration *windowsservice.RegistrationFailure
		if errors.As(e, &registration) {
			fmt.Fprintf(os.Stderr, "PROFILE_REGISTER_FAIL stage=%s codeRecorded=%t hresult=0x%08x scode=0x%08x wcode=0x%04x\n", registration.Stage, registration.CodeRecorded, registration.HRESULT, registration.ExceptionSCODE, registration.ExceptionWCode)
		}
		fmt.Fprintln(os.Stderr, "Windows profile 组件拒绝启动或已停止")
		os.Exit(1)
	}
}
