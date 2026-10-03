//go:build linux

// 实验性单 UID 安装器。只能在已审的独立 Linux VM 验收后部署。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/harmonia-vault/core-go/linuxinstall"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Linux 安装器候选拒绝：", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return linuxinstall.ErrPlan
	}
	command := args[0]
	if command != "plan" && command != "check-systemd" && command != "install" && command != "start" && command != "uninstall" {
		return linuxinstall.ErrUnsupported
	}
	seen := map[string]bool{}
	for n := 1; n < len(args); n += 2 {
		if n+1 >= len(args) || len(args[n]) < 3 || args[n][:2] != "--" || seen[args[n]] {
			return linuxinstall.ErrPlan
		}
		seen[args[n]] = true
	}
	f := flag.NewFlagSet("harmonia-linux-installer", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	name := f.String("user", "", "目标非 root 本地用户名")
	uid := f.String("uid", "", "显式目标 UID")
	binary := new(string)
	sha := new(string)
	ca := new(string)
	caSHA := new(string)
	if command != "start" && command != "uninstall" {
		binary = f.String("binary-source", "", "已审核原生 CLI 绝对路径")
		sha = f.String("binary-sha256", "", "已审核 SHA256")
		ca = f.String("ca-source", "", "可选显式 CA")
		caSHA = f.String("ca-sha256", "", "可选 CA SHA256")
	}
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return linuxinstall.ErrPlan
	}
	u, err := user.Lookup(*name)
	if err != nil || u.Uid != *uid {
		return linuxinstall.ErrPlan
	}
	ctx, cancel := context.WithTimeout(context.Background(), linuxinstall.CommandTimeout())
	defer cancel()
	if command == "start" || command == "uninstall" {
		var result linuxinstall.Result
		var err error
		if command == "start" {
			result, err = linuxinstall.Start(ctx, *uid)
		} else {
			result, err = linuxinstall.Uninstall(ctx, *uid)
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	p, err := linuxinstall.NewPlan(linuxinstall.Input{UserName: *name, UID: *uid, GID: u.Gid, BinarySource: *binary, BinarySHA256: *sha, CASource: *ca, CASHA256: *caSHA})
	if err != nil {
		return err
	}
	if command == "install" {
		result, err := linuxinstall.Install(ctx, p.Input)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if command == "plan" {
		unit, err := p.Unit()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(struct {
			Plan         linuxinstall.Plan `json:"plan"`
			Unit         string            `json:"unit"`
			InstallReady bool              `json:"installReady"`
		}{p, string(unit.Content), false})
	}
	ctx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
	defer checkCancel()
	s, err := linuxinstall.ShowUnit(ctx, p)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(s)
}
