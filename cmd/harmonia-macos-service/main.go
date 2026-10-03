package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/macosservice"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法：harmonia-macos-service <install|start|stop|uninstall> --user 用户名 --uid UID --gid GID")
	}
	op := args[0]
	if op != "install" && op != "start" && op != "stop" && op != "uninstall" {
		return fmt.Errorf("未知操作；没有执行")
	}
	f := flag.NewFlagSet(op, flag.ContinueOnError)
	name := f.String("user", "", "明确的目标本地用户名")
	uid := f.String("uid", "", "必须与目标账号一致的非 root UID")
	gid := f.String("gid", "", "必须与目标账号一致的主 GID")
	binary := f.String("binary", "", "root-owned 程序的规范绝对路径，仅 install")
	hash := f.String("sha256", "", "明确程序 SHA256，仅 install")
	ca := f.String("ca-file", "", "可选 root-owned 公 CA，不改变系统信任，仅 install")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return fmt.Errorf("拒绝多余位置参数")
	}
	parse := func(s string) (uint32, error) {
		n, e := strconv.ParseUint(s, 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != s {
			return 0, fmt.Errorf("UID/GID 必须为规范十进制")
		}
		return uint32(n), nil
	}
	u, e := parse(*uid)
	if e != nil {
		return e
	}
	g, e := parse(*gid)
	if e != nil {
		return e
	}
	if op != "install" && (*binary != "" || *hash != "" || *ca != "") {
		return fmt.Errorf("非 install 操作不接受程序或 CA 参数")
	}
	m, e := macosservice.New(macosservice.Target{UserName: *name, UID: u, GID: g})
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	switch op {
	case "install":
		if e = m.Install(ctx, macosservice.InstallOptions{Binary: *binary, BinarySHA256: *hash, CAFile: *ca}); e == nil {
			fmt.Println("安装已完成并保持禁启动，尚未授权。请以目标用户在以下目录使用正式 CLI login/pair，然后以普通 sudo 执行本入口 start：")
			fmt.Println("程序：", m.BinaryPath())
			fmt.Println("状态：", m.StateDirectory())
		}
	case "start":
		e = m.Start(ctx)
	case "stop":
		e = m.Stop(ctx)
	case "uninstall":
		e = m.Uninstall(ctx)
	}
	if e == nil && op != "install" {
		fmt.Println("已完成：", op)
	}
	return e
}
