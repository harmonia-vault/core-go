//go:build ignore

// 生成服务配置供审查；不安装、启动、提权或修改环境。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/harmonia-vault/core-go/platform"
)

func main() {
	out := flag.String("output", "", "必须显式提供新的输出目录")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "需要 --output <新目录>")
		os.Exit(2)
	}
	if err := os.Mkdir(*out, 0700); err != nil {
		fmt.Fprintln(os.Stderr, "拒绝使用已存在或不可创建的目录")
		os.Exit(1)
	}
	configs := []struct {
		os     string
		cfg    platform.ServiceConfig
		render func(platform.ServiceConfig) (platform.ServiceTemplate, error)
	}{
		{"macos", platform.ServiceConfig{UserName: "harmonia-test", UserID: "10001", BinaryPath: "/usr/local/bin/harmonia", StateDirectory: "/Library/Application Support/Harmonia/10001"}, platform.LaunchDaemon},
		{"linux", platform.ServiceConfig{UserName: "harmonia-test", UserID: "10001", BinaryPath: "/usr/local/bin/harmonia", StateDirectory: "/var/lib/harmonia/10001"}, platform.Systemd},
		{"windows", platform.ServiceConfig{UserID: "S-1-5-21-111-222-333-1001", BinaryPath: `C:\Program Files\Harmonia\harmonia.exe`, StateDirectory: `C:\ProgramData\Harmonia\test-user`}, platform.WindowsService},
	}
	for _, cfg := range configs {
		result, err := cfg.render(cfg.cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		path := filepath.Join(*out, cfg.os+"-"+result.Name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if _, err := f.Write(result.Content); err != nil {
			f.Close()
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := f.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(path)
	}
}
