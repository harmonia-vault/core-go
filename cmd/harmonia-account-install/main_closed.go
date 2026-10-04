//go:build !windows || !harmonia_windows_account_candidate

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "Windows普通账号安装器尚未通过完整原生验收；默认关闭")
	os.Exit(1)
}
