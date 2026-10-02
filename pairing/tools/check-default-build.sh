#!/usr/bin/env bash
set -euo pipefail
for target in darwin/arm64 linux/amd64 windows/amd64; do
  go_os="${target%/*}"
  go_arch="${target#*/}"
  CGO_ENABLED=0 GOOS="$go_os" GOARCH="$go_arch" go build .
  printf '%s\n' "默认关闭配对构建通过：$target CGO_ENABLED=0"
done
