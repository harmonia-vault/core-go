#!/usr/bin/env bash
# mise description="交叉构建三平台 CLI（不生成安装包）"
set -euo pipefail
mkdir -p .build
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 mise exec -- go build -o .build/harmonia-darwin-arm64 ./cmd/harmonia
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 mise exec -- go build -o .build/harmonia-linux-amd64 ./cmd/harmonia
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 mise exec -- go build -o .build/harmonia-windows-amd64.exe ./cmd/harmonia
