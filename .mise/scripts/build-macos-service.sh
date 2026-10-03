#!/bin/sh
set -eu
[ "$(uname -s)" = Darwin ] || { echo '此构建入口需要 macOS；没有安装或启动服务' >&2; exit 1; }
mkdir -p .build/macos-service
go build -trimpath -o .build/macos-service/harmonia-macos-service ./cmd/harmonia-macos-service
