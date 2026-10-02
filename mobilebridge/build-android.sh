#!/bin/sh
set -eu
# SDK、NDK、Java 路径由调用者显式提供；不探测宿主账号、环境凭据或旧签名钥。
if [ "$#" -ne 3 ]; then
 echo '用法：mise exec go@1.26.4 -- sh mobilebridge/build-android.sh <AndroidSDK> <NDK28.2.13676358> <Java17>' >&2
 exit 2
fi
bridge_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bridge_sdk=$1
bridge_ndk=$2
bridge_java=$3
[ "$(go version | awk '{print $3}')" = go1.26.4 ] || { echo '需要 Go1.26.4' >&2; exit 1; }
rg -q '^Pkg.Revision = 28.2.13676358$' "$bridge_ndk/source.properties" || { echo '需要固定 NDK28.2.13676358' >&2; exit 1; }
[ -f "$bridge_root/pairing/native/android-arm64/libcrypto.a" ] || { echo '请先构建固定 BoringSSL Android arm64 库' >&2; exit 1; }
bridge_cache="$bridge_root/.build/mobilebridge"
bridge_output="$bridge_root/../mobile/build/native"
mkdir -p "$bridge_cache/bin" "$bridge_output"
export GOPATH="$bridge_cache/gopath"
export GOBIN="$bridge_cache/bin"
export JAVA_HOME="$bridge_java"
export ANDROID_HOME="$bridge_sdk"
export ANDROID_NDK_HOME="$bridge_ndk"
export PATH="$GOBIN:$JAVA_HOME/bin:$PATH"
mobile_version=v0.0.0-20260908204917-8b95e45f8d3e
go install "golang.org/x/mobile/cmd/gomobile@$mobile_version"
go install "golang.org/x/mobile/cmd/gobind@$mobile_version"
gomobile init
cd "$bridge_root/mobilebridge/binding"
go mod tidy
gomobile bind -target android/arm64 -androidapi 30 -javapkg org.harmoniavault.go -tags harmonia_boringssl -trimpath -o "$bridge_output/harmonia-go.aar" github.com/harmonia-vault/core-go/mobilebridge
