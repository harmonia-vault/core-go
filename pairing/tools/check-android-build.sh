#!/usr/bin/env bash
set -euo pipefail
# 只编译并链接 Android 测试文件，不将交叉编译误报为设备运行通过。
package_dir="$(cd "$(dirname "$0")/.." && pwd)"
ndk_dir="${1:-}"
if [[ $# -ne 1 || ! -f "$ndk_dir/source.properties" ]]; then
  printf '%s\n' '必须显式提供已安装的 NDK 28.2.13676358 目录。' >&2
  exit 2
fi
if ! rg --quiet '^Pkg.Revision = 28\.2\.13676358$' "$ndk_dir/source.properties"; then
  printf '%s\n' 'NDK 版本不符，停止编译。' >&2
  exit 2
fi
case "$(uname -s)" in
  Darwin) host_tag=darwin-x86_64 ;;
  Linux) host_tag=linux-x86_64 ;;
  *) printf '%s\n' '本入口只支持已验证布局的 macOS/Linux NDK 主机。' >&2; exit 2 ;;
esac
toolchain="$ndk_dir/toolchains/llvm/prebuilt/$host_tag"
if [[ ! -x "$toolchain/bin/clang" || ! -f "$package_dir/native/android-arm64/libcrypto.a" ]]; then
  printf '%s\n' '缺少 NDK 编译器或 Android 静态库；先运行 native-build-android。' >&2
  exit 2
fi
symbols="$("$toolchain/bin/llvm-nm" --defined-only "$package_dir/native/android-arm64/libcrypto.a")"
for symbol in SPAKE2_CTX_new SPAKE2_CTX_free SPAKE2_generate_msg SPAKE2_process_msg; do
  if ! rg --quiet "[[:space:]]HARMONIA_BSSL_${symbol}$" <<< "$symbols"; then
    printf '%s\n' '缺少固定前缀的 SPAKE2 公共符号，停止编译。' >&2
    exit 2
  fi
done
if rg --quiet '[[:space:]]SPAKE2_(CTX_new|CTX_free|generate_msg|process_msg)$' <<< "$symbols"; then
  printf '%s\n' '检测到未隔离的 SPAKE2 公共符号，停止编译。' >&2
  exit 2
fi
export GOOS=android GOARCH=arm64 CGO_ENABLED=1
export CC="\"$toolchain/bin/clang\" --target=aarch64-linux-android21"
export CXX="\"$toolchain/bin/clang++\" --target=aarch64-linux-android21"
cd "$package_dir"
mkdir -p .cache
go list -tags harmonia_boringssl -f 'Android 选择的 cgo 文件：{{join .CgoFiles ", "}}' .
go test -c -tags harmonia_boringssl -o .cache/pairing-android-arm64.test .
elf_header="$("$toolchain/bin/llvm-readelf" --file-header .cache/pairing-android-arm64.test)"
if ! rg --quiet 'Class:.*ELF64' <<< "$elf_header" || ! rg --quiet 'Machine:.*AArch64' <<< "$elf_header"; then
  printf '%s\n' '链接产物目标不是 ELF64/AArch64，停止验收。' >&2
  exit 2
fi
printf '%s\n' "$elf_header"
printf '%s\n' 'Android arm64 配对测试已编译并链接；尚未在 Android 运行。'
