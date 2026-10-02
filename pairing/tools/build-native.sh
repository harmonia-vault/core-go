#!/usr/bin/env bash
set -euo pipefail

# 仅在本包忽略目录构建固定原生依赖；不安装系统库或改其它项目。
package_dir="$(cd "$(dirname "$0")/.." && pwd)"
pin="fab96f87245d7c6b941515201843665122650b88"
repo="https://boringssl.googlesource.com/boringssl"
android_ndk=
android_api=21
if [[ "${1:-}" == --android-arm64 ]]; then
  shift
  android_ndk="${1:-}"
  if [[ -z "$android_ndk" || ! -f "$android_ndk/build/cmake/android.toolchain.cmake" ]]; then
    printf '%s\n' 'Android 构建必须显式传入已安装的固定 NDK 目录。' >&2
    exit 2
  fi
  if ! rg --quiet '^Pkg.Revision = 28\.2\.13676358$' "$android_ndk/source.properties"; then
    printf '%s\n' 'NDK 版本必须为已核验的 28.2.13676358；不自动安装或改已有 NDK。' >&2
    exit 2
  fi
  shift
  target=android-arm64
  cmake_arch=
else
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) target=darwin-arm64; cmake_arch=arm64 ;;
    Darwin/x86_64) target=darwin-amd64; cmake_arch=x86_64 ;;
    Linux/aarch64) target=linux-arm64; cmake_arch= ;;
    Linux/x86_64) target=linux-amd64; cmake_arch= ;;
    *) printf '%s\n' '本机构建仅验收 macOS/Linux；Android arm64 使用 --android-arm64 NDK 目录。' >&2; exit 2 ;;
  esac
fi
if [[ $# -gt 1 ]]; then
  printf '%s\n' '参数过多；只允许可选的固定上游源码目录。' >&2
  exit 2
fi
source_dir="${1:-$package_dir/.cache/boringssl-source}"
mkdir -p "$package_dir/.cache"
if [[ ! -e "$source_dir" ]]; then
  if [[ $# -gt 0 ]]; then
    printf '%s\n' '指定的上游源码目录不存在。' >&2
    exit 2
  fi
  mkdir -p "$source_dir"
  git -C "$source_dir" init --quiet
  git -C "$source_dir" remote add origin "$repo"
  git -C "$source_dir" fetch --depth=1 origin "$pin"
  git -C "$source_dir" checkout --detach --quiet FETCH_HEAD
fi
if [[ "$(git -C "$source_dir" rev-parse HEAD)" != "$pin" ]]; then
  printf '%s\n' '上游源码提交与固定版本不同，停止构建；不重置已有目录。' >&2
  exit 2
fi
if [[ -n "$(git -C "$source_dir" status --porcelain --untracked-files=no)" ]]; then
  printf '%s\n' '上游受跟踪源码存在改动，停止构建；不覆盖已有改动。' >&2
  exit 2
fi
build_dir="$package_dir/.cache/boringssl-$target"
args=(-S "$source_dir" -B "$build_dir" -GNinja -DCMAKE_BUILD_TYPE=Debug -DBORINGSSL_PREFIX=HARMONIA_BSSL)
if [[ -n "$android_ndk" ]]; then
  args+=(-DBUILD_TESTING=OFF -DCMAKE_TOOLCHAIN_FILE="$android_ndk/build/cmake/android.toolchain.cmake"
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM="android-$android_api" -DANDROID_STL=c++_static
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON)
else
  args+=(-DBUILD_TESTING=ON)
  if [[ -n "$cmake_arch" ]]; then args+=(-DCMAKE_OSX_ARCHITECTURES="$cmake_arch"); fi
fi
cmake "${args[@]}"
if [[ -n "$android_ndk" ]]; then
  cmake --build "$build_dir" --target crypto --parallel 4
else
  cmake --build "$build_dir" --target crypto crypto_test --parallel 4
  "$build_dir/crypto_test" '--gtest_filter=SPAKE25519Test.*'
fi
mkdir -p "$package_dir/native/include" "$package_dir/native/$target"
cp -R "$source_dir/include/openssl" "$package_dir/native/include/"
cp "$build_dir/libcrypto.a" "$package_dir/native/$target/libcrypto.a"
cp "$source_dir/LICENSE" "$package_dir/native/LICENSE"
if [[ -n "$android_ndk" ]]; then
  printf '%s\n' "已构建 $target/API $android_api 固定 BoringSSL 静态库；未在 Android 运行原语测试。"
else
  printf '%s\n' "已构建并验收 $target 的固定 BoringSSL SPAKE2；原生文件位于 Git 忽略目录。"
fi
