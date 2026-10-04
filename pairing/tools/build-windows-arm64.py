#!/usr/bin/env python3
"""在独占临时目录构建固定 Windows ARM64 原生配对依赖，不安装工具。"""
import argparse
import hashlib
import gzip
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

PIN = "fab96f87245d7c6b941515201843665122650b88"
SOURCE_BYTES = 249630720
SOURCE_SHA = "0f0e21f670dd6c06a5ff9fc8a83748aeb959c6ca7ea4cb0ff8c62c9d88aa4002"
ASSET = "llvm-mingw-20260922-ucrt-ubuntu-22.04-aarch64.tar.xz"
ASSET_SHA = "07d21263c56bfe9a713db6fdb3f7434bf4c121a005e40397d3b4c0170fb06769"
URL = "https://github.com/mstorsjo/llvm-mingw/releases/download/20260922/" + ASSET
PREFIX = "HARMONIA_BSSL"


def digest(path):
    with path.open("rb") as stream:
        result = hashlib.file_digest(stream, "sha256")
    return result.hexdigest()


def invoke(args, **options):
    return subprocess.run(args, check=True, **options)


def extract_locked_archive(archive, destination, compressed=False):
    # 归档已经核验固定 SHA；GNU tar 流式解压，不在 Python 中随机读取大 XZ 文件。
    flags = ["--xz"] if compressed else []
    listed = invoke(["tar", "--list", *flags, "--file", str(archive)], capture_output=True, text=True).stdout
    for name in listed.splitlines():
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError("固定归档含不允许的成员路径")
    destination.mkdir()
    invoke(["tar", "--extract", *flags, "--file", str(archive), "--directory", str(destination), "--no-same-owner", "--no-same-permissions"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source", type=pathlib.Path, help="已存在且无跟踪改动的固定 BoringSSL Git 源码")
    source.add_argument("--source-archive", type=pathlib.Path, help="固定提交的 git archive tar；必须匹配锁定 SHA256")
    parser.add_argument("--go", default="go", help="已安装的 Go1.26.4 可执行文件；不自动安装")
    parser.add_argument("--output", type=pathlib.Path, help="新原生产物目录；默认本包 native/windows-arm64")
    args = parser.parse_args()
    if sys.version_info < (3, 12) or platform.system() != "Linux" or platform.machine() != "aarch64":
        raise RuntimeError("构建入口当前仅验收 Linux ARM64/Python3.12；不自动安装工具")
    package = pathlib.Path(__file__).resolve().parents[1]
    output = (args.output or package / "native" / "windows-arm64").absolute()
    if output.exists() or output.is_symlink():
        raise RuntimeError("原生产物目录已存在；请显式选择新目录，不覆盖已有产物")
    go_version = invoke([args.go, "version"], capture_output=True, text=True).stdout.strip()
    if not go_version.startswith("go version go1.26.4 "):
        raise RuntimeError("必须使用固定 Go1.26.4，不自动下载其它 Go 版本")
    cmake_version = invoke(["cmake", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    ninja_version = invoke(["ninja", "--version"], capture_output=True, text=True).stdout.strip()
    # 上游要求 CMake >=3.22；调用环境可通过本目录 mise.toml 固定版本。
    cmake_numbers = tuple(int(n) for n in cmake_version.split()[-1].split(".")[:2])
    if cmake_numbers < (3, 22):
        raise RuntimeError("CMake 版本不满足固定上游要求")
    # 遵循 TMPDIR；大体积工具链与中间文件应放在磁盘，避免耗尽容器 tmpfs 配额。
    work = pathlib.Path(tempfile.mkdtemp(prefix="harmonia-bssl-windows-arm64-"))
    record = {"boringsslCommit": PIN, "symbolPrefix": PREFIX, "toolchainAsset": ASSET, "toolchainAssetSHA256": ASSET_SHA,
              "goVersion": go_version, "cmakeVersion": cmake_version, "ninjaVersion": ninja_version,
              "profile": "boringssl-spake2-edwards25519-draft02-v1", "temporaryDirectory": str(work)}
    manifest = work / "build-manifest.json"

    def save():
        manifest.write_text(json.dumps(record, indent=2) + "\n")

    try:
        archive = work / "source.tar"
        if args.source:
            head = invoke(["git", "-C", str(args.source), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            dirty = invoke(["git", "-C", str(args.source), "status", "--porcelain", "--untracked-files=no"], capture_output=True).stdout
            if head != PIN or dirty:
                raise RuntimeError("指定源码不符合固定提交或存在跟踪改动")
            with archive.open("xb") as out:
                invoke(["git", "-C", str(args.source), "archive", "--format=tar", PIN], stdout=out)
        else:
            opener = gzip.open if args.source_archive.suffix == ".gz" else pathlib.Path.open
            with opener(args.source_archive, "rb") as inp, archive.open("xb") as out:
                count = 0
                while chunk := inp.read(min(65536, SOURCE_BYTES - count + 1)):
                    count += len(chunk)
                    if count > SOURCE_BYTES:
                        raise RuntimeError("源码归档超过固定大小；不继续解压")
                    out.write(chunk)
                if count != SOURCE_BYTES:
                    raise RuntimeError("源码归档大小与固定提交不匹配")
        record["sourceArchiveSHA256"] = digest(archive)
        if record["sourceArchiveSHA256"] != SOURCE_SHA:
            raise RuntimeError("固定源码归档 SHA256 不匹配；不继续编译")
        record["stage"] = "source_extraction"
        save()
        extract_locked_archive(archive, work / "source")
        asset = work / ASSET
        with urllib.request.urlopen(URL, timeout=90) as inp, asset.open("xb") as out:
            shutil.copyfileobj(inp, out)
        if digest(asset) != ASSET_SHA:
            raise RuntimeError("官方工具链下载 SHA256 不匹配；不执行工具")
        record["stage"] = "toolchain_extraction"
        save()
        extract_locked_archive(asset, work / "toolchain", compressed=True)
        entries = list((work / "toolchain").iterdir())
        if len(entries) != 1 or entries[0].name != ASSET.removesuffix(".tar.xz"):
            raise RuntimeError("工具链归档目录结构不符")
        toolchain = entries[0]
        compiler = toolchain / "bin" / "aarch64-w64-mingw32-clang"
        triple = invoke([str(compiler), "-dumpmachine"], capture_output=True, text=True).stdout.strip()
        if triple != "aarch64-w64-windows-gnu":
            raise RuntimeError("工具链目标架构不符")
        record["targetTriple"] = triple
        record["compilerVersion"] = invoke([str(compiler), "--version"], capture_output=True, text=True).stdout.splitlines()[0]
        record["toolchainDirectory"] = str(toolchain)
        build = work / "build"
        configure = ["cmake", "-S", str(work / "source"), "-B", str(build), "-GNinja", "-DCMAKE_SYSTEM_NAME=Windows",
                     "-DCMAKE_SYSTEM_PROCESSOR=ARM64", "-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_EXE_LINKER_FLAGS=-static",
                     "-DCMAKE_C_COMPILER=" + str(compiler), "-DCMAKE_CXX_COMPILER=" + str(toolchain / "bin" / "aarch64-w64-mingw32-clang++"),
                     "-DCMAKE_ASM_COMPILER=" + str(compiler), "-DCMAKE_RC_COMPILER=" + str(toolchain / "bin" / "aarch64-w64-mingw32-windres"),
                     "-DBORINGSSL_PREFIX=" + PREFIX, "-DGO_EXECUTABLE=" + str(pathlib.Path(shutil.which(args.go) or args.go).resolve()), "-DBUILD_TESTING=ON"]
        for stage, command in [("configure", configure), ("build", ["cmake", "--build", str(build), "--target", "crypto", "crypto_test", "--parallel", "2"])]:
            log = work / (stage + ".log")
            start = time.monotonic()
            with log.open("xb") as out:
                result = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT)
            record[stage] = {"command": command, "exitCode": result.returncode, "seconds": round(time.monotonic() - start, 3), "logSHA256": digest(log)}
            save()
            if result.returncode:
                raise RuntimeError("原生构建失败；私有 manifest 保留日志位置与 hash")
        symbols = invoke([str(toolchain / "bin" / "llvm-nm"), "--defined-only", str(build / "libcrypto.a")], capture_output=True, text=True).stdout
        names = {line.split()[-1] for line in symbols.splitlines() if "SPAKE2_" in line}
        expected = {PREFIX + "_SPAKE2_" + name for name in ["CTX_new", "CTX_free", "generate_msg", "process_msg"]}
        if names != expected:
            raise RuntimeError("固定 SPAKE2 符号前缀不符")
        inspection = invoke([str(toolchain / "bin" / "llvm-readobj"), "--file-headers", "--coff-imports", str(build / "crypto_test.exe")], capture_output=True, text=True).stdout
        (work / "pe-inspection.log").write_text(inspection)
        dlls = [line.strip().split(": ", 1)[1] for line in inspection.splitlines() if line.strip().startswith("Name: ") and ".dll" in line.lower()]
        if "IMAGE_FILE_MACHINE_ARM64" not in inspection or any(not (d.upper() in {"KERNEL32.DLL", "WS2_32.DLL"} or d.lower().startswith("api-ms-win-crt-")) for d in dlls):
            raise RuntimeError("ARM64 PE 架构或系统 DLL 边界不符")
        record["spakeSymbols"] = sorted(names)
        record["dlls"] = dlls
        record["artifacts"] = {name: {"sha256": digest(build / name), "bytes": (build / name).stat().st_size} for name in ["libcrypto.a", "crypto_test.exe"]}
        record["windowsExecution"] = "未跑；必须另在 Windows 来宾运行上游与原生配对测试"
        # 公共头文件只允许首次复制或与已有固定头完全一致，避免影响其它平台产物。
        include = package / "native" / "include" / "openssl"
        headers = list((work / "source" / "include" / "openssl").rglob("*"))
        for path in headers:
            if path.is_file():
                dest = include / path.relative_to(work / "source" / "include" / "openssl")
                if dest.exists() and dest.read_bytes() != path.read_bytes():
                    raise RuntimeError("已有原生头文件与固定源码不同；不覆盖")
        output.mkdir(parents=True, exist_ok=False)
        for path in headers:
            if path.is_file():
                dest = include / path.relative_to(work / "source" / "include" / "openssl")
                dest.parent.mkdir(parents=True, exist_ok=True)
                if not dest.exists():
                    with dest.open("xb") as out, path.open("rb") as inp:
                        shutil.copyfileobj(inp, out)
        shutil.copyfile(build / "libcrypto.a", output / "libcrypto.a")
        shutil.copyfile(work / "source" / "LICENSE", output / "LICENSE")
        save()
        shutil.copyfile(manifest, output / "build-manifest.json")
        print(json.dumps({"built": True, "temporaryDirectory": str(work), "outputDirectory": str(output), "libcryptoSHA256": record["artifacts"]["libcrypto.a"]["sha256"], "windowsExecution": "未跑"}, ensure_ascii=False))
    except Exception as exc:
        record["failureClass"] = type(exc).__name__
        save()
        print(json.dumps({"built": False, "temporaryDirectory": str(work), "failureClass": type(exc).__name__}, ensure_ascii=False), file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
