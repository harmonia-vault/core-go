#!/usr/bin/env python3
"""交叉链接 Windows ARM64 项目配对测试；不执行测试、不安装工具。"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--output", type=pathlib.Path, help="新输出文件；省略时使用遵循 TMPDIR 的独占临时目录")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise RuntimeError("当前构建入口仅验收 Linux ARM64")
    package = pathlib.Path(__file__).resolve().parents[1]
    lock = json.loads((package / "boringssl.lock.json").read_text())
    metadata = json.loads((package / "native/windows-arm64/build-manifest.json").read_text())
    if metadata["boringsslCommit"] != lock["commit"] or metadata["symbolPrefix"] != lock["symbolPrefix"] or metadata["toolchainAssetSHA256"] != lock["windows"]["assetSHA256"] or metadata["sourceArchiveSHA256"] != lock["windows"]["sourceArchiveSHA256"]:
        raise RuntimeError("本地原生产物记录与固定输入不匹配")
    library = package / "native/windows-arm64/libcrypto.a"
    if hashlib.file_digest(library.open("rb"), "sha256").hexdigest() != metadata["artifacts"]["libcrypto.a"]["sha256"]:
        raise RuntimeError("本地静态库 SHA256 不匹配")
    # 与原生依赖构建一致，允许调用者通过 TMPDIR 选择磁盘目录。
    work = pathlib.Path(tempfile.mkdtemp(prefix="harmonia-windows-arm64-test-"))
    output = (args.output or work / "pairing.test.exe").absolute()
    if output.exists() or output.is_symlink():
        raise RuntimeError("测试输出文件已存在；不覆盖")
    toolchain = pathlib.Path(metadata["toolchainDirectory"])
    compiler = toolchain / "bin/aarch64-w64-mingw32-clang"
    if not compiler.is_file():
        raise RuntimeError("独占临时工具链已不存在；请重新构建，不自动安装其它工具")
    version = subprocess.run([args.go, "version"], capture_output=True, text=True, check=True).stdout.strip()
    if not version.startswith("go version go1.26.4 "):
        raise RuntimeError("必须使用固定 Go1.26.4")
    env = os.environ.copy()
    env.update({"GOOS": "windows", "GOARCH": "arm64", "CGO_ENABLED": "1", "GOENV": "off", "GOAUTH": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GOCACHEPROG": "", "GOMAXPROCS": "2",
                "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org", "CC": str(compiler), "CXX": str(toolchain / "bin/aarch64-w64-mingw32-clang++")})
    command = [args.go, "test", "-c", "-p", "2", "-tags", "harmonia_boringssl", "-o", str(output), "."]
    log = work / "compile.log"
    with log.open("xb") as stream:
        result = subprocess.run(command, cwd=package, env=env, stdout=stream, stderr=subprocess.STDOUT)
    record = {"command": command, "exitCode": result.returncode, "logSHA256": hashlib.file_digest(log.open("rb"), "sha256").hexdigest(), "windowsExecution": "未跑"}
    if result.returncode == 0:
        record["binarySHA256"] = hashlib.file_digest(output.open("rb"), "sha256").hexdigest()
        inspection = subprocess.run([str(toolchain / "bin/llvm-readobj"), "--file-headers", "--coff-imports", str(output)], capture_output=True, text=True, check=True).stdout
        (work / "pe-inspection.log").write_text(inspection)
        record["arm64"] = "IMAGE_FILE_MACHINE_ARM64" in inspection
        record["dlls"] = [line.strip().split(": ", 1)[1] for line in inspection.splitlines() if line.strip().startswith("Name: ") and ".dll" in line.lower()]
        if not record["arm64"] or any(not (d.upper() == "KERNEL32.DLL" or d.lower().startswith("api-ms-win-crt-")) for d in record["dlls"]):
            raise RuntimeError("测试 PE 架构或静态运行库依赖边界不符")
    (work / "compile-manifest.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"compiled": result.returncode == 0, "output": str(output), "privateManifest": str(work / "compile-manifest.json"), "windowsExecution": "未跑"}, ensure_ascii=False))
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
