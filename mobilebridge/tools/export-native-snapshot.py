#!/usr/bin/env python3
"""导出明确公开commit+有限native候选覆盖；不复制ignored钥/产物/环境，不覆写目录。"""
from pathlib import Path
import argparse, hashlib, io, json, subprocess, tarfile

CORE_FILES = [
    'mobilebridge/workflow.go', 'mobilebridge/v3_test.go',
    'mobilebridge/cmd/androidfixture/main.go',
    'mobilebridge/cmd/crosscontroller/main.go',
    'mobilebridge/cmd/genericcontroller/main.go',
]
MOBILE_FILES = [
    'android/app/src/main/kotlin/org/harmoniavault/harmonia_mobile/nativebridge/NativeBridgePlugin.kt',
    'lib/native/native_workflow_adapter.dart',
    'android/app/src/androidTest/kotlin/org/harmoniavault/harmonia_mobile/nativebridge/NativeGenericIntegrationTest.kt',
    'android/app/src/androidTest/kotlin/org/harmoniavault/harmonia_mobile/nativebridge/NativeGenericTestSocket.kt',
    'tool/native-generic-test.py',
]

def git(directory, *args):
    return subprocess.run(['git', '-C', str(directory), *args], check=True, capture_output=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    for name in ('workspace', 'core', 'mobile', 'server', 'protocol'):
        parser.add_argument('--'+name+'-revision', required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve(strict=True)
    output = args.output.absolute()
    # 只在该新项目ignored .build内创建新导出；拒symlink/覆写，绝不复制当前用户配置。
    cache = (workspace/'core-go/.build').resolve(strict=True)
    if output.parent.resolve(strict=True) != cache or output.exists() or output.is_symlink():
        raise SystemExit('输出须是core-go/.build内不存在的新目录')
    if not git(workspace/'core-go', 'check-ignore', str(output)).strip():
        raise SystemExit('导出目录必须ignored')
    commits = {}
    archives = {}
    for name, directory in [('workspace', workspace), ('core', workspace/'core-go'), ('mobile', workspace/'mobile'), ('server', workspace/'server'), ('protocol', workspace/'protocol')]:
        revision = getattr(args, name+'_revision')
        if len(revision) != 40 or any(c not in '0123456789abcdef' for c in revision):
            raise SystemExit('必须给完整commit SHA')
        commit = git(directory, 'rev-parse', revision+'^{commit}').decode().strip()
        if commit != revision:
            raise SystemExit('commit解析不一致')
        # 公开底座必须确实属于远端main，不能把未推送commit标为公开。
        git(directory, 'merge-base', '--is-ancestor', commit, 'origin/main')
        commits[name] = commit
        archives[name] = git(directory, 'archive', '--format=tar', commit)
    output.mkdir(mode=0o700)
    manifest = {'version': 1, 'commits': commits, 'archiveSHA256': {}, 'candidateOverrides': {}, 'filesSHA256': {},
                'scope': '公开源码归档加明确native候选文件，无VCS元数据；不声称整个当前working tree通过',
                'excluded': ['RecoverySession/management未公开草稿', 'UI改动', 'ignored产物/钥/本机配置'],
                'bootstrap': ['固定BoringSSL源码构建host/Android static库与headers', '官方固定mise工具链', 'Node locked依赖缓存', 'Flutter pub locked依赖与explicit SDK本机配置']}
    for name, archive in archives.items():
        dest = output if name == 'workspace' else output / ('core-go' if name == 'core' else name)
        dest.mkdir(exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
            tree.extractall(dest, filter='data')
        manifest['archiveSHA256'][name] = hashlib.sha256(archive).hexdigest()
    for name, files in [('core-go', CORE_FILES), ('mobile', MOBILE_FILES)]:
        for filename in files:
            source = workspace/name/filename
            if not source.is_file() or source.is_symlink():
                raise SystemExit('候选文件不是正常源码文件')
            data = source.read_bytes()
            dest = output/name/filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            manifest['candidateOverrides'][name+'/'+filename] = hashlib.sha256(data).hexdigest()
    for path in sorted(output.rglob('*')):
        if path.is_file() and not path.is_symlink():
            manifest['filesSHA256'][path.relative_to(output).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    (output/'source-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2)+'\n')
    print('已导出明确公开源码与native候选；ignored依赖/产物须按固定任务独立bootstrap')

if __name__ == '__main__':
    main()
