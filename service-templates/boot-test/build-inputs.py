import sys
if sys.flags.optimize: raise SystemExit("测试脚本禁止关闭断言")
#!/usr/bin/env python3
"""只打包已通过仓库公开源扫描的源码与合成启动测试输入，不打包忽略文件。"""
import argparse
import pathlib
import subprocess
import sys
import tarfile
p=argparse.ArgumentParser();p.add_argument('--workspace',required=True);p.add_argument('--output',required=True)
a=p.parse_args();root=pathlib.Path(a.workspace).resolve(strict=True);output=pathlib.Path(a.output)
if output.exists() or output.is_symlink():raise SystemExit('拒绝覆盖输出文件')
subprocess.run([sys.executable,str(root/'scripts/check_source.py')],cwd=root,check=True)
assets=root/'core-go/service-templates/boot-test'
with tarfile.open(output,'x:gz') as tar:
 for repo in ['core-go','server']:
  names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root/repo).decode().split('\0')
  for name in sorted(set(names)-{''}):
   file=root/repo/name
   if file.is_file() and not file.is_symlink():tar.add(file,arcname=repo+'/'+name,recursive=False)
 for file in [root/'go.mod',root/'go.sum',*sorted((root/'acceptance').glob('*.go'))]:tar.add(file,arcname=str(file.relative_to(root)),recursive=False)
 tar.add(assets/'boot_prepare_test.go.in',arcname='acceptance/boot_prepare_test.go',recursive=False)
 tar.add(assets/'orbstack-boot-server.ts.in',arcname='server/tests/orbstack-boot-server.ts',recursive=False)
print('公开源与合成启动测试输入已打包；不包含忽略的原生库/构建产物/部署数据')
