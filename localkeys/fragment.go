package localkeys

import (
	"bytes"
	"errors"
	"os"
)

const environmentFragmentName = "environment.sh"
const environmentFragmentMarker = "# Harmonia managed fragment v1\n"

// Directory 和 TargetUserID 只返回已验证的配置绑定，不暴露钥匙。
func (v *Vault) Directory() string    { return v.config.Directory }
func (v *Vault) TargetUserID() string { return v.config.UserID }

// WriteEnvironmentFragment 写固定的 shell 消费文件：此文件必须可直接 source，
// 因此值为权限保护的本地明文；所有辅助状态仍存入 AEAD slot。
// 调用方只能写带工具标记的文件，不能选择任意文件名或覆盖非工具文件。
func (v *Vault) WriteEnvironmentFragment(data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	if !bytes.HasPrefix(data, []byte(environmentFragmentMarker)) || len(data) > 16<<20 {
		return ErrCorrupt
	}
	if err := v.ensureKey(); err != nil {
		return err
	}
	previous, err := v.fs.Read(environmentFragmentName, 16<<20)
	if err == nil && !bytes.HasPrefix(previous, []byte(environmentFragmentMarker)) {
		clear(previous)
		return ErrCorrupt
	}
	clear(previous)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return v.fs.Write(environmentFragmentName, data, false)
}
