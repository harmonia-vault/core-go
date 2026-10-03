//go:build !darwin && !linux

package localkeys

import "errors"

// OpenExisting 仅支持已验同 UID Unix 后台保护；其他平台明确拒绝。
func OpenExisting(Config) (*Vault, error) {
	return nil, errors.New("此平台的受保护离线退出尚未实现")
}
