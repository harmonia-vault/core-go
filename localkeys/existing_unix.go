//go:build darwin || linux

package localkeys

// OpenExisting 使用原有 FD 保护与非阻塞独占；不创建目录、锁或机器钥。
func OpenExisting(c Config) (*Vault, error) {
	fs, owner, err := openUnixSecureFS(c, true)
	if err != nil {
		return nil, err
	}
	return openVault(c, fs, owner, false)
}
