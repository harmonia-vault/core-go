//go:build !darwin && !linux && !windows

package localkeys

import "fmt"

func CurrentUserID() (string, error) { return "", fmt.Errorf("localkeys runtime is unsupported") }
func openSecureFS(c Config) (secureFS, string, error) {
	return nil, "", fmt.Errorf("localkeys runtime is unsupported")
}
func protectorName() string                                                { return "unsupported" }
func protectMachineKey(key []byte, c Config, owner string) ([]byte, error) { return nil, ErrPermission }
func unprotectMachineKey(data []byte, c Config, owner string) ([]byte, error) {
	return nil, ErrPermission
}
