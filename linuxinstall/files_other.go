//go:build !linux

package linuxinstall

type AdminStore struct{}

func OpenAdminStore() (*AdminStore, error) { return nil, ErrUnsupported }
