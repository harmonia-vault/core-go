//go:build !windows

package platform

import "fmt"

func OpenUserRegistry(sid string) (UserEnvironmentStore, error) {
	return nil, fmt.Errorf("Windows registry adapter requires Windows")
}
