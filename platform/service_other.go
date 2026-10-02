//go:build !windows

package platform

import (
	"context"
	"fmt"
)

func RunWindowsService(ctx context.Context, name string, run func(context.Context) error) error {
	return fmt.Errorf("Windows service runtime requires Windows")
}
