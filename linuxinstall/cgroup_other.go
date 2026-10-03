//go:build !linux

package linuxinstall

import "context"

func checkCgroupDrained(context.Context, string) error { return ErrUnsupported }
