package windowsaccount

import (
	"errors"
	"syscall"
)

// This diagnostic carries only fixed enums and a bounded native code, never a
// path, ACL principal, configuration body, username or underlying error text.
type configurationRejection struct {
	resource, operation, index uint8
	native                     uint32
}

func (e *configurationRejection) Error() string { return ErrPlan.Error() }
func (e *configurationRejection) Unwrap() error { return ErrPlan }
func configurationFailure(resource, operation, index uint8, err error) error {
	if resource == 0 {
		return ErrPlan
	} // Existing installer/IPC validation contract.
	native := uint32(0)
	if err != nil {
		native = 0xfff
		var n syscall.Errno
		if errors.As(err, &n) && uint64(n) < 0xfff {
			native = uint32(n)
		}
	}
	return &configurationRejection{resource, operation, index, native}
}

// Code layout: 0x48 R O I NNN. R=1 initial config,2 config pin,3 image
// pin,4 CA pin; O=1..13 fixed operation; I=0..14 ancestor or15 leaf;
// NNN=Win32 0..4094,4095 unknown/too large,0 logical invariant rejection.
func ConfigurationFailureCode(err error) (uint32, bool) {
	var e *configurationRejection
	if !errors.As(err, &e) || e.resource < 1 || e.resource > 4 || e.operation < 1 || e.operation > 13 || e.index > 15 || e.native > 0xfff {
		return 0, false
	}
	return 0x48000000 | uint32(e.resource)<<20 | uint32(e.operation)<<16 | uint32(e.index)<<12 | e.native, true
}
