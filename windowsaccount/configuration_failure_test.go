package windowsaccount

import (
	"errors"
	"syscall"
	"testing"
)

func TestConfigurationFailureCodeIsBoundedAndPrivate(t *testing.T) {
	err := configurationFailure(2, 1, 3, syscall.Errno(5))
	code, ok := ConfigurationFailureCode(err)
	if !ok || code != 0x48213005 || err.Error() != ErrPlan.Error() || !errors.Is(err, ErrPlan) {
		t.Fatal("fixed ancestor/native code contract")
	}
	code, ok = ConfigurationFailureCode(configurationFailure(3, 8, 15, nil))
	if !ok || code != 0x4838f000 {
		t.Fatal("fixed leaf invariant code")
	}
	code, ok = ConfigurationFailureCode(configurationFailure(1, 1, 15, syscall.Errno(0xffff)))
	if !ok || code != 0x4811ffff {
		t.Fatal("large native code must stay unknown")
	}
	if _, ok = ConfigurationFailureCode(configurationFailure(0, 1, 0, nil)); ok {
		t.Fatal("generic validation became diagnostic")
	}
	if _, ok = ConfigurationFailureCode(&configurationRejection{resource: 9, operation: 99, index: 99, native: 0xffff}); ok {
		t.Fatal("unbounded diagnostic accepted")
	}
}
