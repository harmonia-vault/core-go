//go:build windows

package platform

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type registryUserStore struct {
	sid string
	key registry.Key
}

// OpenUserRegistry 仅打开已经加载的目标用户 hive；没有权限或 hive 未加载则失败，不暗中提权/加载 profile。
func OpenUserRegistry(sid string) (UserEnvironmentStore, error) {
	if !ValidSID(sid) {
		return nil, fmt.Errorf("invalid user SID")
	}
	if _, err := windows.StringToSid(sid); err != nil {
		return nil, err
	}
	key, err := registry.OpenKey(registry.USERS, sid+`\Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, fmt.Errorf("target user hive is unavailable or access denied: %w", err)
	}
	return &registryUserStore{sid: sid, key: key}, nil
}
func (s *registryUserStore) UserSID() string { return s.sid }
func (s *registryUserStore) Read(name string) (RegistryValue, bool, error) {
	value, typ, err := s.key.GetStringValue(name)
	if err == registry.ErrNotExist {
		return RegistryValue{}, false, nil
	}
	if err != nil {
		return RegistryValue{}, false, err
	}
	if typ != registry.SZ && typ != registry.EXPAND_SZ {
		return RegistryValue{}, false, fmt.Errorf("unsupported registry value type")
	}
	return RegistryValue{Value: value, Expand: typ == registry.EXPAND_SZ}, true, nil
}
func (s *registryUserStore) Set(name string, value RegistryValue) error {
	if value.Expand {
		return s.key.SetExpandStringValue(name, value.Value)
	}
	return s.key.SetStringValue(name, value.Value)
}
func (s *registryUserStore) Delete(name string) error {
	err := s.key.DeleteValue(name)
	if err == registry.ErrNotExist {
		return nil
	}
	return err
}
func (s *registryUserStore) Close() error { return s.key.Close() }
func (s *registryUserStore) Notify() error {
	name, err := syscall.UTF16PtrFromString("Environment")
	if err != nil {
		return err
	}
	var result uintptr
	proc := windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")
	ok, _, callErr := proc.Call(0xffff, 0x001a, 0, uintptr(unsafe.Pointer(name)), 0x0002, 5000, uintptr(unsafe.Pointer(&result)))
	// Session 0 无接收窗口时仍已持久化；超时不能把持久化写入当作未提交。
	if ok == 0 && callErr != windows.ERROR_SUCCESS {
		return fmt.Errorf("environment persisted; broadcast failed: %w", callErr)
	}
	return nil
}
