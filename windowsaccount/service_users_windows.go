//go:build windows

package windowsaccount

import (
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
	"strings"
	"unsafe"
)

type nativeServiceInventory struct{ manager *mgr.Mgr }

func (n nativeServiceInventory) Registry() ([]registryServiceRecord, error) {
	root, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if e != nil {
		return nil, ErrUncertain
	}
	defer root.Close()
	rootBefore, e := root.Stat()
	if e != nil {
		return nil, ErrUncertain
	}
	names, e := root.ReadSubKeyNames(-1)
	if e != nil || len(names) > 16384 {
		return nil, ErrUncertain
	}
	records := make([]registryServiceRecord, 0, len(names))
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, "\\/\x00") {
			return nil, ErrUncertain
		}
		key, e := registry.OpenKey(root, name, registry.QUERY_VALUE)
		if e != nil {
			return nil, ErrUncertain
		}
		record, readErr := readServiceRecord(name, key)
		closeErr := key.Close()
		if readErr != nil || closeErr != nil {
			return nil, ErrUncertain
		}
		record.RootWriteStamp = rootBefore.ModTime().UnixNano()
		records = append(records, record)
	}
	rootAfter, e := root.Stat()
	if e != nil || !rootBefore.ModTime().Equal(rootAfter.ModTime()) {
		return nil, ErrUncertain
	}
	return records, nil
}
func readServiceRecord(name string, key registry.Key) (registryServiceRecord, error) {
	record := registryServiceRecord{Name: name}
	before, e := key.Stat()
	if e != nil {
		return record, ErrUncertain
	}
	value, kind, e := key.GetIntegerValue("Type")
	if e == nil {
		if kind != registry.DWORD || value > 0xffffffff {
			return record, ErrUncertain
		}
		record.HasType = true
		record.Type = uint32(value)
	} else if !errors.Is(e, registry.ErrNotExist) {
		return record, ErrUncertain
	}
	account, kind, e := key.GetStringValue("ObjectName")
	if e == nil {
		if kind != registry.SZ || len(account) > 1024 || strings.ContainsAny(account, "\x00\r\n") {
			return record, ErrUncertain
		}
		record.HasAccount = true
		record.Account = account
	} else if !errors.Is(e, registry.ErrNotExist) {
		return record, ErrUncertain
	}
	after, e := key.Stat()
	if e != nil || !before.ModTime().Equal(after.ModTime()) {
		return record, ErrUncertain
	}
	record.WriteStamp = after.ModTime().UnixNano()
	return record, nil
}
func (n nativeServiceInventory) Service(name string) (serviceObservation, error) {
	s, e := openService(n.manager, name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return serviceObservation{}, errServiceNotPresent
	}
	if e != nil {
		return serviceObservation{}, ErrUncertain
	}
	defer s.Close()
	config, e := s.Config()
	if e != nil {
		return serviceObservation{}, ErrUncertain
	}
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if windows.QueryServiceStatusEx(s.Handle, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed) != nil || status.ServiceType != config.ServiceType {
		return serviceObservation{}, ErrUncertain
	}
	return serviceObservation{Type: config.ServiceType, Account: config.ServiceStartName, State: status.CurrentState, ProcessID: status.ProcessId}, nil
}
func (n nativeServiceInventory) Resolve(name string) (string, error) {
	if strings.HasPrefix(name, ".\\") {
		sid, err := resolveLocalShorthand(name, nativeSAMLookup{})
		if err != nil {
			return "", ErrUncertain
		}
		return sid, nil
	}
	if name == "S-1-5-18" {
		return name, nil
	}
	sid, _, kind, e := windows.LookupSID("", name)
	if e != nil || (kind != windows.SidTypeUser && kind != windows.SidTypeWellKnownGroup) {
		return "", ErrUncertain
	}
	return sid.String(), nil
}
func otherServicesForSID(p Plan) (int, error) {
	m, e := serviceManager(false)
	if e != nil {
		return 0, e
	}
	defer m.Disconnect()
	proof, e := inspectServiceUsers(p.TargetSID, nativeServiceInventory{manager: m})
	if e != nil || !proof.Complete {
		return 0, ErrUncertain
	}
	return proof.Count, nil
}
