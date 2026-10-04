package windowsaccount

import (
	"errors"
	"slices"
	"strings"
)

var errServiceNotPresent = errors.New("service_not_present")

type registryServiceRecord struct {
	Name           string
	Type           uint32
	HasType        bool
	Account        string
	HasAccount     bool
	WriteStamp     int64
	RootWriteStamp int64
}
type serviceObservation struct {
	Type      uint32
	Account   string
	State     uint32
	ProcessID uint32
}
type serviceInventorySource interface {
	Registry() ([]registryServiceRecord, error)
	Service(string) (serviceObservation, error)
	Resolve(string) (string, error)
}
type serviceUsersProof struct {
	Complete bool
	Count    int
}

func normalizedRegistry(records []registryServiceRecord) ([]registryServiceRecord, error) {
	if len(records) == 0 {
		return nil, ErrUncertain
	}
	records = slices.Clone(records)
	seen := map[string]bool{}
	for _, record := range records {
		name := strings.ToLower(record.Name)
		if name == "" || strings.ContainsAny(name, "\\/\x00") || seen[name] {
			return nil, ErrUncertain
		}
		seen[name] = true
	}
	slices.SortFunc(records, func(a, b registryServiceRecord) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return records, nil
}
func systemDefaultAccount(value string) string {
	if value == "" || strings.EqualFold(value, "LocalSystem") {
		return "S-1-5-18"
	}
	return value
}

// 没有通过完整登记表核对的零count不构成撤销依据。此证明只有只读观察，没有LSA修改。
// 两次registry快照检测可见增删/改动；不能代替SCM与LSA之间不存在的原子事务。
func inspectServiceUsers(target string, source serviceInventorySource) (serviceUsersProof, error) {
	fail := func() (serviceUsersProof, error) { return serviceUsersProof{}, ErrUncertain }
	if target == "" || source == nil {
		return fail()
	}
	first, e := source.Registry()
	if e != nil {
		return fail()
	}
	first, e = normalizedRegistry(first)
	if e != nil {
		return fail()
	}
	count := 0
	for _, record := range first {
		observed, e := source.Service(record.Name)
		if errors.Is(e, errServiceNotPresent) && !record.HasType && !record.HasAccount {
			continue
		}
		if e != nil || !record.HasType || record.Type != observed.Type || observed.State < 1 || observed.State > 7 {
			return fail()
		}
		// 每用户模板/实例有特殊用户上下文，空ObjectName不能解释为LocalSystem。
		// 这里未证明其LSA使用语义；不推断它们一定需要或不需要service-logon right。
		if record.Type&0xc0 != 0 {
			return fail()
		}
		switch record.Type {
		case 1, 2, 8: // 已由SCM回验的driver，不是LSA服务账号登录。
			continue
		case 0x10, 0x20, 0x110, 0x120:
		default:
			return fail()
		}
		registered := systemDefaultAccount(record.Account)
		actual := systemDefaultAccount(observed.Account)
		registeredSID, e := source.Resolve(registered)
		if e != nil || registeredSID == "" {
			return fail()
		}
		actualSID, e := source.Resolve(actual)
		if e != nil || actualSID == "" || actualSID != registeredSID {
			return fail()
		}
		if actualSID == target {
			count++
		}
	}
	second, e := source.Registry()
	if e != nil {
		return fail()
	}
	second, e = normalizedRegistry(second)
	if e != nil || !slices.Equal(first, second) {
		return fail()
	}
	return serviceUsersProof{Complete: true, Count: count}, nil
}
