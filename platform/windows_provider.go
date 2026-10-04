package platform

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
)

// RegistryValue 保留 REG_SZ/REG_EXPAND_SZ，不展开变量引用。
type RegistryValue struct {
	Value  string
	Expand bool
}

// UserEnvironmentStore 必须绑定一个明确 SID，禁止把服务账号的 HKCU 当目标用户。
type UserEnvironmentStore interface {
	UserSID() string
	Read(name string) (RegistryValue, bool, error)
	Set(name string, value RegistryValue) error
	Delete(name string) error
	Notify() error
}

type WindowsProvider struct {
	mu            sync.Mutex
	store         UserEnvironmentStore
	originals     map[string]registryOriginal
	statePath     string
	secret        *localkeys.Vault
	notifyPending bool
}

func NewWindowsProvider(expectedSID string, store UserEnvironmentStore) (*WindowsProvider, error) {
	if !ValidSID(expectedSID) || store == nil || store.UserSID() != expectedSID {
		return nil, fmt.Errorf("user SID binding mismatch")
	}
	return &WindowsProvider{store: store, originals: map[string]registryOriginal{}}, nil
}

func (p *WindowsProvider) Snapshot(ctx context.Context, names []string) (map[string]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := uniqueWindowsNames(names); err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !ValidName(name) {
			return nil, fmt.Errorf("invalid name")
		}
		value, exists, err := p.store.Read(name)
		if err != nil {
			return nil, err
		}
		folded := strings.ToUpper(name)
		if _, saved := p.originals[folded]; !saved {
			p.originals[folded] = registryOriginal{Present: exists, Value: value}
		}
		if exists {
			result[name] = value.Value
		}
	}
	if err := p.save(); err != nil {
		return nil, err
	}
	return result, nil
}

func (p *WindowsProvider) Apply(ctx context.Context, changes []localstate.Change) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	names := make([]string, 0, len(changes))
	for _, change := range changes {
		names = append(names, change.Name)
	}
	if err := uniqueWindowsNames(names); err != nil {
		return err
	}
	for _, change := range changes {
		if change.Value != nil && strings.ContainsRune(*change.Value, 0) {
			return fmt.Errorf("NUL is not an environment value")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(changes) > 0 {
		// 注册表写入后进程可能退出，或广播可能失败。先保存待通知状态，
		// 即使下一次同步发现值已相同，也必须完成原通知再报告成功。
		p.notifyPending = true
		if err := p.save(); err != nil {
			return err
		}
	}
	for _, change := range changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !ValidName(change.Name) {
			return fmt.Errorf("invalid name")
		}
		folded := strings.ToUpper(change.Name)
		original, saved := p.originals[folded]
		if !saved {
			value, exists, err := p.store.Read(change.Name)
			if err != nil {
				return err
			}
			original = registryOriginal{Present: exists, Value: value}
			p.originals[folded] = original
			if err := p.save(); err != nil {
				return err
			}
		}
		// 即使上次保存失败留下内存记录，也必须先保证原值已落盘。
		if err := p.save(); err != nil {
			return err
		}
		if change.Release {
			if original.Present {
				if err := p.store.Set(change.Name, original.Value); err != nil {
					return err
				}
			} else if err := p.store.Delete(change.Name); err != nil {
				return err
			}
			delete(p.originals, folded)
			if err := p.save(); err != nil {
				p.originals[folded] = original
				return err
			}
			continue
		}
		if change.Value == nil {
			if err := p.store.Delete(change.Name); err != nil {
				return err
			}
			continue
		}
		if err := p.store.Set(change.Name, RegistryValue{Value: *change.Value}); err != nil {
			return err
		}
	}
	if p.notifyPending {
		if err := p.store.Notify(); err != nil {
			return err
		}
		p.notifyPending = false
		if err := p.save(); err != nil {
			p.notifyPending = true
			return err
		}
	}
	return nil
}

// MemoryUserStore 是测试用的隔离假注册表，不会读取或写入宿主注册表。
type MemoryUserStore struct {
	SID           string
	Values        map[string]RegistryValue
	Notifications int
}

func (s *MemoryUserStore) UserSID() string { return s.SID }
func (s *MemoryUserStore) Read(name string) (RegistryValue, bool, error) {
	v, ok := s.Values[strings.ToUpper(name)]
	return v, ok, nil
}
func (s *MemoryUserStore) Set(name string, v RegistryValue) error {
	if s.Values == nil {
		s.Values = map[string]RegistryValue{}
	}
	s.Values[strings.ToUpper(name)] = v
	return nil
}
func (s *MemoryUserStore) Delete(name string) error {
	delete(s.Values, strings.ToUpper(name))
	return nil
}
func (s *MemoryUserStore) Notify() error { s.Notifications++; return nil }
func (s *MemoryUserStore) Names() []string {
	names := make([]string, 0, len(s.Values))
	for name := range s.Values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
