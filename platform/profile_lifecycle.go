package platform

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

var ErrProfileClosed = errors.New("profile environment is closing or closed")
var ErrProfileIdentity = errors.New("profile identity or local path policy rejected")
var ErrProfilePrivilege = errors.New("profile broker requires existing SYSTEM privileges")

// 仅 backend 持有 profile 根和 token；调用方只得到固定 Environment 接口。
type closeableUserEnvironment interface {
	UserEnvironmentStore
	Close() error
}
type profileBackend interface {
	Load() (bool, error)
	OpenEnvironment() (closeableUserEnvironment, error)
	Unload() error
	Close() error
}

// ProfileEnvironmentStore 将读写、加载和停止串行化。必须由唯一 broker owner 调用 Close。
// 它不取得用户 token、不授予 ACL，也不提供任意路径或注册表根的访问。
type ProfileEnvironmentStore struct {
	mu       sync.Mutex
	sid      string
	backend  profileBackend
	key      closeableUserEnvironment
	loaded   bool
	closing  bool
	closed   bool
	stopping atomic.Bool
}

func newProfileEnvironmentStore(sid string, backend profileBackend) (*ProfileEnvironmentStore, error) {
	if !ValidSID(sid) || backend == nil {
		return nil, ErrProfileIdentity
	}
	return &ProfileEnvironmentStore{sid: sid, backend: backend}, nil
}
func (s *ProfileEnvironmentStore) UserSID() string { return s.sid }
func (s *ProfileEnvironmentStore) open() error {
	if s.stopping.Load() || s.closing || s.closed {
		return ErrProfileClosed
	}
	if !s.loaded {
		owned, err := s.backend.Load()
		s.loaded = owned
		if err != nil {
			// 原生加载成功后策略检查失败仍持有引用，停止访问并保留清理能力。
			if owned {
				s.closing = true
				s.stopping.Store(true)
			}
			return err
		}
		if !owned {
			s.closing = true
			s.stopping.Store(true)
			return ErrProfileIdentity
		}
	}
	if s.key == nil {
		key, err := s.backend.OpenEnvironment()
		if err != nil {
			return err
		}
		if key == nil {
			return ErrProfileIdentity
		}
		// 身份绑定异常必须先关闭子 key；Close 失败时保留句柄供停止重试。
		s.key = key
		if key.UserSID() != s.sid {
			s.closing = true
			s.stopping.Store(true)
			return ErrProfileIdentity
		}
	}
	return nil
}

// EnsureReady 只完成 profile 与固定 Environment 子 key 的验证，不读取任何变量值。
func (s *ProfileEnvironmentStore) EnsureReady() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open()
}

func (s *ProfileEnvironmentStore) Read(name string) (RegistryValue, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidName(name) {
		return RegistryValue{}, false, fmt.Errorf("invalid environment name")
	}
	if err := s.open(); err != nil {
		return RegistryValue{}, false, err
	}
	return s.key.Read(name)
}
func (s *ProfileEnvironmentStore) Set(name string, value RegistryValue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidName(name) || strings.ContainsRune(value.Value, 0) {
		return fmt.Errorf("invalid environment name or value")
	}
	if err := s.open(); err != nil {
		return err
	}
	return s.key.Set(name, value)
}
func (s *ProfileEnvironmentStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidName(name) {
		return fmt.Errorf("invalid environment name")
	}
	if err := s.open(); err != nil {
		return err
	}
	return s.key.Delete(name)
}
func (s *ProfileEnvironmentStore) Notify() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.open(); err != nil {
		return err
	}
	return s.key.Notify()
}

// Close 先拒绝所有后续操作，再关闭子 key、释放本组件的 LoadUserProfile 引用、关闭 token。
// 子 key 关闭或 Unload 失败时保持永久停止态；下一次 Close 只重试尚未完成的清理。
// 正常 stop 保留已下发的环境，不能以停止服务为由删除其他用户/会话的 hive。
func (s *ProfileEnvironmentStore) Close() error {
	s.stopping.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closing = true
	if s.key != nil {
		if err := s.key.Close(); err != nil {
			return err
		}
		s.key = nil
	}
	if s.loaded {
		if err := s.backend.Unload(); err != nil {
			return err
		}
		s.loaded = false
	}
	if err := s.backend.Close(); err != nil {
		return err
	}
	s.closed = true
	return nil
}
