// Package localstate 将已验证云快照与本机选择进行收敛。
// 本包不提供网络或信任入网；调用 AcceptSnapshot 前必须完成认证、
// 签授权与检查点验证，并解密。
package localstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ErrReplay          = errors.New("cloud checkpoint moved backwards or changed at the same sequence")
	ErrAccount         = errors.New("account changed: logout and restore managed values first")
	ErrLocalSession    = errors.New("local account session changed")
	ErrDataPaused      = errors.New("ordinary cloud data is paused")
	ErrUnauthorized    = errors.New("environment is unavailable or its grant has expired")
	fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	namePattern        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

type Role string

const (
	ReadOnly  Role = "RO"
	ReadWrite Role = "RW"
	Admin     Role = "Admin"
)

// EnvironmentSource 固定最后一次完整数据读取的签授权及其指纹。
// AuthorizationPath 从该来源连续连接到当前授权，不改变数据版本或值。
// 密码学验证由固定设备根的 syncclient 完成，本包只检查事务不变量。
type EnvironmentSource struct {
	AuthorityHash     string   `json:"authorityHash"`
	Fingerprint       string   `json:"fingerprint"`
	AuthorizationPath []string `json:"authorizationPath"`
}

type Environment struct {
	ID              string             `json:"id"`
	KeyVersion      uint64             `json:"keyVersion"`
	GrantGeneration uint64             `json:"grantGeneration"`
	Role            Role               `json:"role"`
	ExpiresAt       *time.Time         `json:"expiresAt,omitempty"`
	Values          map[string]string  `json:"values"`
	Source          *EnvironmentSource `json:"source,omitempty"`
}

type MutationCheckpoint struct {
	Sequence    uint64 `json:"sequence"`
	Fingerprint string `json:"fingerprint"`
}

type CloudSnapshot struct {
	// IssuerEvidence 由上层固定根全量复验，与本快照同一受保护事务持久化。
	IssuerEvidence    json.RawMessage `json:"issuerEvidence,omitempty"`
	AccountID         string          `json:"accountId"`
	AccountGeneration uint64          `json:"accountGeneration"`
	// Sequence 与 SeenMutations 只由完整普通数据验证推进。
	Sequence uint64 `json:"sequence"`
	// 授权投影推进此序号及当前 grant 检查点，不改来源的数据 KV/GG。
	AuthorizationSequence  uint64                        `json:"authorizationSequence,omitempty"`
	EnvironmentCheckpoints map[string]MutationCheckpoint `json:"environmentCheckpoints,omitempty"`
	DeletedEnvironments    map[string]uint64             `json:"deletedEnvironments,omitempty"`
	Environments           map[string]Environment        `json:"environments"`
	// 以下两个 map 绑定当前授权；Environment.Source 绑定缓存数据来源。
	GrantCheckpoints  map[string]uint64             `json:"grantCheckpoints,omitempty"`
	GrantFingerprints map[string]string             `json:"grantFingerprints,omitempty"`
	SeenMutations     map[string]MutationCheckpoint `json:"seenMutations,omitempty"`
}

type Activation struct {
	EnvironmentID string `json:"environmentId"`
	Priority      int    `json:"priority"`
}
type Original struct {
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
}
type ManagedValue struct {
	Value         string `json:"value"`
	EnvironmentID string `json:"environmentId"`
}

type State struct {
	Version       int    `json:"version"`
	SessionEpoch  uint64 `json:"sessionEpoch,omitempty"`
	AccountClosed bool   `json:"accountClosed,omitempty"`
	// Synthetic 只由明确测试入口写入，网络客户端必须拒绝这种状态。
	// 它不能替代设备入网，也不能绕过信任建立。
	Synthetic  bool                         `json:"synthetic,omitempty"`
	Cloud      CloudSnapshot                `json:"cloud"`
	Active     []Activation                 `json:"active"`
	Overrides  map[string]map[string]string `json:"overrides"`
	Originals  map[string]Original          `json:"originals"`
	Managed    map[string]ManagedValue      `json:"managed"`
	SafetyKeys map[string]bool              `json:"safetyKeys"`
	Paused     bool                         `json:"paused"`
}

func EmptyState() State {
	return State{Version: 1, Cloud: CloudSnapshot{Environments: map[string]Environment{}}, Overrides: map[string]map[string]string{}, Originals: map[string]Original{}, Managed: map[string]ManagedValue{}, SafetyKeys: map[string]bool{}}
}

// Change 表示逐变量变更。Release 让 shell provider 恢复各 shell 的
// 原值；服务基线 Value 供文件与 Windows provider 使用。
type Change struct {
	Name    string
	Value   *string
	Release bool
}

// Snapshot 仅读取明确给出的变量，不能枚举用户环境。
// Apply 必须保留无关变量。原值在 Apply 前已持久化，因此部分写入错误
// 可以重试；收敛过程保持幂等。
type Provider interface {
	Snapshot(context.Context, []string) (map[string]string, error)
	Apply(context.Context, []Change) error
}

// PauseAwareProvider 让 shell fragment 停止普通纠正，同时保留撤销恢复动作。
type PauseAwareProvider interface {
	SetPaused(context.Context, bool) error
}

type Store interface {
	Load() (State, error)
	Save(State) error
}
type Engine struct {
	mu    sync.Mutex
	state State
	store Store
}

func New(store Store) (*Engine, error) {
	s, err := store.Load()
	if err != nil {
		return nil, err
	}
	if err = normalize(&s); err != nil {
		return nil, err
	}
	return &Engine{state: s, store: store}, nil
}
func normalize(s *State) error {
	if s.Version != 1 {
		return fmt.Errorf("unsupported state version %d", s.Version)
	}
	if s.Cloud.Environments == nil {
		s.Cloud.Environments = map[string]Environment{}
	}
	if s.Overrides == nil {
		s.Overrides = map[string]map[string]string{}
	}
	if s.Originals == nil {
		s.Originals = map[string]Original{}
	}
	if s.Managed == nil {
		s.Managed = map[string]ManagedValue{}
	}
	if s.SafetyKeys == nil {
		s.SafetyKeys = map[string]bool{}
	}
	for _, a := range s.Active {
		if a.EnvironmentID == "" {
			return errors.New("invalid empty activation")
		}
	}
	for k, o := range s.Originals {
		if err := validateValue(k, o.Value); err != nil {
			return err
		}
	}
	for k, m := range s.Managed {
		if err := validateValue(k, m.Value); err != nil {
			return err
		}
	}
	for _, values := range s.Overrides {
		for k, v := range values {
			if err := validateValue(k, v); err != nil {
				return err
			}
		}
	}
	for k := range s.SafetyKeys {
		if !namePattern.MatchString(k) {
			return errors.New("invalid safety key")
		}
	}
	if s.Cloud.AccountID != "" {
		return validateCloud(s.Cloud)
	}
	if s.Cloud.AccountGeneration != 0 || s.Cloud.Sequence != 0 || len(s.Cloud.Environments) > 0 {
		return errors.New("cloud state without account")
	}
	return nil
}
func clone(s State) State {
	b, _ := json.Marshal(s)
	var out State
	_ = json.Unmarshal(b, &out)
	return out
}
func (e *Engine) State() State { e.mu.Lock(); defer e.mu.Unlock(); return clone(e.state) }
func (e *Engine) transaction(fn func(*State) error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := clone(e.state)
	if err := fn(&s); err != nil {
		return err
	}
	if err := e.store.Save(s); err != nil {
		return err
	}
	e.state = s
	return nil
}
func validateValue(name, value string) error {
	if !namePattern.MatchString(name) || strings.HasPrefix(strings.ToUpper(name), "__HARMONIA_") {
		return fmt.Errorf("invalid portable environment name %q", name)
	}
	if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return fmt.Errorf("invalid environment value for %s", name)
	}
	return nil
}
func validateCloud(s CloudSnapshot) error {
	if len(s.IssuerEvidence) > 1<<20 || (len(s.IssuerEvidence) > 0 && !json.Valid(s.IssuerEvidence)) {
		return errors.New("invalid protected issuer evidence encoding")
	}
	if s.AccountID == "" || s.AccountGeneration == 0 {
		return errors.New("account and positive generation required")
	}
	for id, env := range s.Environments {
		if id == "" || id != env.ID || env.KeyVersion == 0 || env.GrantGeneration == 0 {
			return errors.New("invalid environment metadata")
		}
		if env.Role != ReadOnly && env.Role != ReadWrite && env.Role != Admin {
			return errors.New("invalid environment role")
		}
		if env.Source != nil {
			source := env.Source
			if len(s.IssuerEvidence) == 0 || !fingerprintPattern.MatchString(source.AuthorityHash) || !fingerprintPattern.MatchString(source.Fingerprint) || len(source.AuthorizationPath) == 0 || len(source.AuthorizationPath) > 512 || source.AuthorizationPath[0] != source.AuthorityHash {
				return errors.New("invalid cached source metadata")
			}
			seen := map[string]bool{}
			for _, h := range source.AuthorizationPath {
				if !fingerprintPattern.MatchString(h) || seen[h] {
					return errors.New("invalid cached source path")
				}
				seen[h] = true
			}
		}
		for k, v := range env.Values {
			if err := validateValue(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}
func allowed(env Environment, now time.Time) bool {
	return env.ExpiresAt == nil || now.Before(*env.ExpiresAt)
}
func markSafety(s *State, env Environment) {
	for key := range env.Values {
		s.SafetyKeys[key] = true
		if managed, ok := s.Managed[key]; ok && managed.EnvironmentID == env.ID {
			delete(s.Managed, key)
		}
	}
}
func expire(s *State, now time.Time) bool {
	changed := false
	for id, env := range s.Cloud.Environments {
		if !allowed(env, now) {
			markSafety(s, env)
			delete(s.Cloud.Environments, id)
			delete(s.Overrides, id)
			changed = true
		}
	}
	return changed
}

// AcceptSnapshot 只接受已经完整验证权限的明文快照。
// 更高账号代际使旧环境与 override 全部失效；相同检查点必须内容一致。
func (e *Engine) AcceptSnapshot(in CloudSnapshot, now time.Time) error {
	return e.acceptSnapshot(in, now, nil, false)
}

// AcceptSnapshotAtEpoch 防止退出账号后的在途旧响应重新填充本地权威缓存。
func (e *Engine) AcceptSnapshotAtEpoch(in CloudSnapshot, now time.Time, epoch uint64) error {
	return e.acceptSnapshot(in, now, &epoch, false)
}

// AcceptDataSnapshotAtEpoch 在同一状态事务检查暂停和账号epoch，避免已经在途的
// 普通响应在用户暂停后填入新数据。授权投影继续由独立接口处理。
func (e *Engine) AcceptDataSnapshotAtEpoch(in CloudSnapshot, now time.Time, epoch uint64) error {
	return e.acceptSnapshot(in, now, &epoch, true)
}
func (e *Engine) acceptSnapshot(in CloudSnapshot, now time.Time, epoch *uint64, requireUnpaused bool) error {
	if err := validateCloud(in); err != nil {
		return err
	}
	return e.transaction(func(s *State) error {
		if epoch != nil && s.SessionEpoch != *epoch {
			return ErrLocalSession
		}
		if requireUnpaused && s.Paused {
			return ErrDataPaused
		}
		old := s.Cloud
		if old.AccountID != "" && old.AccountID != in.AccountID {
			return ErrAccount
		}
		if in.AccountGeneration < old.AccountGeneration {
			return ErrReplay
		}
		if in.AccountGeneration == old.AccountGeneration {
			if in.Sequence < old.Sequence {
				return ErrReplay
			}
			if in.Sequence == old.Sequence {
				// 本地已删除到期缓存，而相同服务器快照可能仍带到期授权。
				// 先按本地到期规则归一化，再比较内容。
				check := clone(*s)
				check.Cloud = in
				check = clone(check)
				expire(&check, now)
				if old.AuthorizationSequence == 0 {
					old.AuthorizationSequence = old.Sequence
				}
				if check.Cloud.AuthorizationSequence == 0 {
					check.Cloud.AuthorizationSequence = check.Cloud.Sequence
				}
				a, _ := json.Marshal(old)
				b, _ := json.Marshal(check.Cloud)
				if string(a) != string(b) {
					return ErrReplay
				}
				return nil
			}
		}
		generationChanged := old.AccountID != "" && old.AccountGeneration != in.AccountGeneration
		for id, env := range old.Environments {
			next, ok := in.Environments[id]
			if generationChanged || !ok || !allowed(next, now) {
				markSafety(s, env)
			} else {
				for key := range env.Values {
					if _, exists := next.Values[key]; !exists {
						s.SafetyKeys[key] = true
						if managed, ok := s.Managed[key]; ok && managed.EnvironmentID == env.ID {
							delete(s.Managed, key)
						}
					}
				}
			}
		}
		if generationChanged {
			if s.SessionEpoch == ^uint64(0) {
				return ErrLocalSession
			}
			s.SessionEpoch++
			s.Overrides = map[string]map[string]string{}
			s.Active = nil
		}
		s.Cloud = in
		// 复制调用方 map，防止调用结束后的外部修改改变权威状态。
		s.Cloud = clone(*s).Cloud
		for id, overrides := range s.Overrides {
			env, ok := s.Cloud.Environments[id]
			if !ok {
				delete(s.Overrides, id)
				continue
			}
			for key := range overrides {
				if _, exists := env.Values[key]; !exists {
					delete(overrides, key)
				}
			}
			if len(overrides) == 0 {
				delete(s.Overrides, id)
			}
		}
		expire(s, now)
		return nil
	})
}
func (e *Engine) Activate(id string, priority int, now time.Time) error {
	return e.transaction(func(s *State) error {
		env, ok := s.Cloud.Environments[id]
		if !ok || !allowed(env, now) {
			return ErrUnauthorized
		}
		for i, a := range s.Active {
			if a.EnvironmentID == id {
				s.Active[i].Priority = priority
				return nil
			}
		}
		s.Active = append(s.Active, Activation{EnvironmentID: id, Priority: priority})
		return nil
	})
}
func (e *Engine) Deactivate(id string) error {
	return e.transaction(func(s *State) error {
		active := s.Active[:0]
		for _, a := range s.Active {
			if a.EnvironmentID != id {
				active = append(active, a)
			}
		}
		s.Active = active
		return nil
	})
}
func (e *Engine) SetOverride(id, key, value string, now time.Time) error {
	if err := validateValue(key, value); err != nil {
		return err
	}
	return e.transaction(func(s *State) error {
		env, ok := s.Cloud.Environments[id]
		if !ok || !allowed(env, now) {
			return ErrUnauthorized
		}
		if _, ok = env.Values[key]; !ok {
			return errors.New("override requires an existing authorized cloud variable")
		}
		if s.Overrides[id] == nil {
			s.Overrides[id] = map[string]string{}
		}
		s.Overrides[id][key] = value
		return nil
	})
}
func (e *Engine) RemoveOverride(id, key string) error {
	return e.transaction(func(s *State) error { delete(s.Overrides[id], key); return nil })
}
func (e *Engine) SetPaused(paused bool) error {
	return e.transaction(func(s *State) error { s.Paused = paused; return nil })
}
func desired(s State, now time.Time) map[string]ManagedValue {
	out := map[string]ManagedValue{}
	active := append([]Activation(nil), s.Active...)
	// 相同优先级采用激活顺序，后激活者覆盖；修改已有项优先级保留顺序。
	sort.SliceStable(active, func(i, j int) bool { return active[i].Priority < active[j].Priority })
	for _, a := range active {
		env, ok := s.Cloud.Environments[a.EnvironmentID]
		if !ok || !allowed(env, now) {
			continue
		}
		for k, v := range env.Values {
			if override, ok := s.Overrides[a.EnvironmentID][k]; ok {
				v = override
			}
			out[k] = ManagedValue{Value: v, EnvironmentID: a.EnvironmentID}
		}
	}
	return out
}

// Effective 先执行离线到期，再返回有效值副本。暂停时保留上次下发值，
// 已知撤销/到期影响的项则使用剩余合法来源；Reconcile 负责实际恢复。
func (e *Engine) Effective(now time.Time) (map[string]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := clone(e.state)
	if expire(&s, now) {
		if err := e.store.Save(s); err != nil {
			return nil, err
		}
		e.state = s
	}
	out := map[string]string{}
	if s.Paused {
		for k, v := range s.Managed {
			if !s.SafetyKeys[k] {
				out[k] = v.Value
			}
		}
		for k, v := range desired(s, now) {
			if s.SafetyKeys[k] {
				out[k] = v.Value
			}
		}
		return out, nil
	}
	for k, v := range desired(s, now) {
		out[k] = v.Value
	}
	return out, nil
}

// Reconcile 在 provider 写入前持久保存首次接管原值。
// 部分写入、崩溃或外部修改之后可以安全重复执行。
func (e *Engine) Reconcile(ctx context.Context, p Provider, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := clone(e.state)
	expiryChanged := expire(&s, now)
	want := desired(s, now)
	targets := map[string]bool{}
	if s.Paused {
		for k := range s.SafetyKeys {
			targets[k] = true
		}
	} else {
		for k := range want {
			targets[k] = true
		}
		for k := range s.Originals {
			targets[k] = true
		}
		for k := range s.Managed {
			targets[k] = true
		}
		for k := range s.SafetyKeys {
			targets[k] = true
		}
	}
	keys := make([]string, 0, len(targets))
	for k := range targets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// 即使 provider 暂时不可用，到期缓存清理也先持久化。
	if expiryChanged {
		if err := e.store.Save(s); err != nil {
			return err
		}
		e.state = clone(s)
	}
	if lifecycle, ok := p.(PauseAwareProvider); ok {
		if err := lifecycle.SetPaused(ctx, s.Paused); err != nil {
			return err
		}
	}
	if len(keys) == 0 {
		return nil
	}
	current, err := p.Snapshot(ctx, keys)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if _, ok := want[k]; ok {
			if _, recorded := s.Originals[k]; !recorded {
				v, present := current[k]
				s.Originals[k] = Original{Present: present, Value: v}
			}
		}
	}
	if err = e.store.Save(s); err != nil {
		return err
	}
	e.state = clone(s)
	patches := []Change{}
	for _, k := range keys {
		cur, present := current[k]
		if value, ok := want[k]; ok {
			if !present || cur != value.Value {
				v := value.Value
				patches = append(patches, Change{Name: k, Value: &v})
			}
		} else if original, tracked := s.Originals[k]; tracked {
			// 即使服务基线已经等于原值，也发送 release；
			// 每个 shell 有自己的首次接管记录。
			var v *string
			if original.Present {
				copy := original.Value
				v = &copy
			}
			patches = append(patches, Change{Name: k, Value: v, Release: true})
		} else if _, tracked := s.Managed[k]; tracked {
			return errors.New("managed key lacks its durable original")
		}
	}
	if err = p.Apply(ctx, patches); err != nil {
		return err
	}
	for _, k := range keys {
		if v, ok := want[k]; ok {
			s.Managed[k] = v
		} else {
			delete(s.Managed, k)
			delete(s.Originals, k)
		}
		delete(s.SafetyKeys, k)
	}
	if err = e.store.Save(s); err != nil {
		return err
	}
	e.state = s
	return nil
}

// Logout 立即删除云明文与 override。原值记录保留到 provider 恢复成功，
// 崩溃或 provider 错误之后仍能按变量重试清理。
func (e *Engine) Logout() error { return e.logout(nil) }

// LogoutAtEpoch 让当前网络会话的拒绝不能清理随后建立的新账号上下文。
func (e *Engine) LogoutAtEpoch(epoch uint64) error { return e.logout(&epoch) }
func (e *Engine) logout(epoch *uint64) error {
	return e.transaction(func(s *State) error {
		if epoch != nil && s.SessionEpoch != *epoch {
			return ErrLocalSession
		}
		if s.SessionEpoch == ^uint64(0) {
			return ErrLocalSession
		}
		s.SessionEpoch++
		s.AccountClosed = true
		s.Cloud = CloudSnapshot{Environments: map[string]Environment{}}
		s.Active = nil
		s.Overrides = map[string]map[string]string{}
		s.Managed = map[string]ManagedValue{}
		s.Paused = false
		return nil
	})
}

// InvalidateAuthorizationsAtEpoch 停用全部环境来源但保留仍可信的设备身份、
// 已见检查点和本机激活偏好。所有环境授权到期不等于账号退出或设备被撤销。
func (e *Engine) InvalidateAuthorizationsAtEpoch(epoch uint64) error {
	return e.transaction(func(s *State) error {
		if s.SessionEpoch != epoch || s.SessionEpoch == ^uint64(0) {
			return ErrLocalSession
		}
		s.SessionEpoch++
		for name := range s.Originals {
			s.SafetyKeys[name] = true
		}
		s.Cloud.Environments = map[string]Environment{}
		s.Overrides = map[string]map[string]string{}
		s.Managed = map[string]ManagedValue{}
		return nil
	})
}

// AcceptAuthorizationRefreshAtEpoch 只接受已验证的安全授权投影，不推进数据
// 序号，不添加环境或变量、不改变已有值。暂停刷新也可删失权来源并标记恢复。
func (e *Engine) AcceptAuthorizationRefreshAtEpoch(in CloudSnapshot, now time.Time, epoch uint64) error {
	if err := validateCloud(in); err != nil {
		return err
	}
	return e.transaction(func(s *State) error {
		old := s.Cloud
		if s.SessionEpoch != epoch {
			return ErrLocalSession
		}
		if old.AccountID != "" && (old.AccountID != in.AccountID || old.AccountGeneration != in.AccountGeneration) {
			return ErrAccount
		}
		if in.Sequence != old.Sequence || in.AuthorizationSequence < old.Sequence || in.AuthorizationSequence < old.AuthorizationSequence {
			return ErrReplay
		}
		if !sameStateJSON(old.SeenMutations, in.SeenMutations) {
			return ErrReplay
		}
		if in.AuthorizationSequence == maxSequence(old.Sequence, old.AuthorizationSequence) {
			check := clone(*s)
			check.Cloud = in
			check = clone(check)
			expire(&check, now)
			original := clone(*s)
			expire(&original, now)
			original.Cloud.AuthorizationSequence = maxSequence(old.Sequence, old.AuthorizationSequence)
			if !sameStateJSON(original.Cloud, check.Cloud) {
				return ErrReplay
			}
		}
		for id, next := range in.Environments {
			previous, exists := old.Environments[id]
			if !exists || previous.KeyVersion != next.KeyVersion {
				return ErrUnauthorized
			}
			if previous.Source != nil {
				if next.Source == nil || previous.GrantGeneration != next.GrantGeneration || previous.Source.AuthorityHash != next.Source.AuthorityHash || previous.Source.Fingerprint != next.Source.Fingerprint || len(next.Source.AuthorizationPath) < len(previous.Source.AuthorizationPath) {
					return ErrReplay
				}
				for i, h := range previous.Source.AuthorizationPath {
					if next.Source.AuthorizationPath[i] != h {
						return ErrReplay
					}
				}
			} else if next.Source != nil {
				if previous.GrantGeneration != next.GrantGeneration || len(next.Source.AuthorizationPath) < 1 || next.Source.Fingerprint != old.GrantFingerprints[id] || previous.GrantGeneration != old.GrantCheckpoints[id] {
					return ErrReplay
				}
			}
			for key, value := range next.Values {
				if previous.Values[key] != value {
					return ErrReplay
				}
				if _, exists := previous.Values[key]; !exists {
					return ErrReplay
				}
			}
			if roleRank(next.Role) > roleRank(previous.Role) || previous.ExpiresAt != nil && (next.ExpiresAt == nil || next.ExpiresAt.After(*previous.ExpiresAt)) {
				return ErrUnauthorized
			}
		}
		for id, previous := range old.Environments {
			next, exists := in.Environments[id]
			if !exists || !allowed(next, now) {
				markSafety(s, previous)
				delete(s.Overrides, id)
			} else {
				for key := range previous.Values {
					if _, exists := next.Values[key]; !exists {
						s.SafetyKeys[key] = true
						delete(s.Managed, key)
						delete(s.Overrides[id], key)
					}
				}
			}
		}
		s.Cloud = in
		s.Cloud = clone(*s).Cloud
		expire(s, now)
		return nil
	})
}
func roleRank(role Role) int {
	if role == Admin {
		return 3
	}
	if role == ReadWrite {
		return 2
	}
	return 1
}

// SelectImport 只返回人明确选择的候选变量；不扫描宿主，也不修改
// 云或本地权威状态。受信在线客户端须加密、签名、提交后再拉取。
func SelectImport(candidates map[string]string, selected []string) (map[string]string, error) {
	if len(selected) == 0 {
		return nil, errors.New("explicit selected names are required")
	}
	out := map[string]string{}
	for _, k := range selected {
		v, ok := candidates[k]
		if !ok {
			return nil, fmt.Errorf("selected variable %s is absent", k)
		}
		if err := validateValue(k, v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}

// EnableSyntheticFixtures 只能把状态永久标记为测试来源，不能取消该标记。
func (e *Engine) EnableSyntheticFixtures() error {
	return e.transaction(func(s *State) error { s.Synthetic = true; return nil })
}

// CompleteEnrollmentAtEpoch 仅供已完成真实配对且服务器确认完整双签收据的控制器。
// 不接收未签云快照，不可由IPC、pending或unknown状态调用。
func (e *Engine) CompleteEnrollmentAtEpoch(epoch uint64) error {
	return e.transaction(func(s *State) error {
		if s.SessionEpoch != epoch {
			return ErrLocalSession
		}
		if s.Cloud.AccountID != "" || len(s.Originals) != 0 || len(s.Managed) != 0 {
			return ErrAccount
		}
		s.AccountClosed = false
		return nil
	})
}

func sameStateJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
func maxSequence(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
