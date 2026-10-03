package platform

import (
	"context"
	"errors"

	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
)

// SecurePOSIXLogoutProvider 仅读取既有元数据；不在加载或取消暂停时重放旧值。
// 它刻意不实现 PauseAwareProvider，实际 release 统一通过原有 Apply 写入。
type SecurePOSIXLogoutProvider struct{ provider *POSIXProvider }

func NewSecurePOSIXLogoutProvider(fragment string, vault *localkeys.Vault) (*SecurePOSIXLogoutProvider, error) {
	if vault == nil {
		return nil, errors.New("离线恢复必须绑定受保护Vault")
	}
	return newSecurePOSIXLogoutProvider(fragment, vault)
}
func newSecurePOSIXLogoutProvider(fragment string, vault securePOSIXVault) (*SecurePOSIXLogoutProvider, error) {
	p, err := loadSecurePOSIXProvider(fragment, vault, false)
	if err != nil {
		return nil, err
	}
	return &SecurePOSIXLogoutProvider{provider: p}, nil
}

// ValidateTrackedKeys 必须在任何 release 写入前执行；缺原值记录不能静默漏清。
func (p *SecurePOSIXLogoutProvider) ValidateTrackedKeys(keys []string) error {
	p.provider.mu.Lock()
	defer p.provider.mu.Unlock()
	tracked := make(map[string]bool, len(keys))
	for _, key := range keys {
		tracked[key] = true
	}
	for key := range p.provider.state.Desired {
		if !tracked[key] {
			return errors.New("托管配置缺少对应原值记录；保留材料")
		}
	}
	return nil
}
func (p *SecurePOSIXLogoutProvider) Snapshot(ctx context.Context, keys []string) (map[string]string, error) {
	return p.provider.Snapshot(ctx, keys)
}
func (p *SecurePOSIXLogoutProvider) Apply(ctx context.Context, changes []localstate.Change) error {
	p.provider.mu.Lock()
	p.provider.state.Paused = false
	p.provider.mu.Unlock()
	return p.provider.Apply(ctx, changes)
}

// Finalize 在 engine 最终持久保存后输出仅含 release 的幂等片段。
func (p *SecurePOSIXLogoutProvider) Finalize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.provider.mu.Lock()
	defer p.provider.mu.Unlock()
	if len(p.provider.state.Desired) != 0 {
		return errors.New("托管配置尚未全部恢复；保留材料")
	}
	p.provider.state.Paused = false
	if err := p.provider.saveState(p.provider.state); err != nil {
		return err
	}
	return p.provider.writeFragment(p.provider.state)
}
