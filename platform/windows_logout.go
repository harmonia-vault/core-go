package platform

import (
	"context"
	"errors"
	"strings"
)

// ValidateTrackedKeys在离线退出前核对两份持久原值记录，缺失时不猜测恢复值。
func (p *WindowsProvider) ValidateTrackedKeys(keys []string) error {
	if err := p.PrepareOriginals(context.Background(), keys); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if uniqueWindowsNames(keys) != nil {
		return errors.New("invalid Windows restoration keys")
	}
	expected := map[string]bool{}
	for _, key := range keys {
		expected[strings.ToUpper(key)] = true
	}
	for key := range expected {
		if _, ok := p.originals[key]; !ok {
			return errors.New("Windows original metadata is missing; keep recovery material")
		}
	}
	for key := range p.originals {
		if !expected[key] {
			return errors.New("Windows original metadata lacks engine ownership; keep recovery material")
		}
	}
	return nil
}
func (p *WindowsProvider) Finalize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, original := range p.originals {
		if !original.Released {
			return errors.New("Windows restoration is incomplete; keep recovery material")
		}
	}
	if p.notifyPending {
		return errors.New("Windows restoration is incomplete; keep recovery material")
	}
	p.originals = map[string]registryOriginal{}
	return p.save()
}

func (p *WindowsProvider) PrepareOriginals(ctx context.Context, tracked []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if uniqueWindowsNames(tracked) != nil {
		return errors.New("invalid Windows original keys")
	}
	p.reconcileTracked = map[string]bool{}
	for _, name := range tracked {
		p.reconcileTracked[strings.ToUpper(name)] = true
	}
	changed := false
	for name, original := range p.originals {
		if original.Released && !p.reconcileTracked[name] {
			delete(p.originals, name)
			changed = true
		}
	}
	if changed {
		return p.save()
	}
	return nil
}
