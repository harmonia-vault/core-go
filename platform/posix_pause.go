package platform

import (
	"context"
	"encoding/json"
)

// SetPaused 暂停时每个 shell 仅在 key 的本地修订号改变时应用一次；已收到撤销仍恢复或切换来源。
func (p *POSIXProvider) SetPaused(ctx context.Context, paused bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state.Paused == paused {
		return nil
	}
	next := p.state
	next.Paused = paused
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := writePrivateFile(p.path+".state.json", append(data, '\n'), []byte(`{"marker":"`+stateMarker+`"`)); err != nil {
		return err
	}
	// 若 fragment 写入失败，保留旧内存 paused 状态；下一轮会再次尝试。
	if err := p.writeFragment(next); err != nil {
		return err
	}
	p.state = next
	return nil
}
