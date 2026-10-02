package localipc

import (
	"context"
	"sync"
)

// operationGate 保持唯一串行 owner，排队取消无需辅助 goroutine 或无界队列。
// 零值可用；检查取锁后取消，避免同时就绪时意外执行已经过期的操作。
type operationGate struct {
	once  sync.Once
	token chan struct{}
}

func (g *operationGate) Lock(ctx context.Context) error {
	g.once.Do(func() { g.token = make(chan struct{}, 1); g.token <- struct{}{} })
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.token:
		if err := ctx.Err(); err != nil {
			g.Unlock()
			return err
		}
		return nil
	}
}
func (g *operationGate) Unlock() { g.token <- struct{}{} }
