package syncclient

import (
	"context"
	"errors"
	"reflect"
)

var ErrVerifiedPullCommitScope = errors.New("verified pull commit context mismatch")

type verifiedPullCommit struct {
	context context.Context
	apply   func(context.Context, Pull) error
}

// WithVerifiedPullCommit 返回独立Client副本，仅绑定本操作的同一个可比较context。
// 回调只在成熟验签与同epoch Engine原子接受成功后运行，不能注入未验证快照。
// 完整数据、显式授权刷新和迟到暂停投影均调用；普通Client默认nil行为不变。
// 回调必须只提交实际response和同Engine，不能发网络或改response；失败硬返回。
func (c *Client) WithVerifiedPullCommit(ctx context.Context, apply func(context.Context, Pull) error) (*Client, error) {
	if c == nil || c.verifiedCommit != nil || ctx == nil || !reflect.TypeOf(ctx).Comparable() || apply == nil || ctx.Err() != nil {
		return nil, ErrVerifiedPullCommitScope
	}
	out := *c
	out.verifiedCommit = &verifiedPullCommit{context: ctx, apply: apply}
	return &out, nil
}
func (c *Client) checkVerifiedCommitContext(ctx context.Context) error {
	if c.verifiedCommit == nil {
		return nil
	}
	if ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != c.verifiedCommit.context {
		return ErrVerifiedPullCommitScope
	}
	return ctx.Err()
}
func (c *Client) commitVerifiedPull(ctx context.Context, p Pull) error {
	if c.verifiedCommit == nil {
		return nil
	}
	if ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != c.verifiedCommit.context {
		return ErrVerifiedPullCommitScope
	}
	// Engine已接受后必须交给owner判断取消窗口的安全投影；不能在这里丢已验撤销。
	return c.verifiedCommit.apply(ctx, p)
}
