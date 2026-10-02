package localipc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localstate"
)

func TestOperationQueueCancellationAndAlreadyExpiredContext(t *testing.T) {
	var gate operationGate
	must(t, gate.Lock(context.Background()))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- gate.Lock(ctx) }()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("排队截止未返回")
		}
	case <-time.After(time.Second):
		t.Fatal("过期排队仍在等待owner")
	}
	gate.Unlock()
	canceled, stop := context.WithCancel(context.Background())
	stop()
	for range 100 {
		if !errors.Is(gate.Lock(canceled), context.Canceled) {
			t.Fatal("已取消请求取得可用锁")
		}
	}
	must(t, gate.Lock(context.Background()))
	gate.Unlock()
}
func TestCanceledCommandsAndReconciliationCannotMutateState(t *testing.T) {
	engine, _, provider := fixture(t)
	server := &Server{config: Config{Engine: engine, Provider: provider, Now: func() time.Time { return syntheticNow }}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response := server.dispatch(ctx, Request{Version: Version, Command: "override-set", EnvironmentID: "one", Name: "TOKEN", Value: ptr("synthetic-canceled")})
	if response.OK || response.Code != "request_canceled" || len(engine.State().Overrides) != 0 {
		t.Fatal("已取消请求仍执行修改")
	}
	if !errors.Is(server.Reconcile(ctx, syntheticNow), context.Canceled) {
		t.Fatal("后台已取消时仍开始调和")
	}
	if provider.values["TOKEN"] != "original" {
		t.Fatal("取消操作改写provider")
	}
}

type cancelingFailedStore struct {
	localstate.Store
	cancel context.CancelFunc
}

func (s *cancelingFailedStore) Save(localstate.State) error {
	s.cancel()
	return errors.New("SYNTHETIC_SECRET_PERSISTENCE_FAILURE")
}
func TestInFlightCancellationDoesNotHidePersistenceFailure(t *testing.T) {
	source, store, provider := fixture(t)
	must(t, source.Activate("one", 0, syntheticNow))
	must(t, source.Reconcile(context.Background(), provider, syntheticNow))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine, err := localstate.New(&cancelingFailedStore{Store: store, cancel: cancel})
	must(t, err)
	server := &Server{config: Config{Engine: engine, Provider: provider, Now: func() time.Time { return syntheticNow }}}
	response := server.dispatch(ctx, Request{Version: Version, Command: "status"})
	if response.OK || response.Code != "provider_or_persistence_failed" || ctx.Err() == nil {
		t.Fatal("在途取消掩盖真实持久化错误")
	}
}
