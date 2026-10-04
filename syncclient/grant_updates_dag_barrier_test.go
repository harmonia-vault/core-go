package syncclient

import (
	"context"
	"errors"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
)

func TestGrantControlBarriersPreserveProducerAndZeroPOST(t *testing.T) {
	f := newManagementFixture(t)
	in := GrantUpdateIntent{ID: "synthetic-control-barrier", EnvironmentID: f.control.EnvironmentID, SubjectDeviceID: f.control.Subjects[0].DeviceID, Role: "rw"}
	rejected := errors.New("synthetic control persistence rejection")
	called := 0
	if tx, e := f.c.prepareGrantUpdate(context.Background(), in, f.key, func(control ManagementControl) error { called++; return rejected }); !errors.Is(e, rejected) || tx != nil || called != 1 || f.posts != 0 {
		t.Fatal("failed control barrier generated transaction or POST", e)
	}
	tx, e := f.c.prepareGrantUpdate(context.Background(), in, f.key, func(control ManagementControl) error {
		control.KeyVersion = "99"
		control.Subjects[0].CurrentGrant.Grant.Role = "none"
		return nil
	})
	check(t, e)
	if tx.ControlCheckpoint().KeyVersion != "1" || tx.record.Signed.Grant.Role != "rw" || tx.record.Signed.Grant.KeyVersion != "1" {
		t.Fatal("callback changed producer control")
	}
	postBarrier := 0
	if _, e = tx.submit(context.Background(), func() error { postBarrier++; return nil }, func(control ManagementControl) error { return rejected }); !errors.Is(e, rejected) || postBarrier != 0 || f.posts != 0 {
		t.Fatal("failed fresh control allowed POST barrier or POST", e)
	}
	if _, e = tx.submit(context.Background(), func() error { postBarrier++; return rejected }, func(control ManagementControl) error { control.Subjects = nil; control.KeyVersion = "99"; return nil }); !errors.Is(e, rejected) || postBarrier != 1 || f.posts != 0 {
		t.Fatal("Attempted barrier failed open", e)
	}
	// 新export本身明确DAG。不能由普通客户端带一个回调而打开P4入口。
	if _, e = f.c.PrepareDAGGrantUpdate(context.Background(), in, f.key, func(ManagementControl) error { return nil }); !errors.Is(e, cryptox.ErrInvalidWire) {
		t.Fatal("nonDAG used DAG producer", e)
	}
	if _, e = tx.SubmitDAGWithControlBarrier(context.Background(), func(ManagementControl) error { return nil }, func() error { return nil }); !errors.Is(e, cryptox.ErrInvalidWire) {
		t.Fatal("nonDAG used DAG submit", e)
	}
}
