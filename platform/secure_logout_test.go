package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localstate"
)

// 此 spy 只验证 I/O 顺序，不作密码学或真实 Vault 通过证据。
type logoutIOTrace struct {
	dir    string
	record []byte
	events []string
	writes [][]byte
}

func (v *logoutIOTrace) Directory() string { return v.dir }
func (v *logoutIOTrace) Load(slot string) ([]byte, error) {
	v.events = append(v.events, "load:"+slot)
	return append([]byte(nil), v.record...), nil
}
func (v *logoutIOTrace) Save(slot string, b []byte) error {
	v.events = append(v.events, "save:"+slot)
	v.writes = append(v.writes, append([]byte(nil), b...))
	v.record = append([]byte(nil), b...)
	return nil
}
func (v *logoutIOTrace) WriteEnvironmentFragment(b []byte) error {
	v.events = append(v.events, "fragment")
	v.writes = append(v.writes, append([]byte(nil), b...))
	return nil
}

type logoutEngineStore struct{ state localstate.State }

func (s *logoutEngineStore) Load() (localstate.State, error)   { return s.state, nil }
func (s *logoutEngineStore) Save(state localstate.State) error { s.state = state; return nil }
func logoutTrace(t *testing.T) (*SecurePOSIXLogoutProvider, *logoutIOTrace) {
	t.Helper()
	v := &logoutIOTrace{dir: t.TempDir()}
	fragment := filepath.Join(v.dir, "environment.sh")
	old := securePOSIXState{Schema: securePOSIXSchema, FragmentPath: fragment, State: posixState{Marker: stateMarker, Desired: map[string]string{"VX": "synthetic-old-value"}, Released: map[string]bool{}, Revisions: map[string]uint64{"VX": 1}, Paused: true}}
	var e error
	v.record, e = json.Marshal(old)
	if e != nil {
		t.Fatal(e)
	}
	p, e := newSecurePOSIXLogoutProvider(fragment, v)
	if e != nil {
		t.Fatal(e)
	}
	return p, v
}
func TestClosedLogoutProviderEntireIOTraceNeverReappliesOldValue(t *testing.T) {
	p, v := logoutTrace(t)
	if len(v.events) != 1 || v.events[0] != "load:provider-v1" {
		t.Fatal("构造器已写入", v.events)
	}
	if _, ok := any(p).(localstate.PauseAwareProvider); ok {
		t.Fatal("离线包装不应有取消pause的旧值写入入口")
	}
	state := localstate.EmptyState()
	state.AccountClosed = true
	state.SessionEpoch = 3
	state.Originals["VX"] = localstate.Original{Present: true, Value: "synthetic-original"}
	s := &logoutEngineStore{state}
	engine, e := localstate.New(s)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.ValidateTrackedKeys([]string{"VX"}); e != nil {
		t.Fatal(e)
	}
	if e = engine.Reconcile(context.Background(), p, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = p.Finalize(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(v.writes) == 0 {
		t.Fatal("没有真实经过provider写入调用")
	}
	for _, b := range v.writes {
		if bytes.Contains(b, []byte("synthetic-old-value")) {
			t.Fatal("任何I/O阶段重写了旧值")
		}
	}
	first := append([]byte(nil), v.writes[len(v.writes)-1]...)
	if e = p.Finalize(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(first, v.writes[len(v.writes)-1]) {
		t.Fatal("最终release输出不幂等")
	}
	if s.state.SessionEpoch != 3 || len(s.state.Originals) != 0 {
		t.Fatal("关闭重试改变epoch或没有持久恢复")
	}
}
func TestLogoutProviderUntrackedDesiredStopsBeforeAnyWrite(t *testing.T) {
	p, v := logoutTrace(t)
	if e := p.ValidateTrackedKeys(nil); e == nil {
		t.Fatal("缺原值记录未拒绝")
	}
	if e := p.Finalize(context.Background()); e == nil {
		t.Fatal("未清Desired假报完成")
	}
	if len(v.writes) != 0 {
		t.Fatal("拒绝前已下发旧值")
	}
}
