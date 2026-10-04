package mobilebridge

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/accountreset"
)

func TestNativeAccountResetMailConsumesOnlyEmailAndNeverTrusts(t *testing.T) {
	calls := 0
	r := &NativeAccountResetMail{request: func(ctx context.Context, email string) error {
		calls++
		if email != "synthetic@example.invalid" {
			t.Fatal("邮箱输入不匹配合成范围")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("申请邮件缺少有界取消")
		}
		return nil
	}}
	defer r.Close()
	input := []byte("synthetic@example.invalid")
	out, e := r.RequestEmail(input)
	if e != nil || out != `{"version":1,"accepted":true,"trustedDevice":false}` || calls != 1 || !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("邮件申请泄露输入或伪造信任")
	}
	for _, invalid := range [][]byte{nil, []byte(strings.Repeat("x", 321)), {0xff}, []byte("synthetic\n@example.invalid"), []byte("synthetic\x00@example.invalid")} {
		if _, e = r.RequestEmail(invalid); e == nil || !bytes.Equal(invalid, make([]byte, len(invalid))) {
			t.Fatal("非法输入没有拒绝/消费")
		}
	}
	if calls != 1 {
		t.Fatal("非法邮件发出请求")
	}
}

func TestNativeAccountResetMailCloseCancelsAndRejectsLateAcceptance(t *testing.T) {
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r := &NativeAccountResetMail{request: func(ctx context.Context, _ string) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release // 合成 transport 故意在取消后晚到成功。
		return nil
	}}
	done := make(chan error, 1)
	go func() { _, e := r.RequestEmail([]byte("synthetic@example.invalid")); done <- e }()
	<-entered
	busy := []byte("synthetic-other@example.invalid")
	if _, e := r.RequestEmail(busy); !errors.Is(e, accountreset.ErrBusy) || !bytes.Equal(busy, make([]byte, len(busy))) {
		t.Fatal("并发申请未拒绝/消费")
	}
	r.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("Close 没有及时取消网络")
	}
	close(release)
	if e := <-done; !errors.Is(e, accountreset.ErrClosed) {
		t.Fatal("退休后晚到成功被接受")
	}
	if _, e := r.RequestEmail([]byte("synthetic@example.invalid")); !errors.Is(e, accountreset.ErrClosed) {
		t.Fatal("退休 owner 被重用")
	}
}

func TestNativeAccountResetMailInvalidNativeScopeNeverBuildsOwner(t *testing.T) {
	for _, item := range []struct {
		endpoint, namespace string
		ca                  []byte
	}{
		{"http://synthetic.invalid", "synthetic", nil},
		{"https://synthetic.invalid/", "synthetic", nil},
		{"https://synthetic.invalid", "", nil},
		{"https://synthetic.invalid", string([]byte{0xff}), nil},
		{"https://synthetic.invalid", "synthetic", []byte("SYNTHETIC_INVALID_CA")},
	} {
		if r, e := OpenNativeAccountResetMail(item.endpoint, item.namespace, item.ca); e == nil || r != nil {
			t.Fatal("非法平台 scope 创建了邮件 owner")
		}
	}
	var zero NativeAccountResetMail
	if _, e := zero.RequestEmail([]byte("synthetic@example.invalid")); e == nil {
		t.Fatal("空 owner 获得请求权限")
	}
}
