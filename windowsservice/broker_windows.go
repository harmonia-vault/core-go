//go:build windows

package windowsservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/harmonia-vault/core-go/platform"
	"golang.org/x/sys/windows"
)

const tokenHello = "harmonia/profile-token/v1"

func acquireUserToken(ctx context.Context, c Config) (windows.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	listener, e := nativeListener(c.TokenPipe(), c.TargetSID)
	if e != nil {
		return 0, ErrUnavailable
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	if e = runVerifiedTask(ctx, c); e != nil {
		return 0, e
	}
	conn, e := listener.Accept()
	if e != nil {
		return 0, ErrUnavailable
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	hello, e := readFrame(conn)
	if e != nil || string(hello) != tokenHello {
		return 0, ErrProtocol
	}
	var challenge [32]byte
	if _, e = rand.Read(challenge[:]); e != nil {
		return 0, e
	}
	if writeFrame(conn, challenge[:]) != nil {
		return 0, ErrUnavailable
	}
	reply, e := readFrame(conn)
	if e != nil || !bytes.Equal(reply, challenge[:]) {
		return 0, ErrIdentity
	}
	token, e := authenticatedClient(conn, c, c.TargetSID, true)
	if e != nil {
		return 0, e
	}
	if writeFrame(conn, []byte("accepted")) != nil {
		_ = token.Close()
		return 0, ErrUnavailable
	}
	return token, nil
}

// RunTokenHelper 只运行在 target SID 的 Batch/Session0 token，下发真实 handle 的能力由 OS impersonation 提供。
// 只发送协议 hello/challenge，不读取云账号或用户密码，不序列化 token。
func RunTokenHelper(ctx context.Context, configPath string) error {
	locked, e := LoadConfig(configPath)
	if e != nil {
		return e
	}
	defer locked.Close()
	c := locked.Config
	process := windows.GetCurrentProcessToken()
	if !tokenUser(process, c.TargetSID) || !batchToken(process, c) {
		return ErrIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, e := winio.DialPipeAccessImpLevel(ctx, c.TokenPipe(), pipeClientAccess, winio.PipeImpLevelImpersonation)
	if e != nil {
		return ErrUnavailable
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if nativeServerIdentity(conn, c) != nil {
		return ErrIdentity
	}
	if writeFrame(conn, []byte(tokenHello)) != nil {
		return ErrUnavailable
	}
	challenge, e := readFrame(conn)
	if e != nil || len(challenge) != 32 {
		return ErrProtocol
	}
	if writeFrame(conn, challenge) != nil {
		return ErrUnavailable
	}
	answer, e := readFrame(conn)
	if e != nil || string(answer) != "accepted" {
		return ErrUnavailable
	}
	return nil
}
func runBroker(ctx context.Context, locked *LockedConfig, ready func()) error {
	c := locked.Config
	if requireSYSTEM(c, true) != nil {
		return ErrIdentity
	}
	restore, e := enableOwnedPrivileges()
	if e != nil {
		return e
	}
	defer restore()
	token, e := acquireUserToken(ctx, c)
	if e != nil {
		return e
	}
	store, e := platform.NewWindowsProfileEnvironment(c.TargetSID, token)
	_ = token.Close()
	if e != nil {
		return e
	}
	if e = store.EnsureReady(); e != nil {
		if store.Close() != nil {
			return ErrCleanup
		}
		return e
	}
	listener, e := nativeListener(c.ProfilePipe(), c.SyncServiceSID)
	if e != nil {
		if store.Close() != nil {
			return ErrCleanup
		}
		return ErrUnavailable
	}
	server := rpcServer{store: store}
	return server.serve(ctx, listener, func(conn net.Conn) error { _, e := authenticatedClient(conn, c, c.SyncServiceSID, false); return e }, ready)
}
