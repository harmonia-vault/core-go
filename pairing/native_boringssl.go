//go:build harmonia_boringssl && cgo && (darwin || linux)

package pairing

/*
#cgo CFLAGS: -I${SRCDIR}/native/include -DBORINGSSL_PREFIX=HARMONIA_BSSL
#cgo darwin,arm64,!ios LDFLAGS: ${SRCDIR}/native/darwin-arm64/libcrypto.a -lc++
#cgo darwin,amd64,!ios LDFLAGS: ${SRCDIR}/native/darwin-amd64/libcrypto.a -lc++
#cgo ios,arm64,!harmonia_ios_simulator LDFLAGS: ${SRCDIR}/native/ios-arm64/libcrypto.a -lc++
#cgo ios,arm64,harmonia_ios_simulator LDFLAGS: ${SRCDIR}/native/ios-simulator-arm64/libcrypto.a -lc++
#cgo ios,amd64 LDFLAGS: ${SRCDIR}/native/ios-simulator-amd64/libcrypto.a -lc++
#cgo linux,arm64,!android LDFLAGS: ${SRCDIR}/native/linux-arm64/libcrypto.a -lstdc++ -lpthread -ldl
#cgo linux,amd64,!android LDFLAGS: ${SRCDIR}/native/linux-amd64/libcrypto.a -lstdc++ -lpthread -ldl
#cgo android,arm64 LDFLAGS: ${SRCDIR}/native/android-arm64/libcrypto.a -lc++_static -lc++abi
#cgo android,amd64 LDFLAGS: ${SRCDIR}/native/android-amd64/libcrypto.a -lc++_static -lc++abi
#include <openssl/curve25519.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

type boringState struct{ ctx *C.SPAKE2_CTX }

func NativeAvailable() bool { return true }
func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func newNative(role string, myName, peerName, code []byte) (nativeState, []byte, error) {
	r := C.enum_spake2_role_t(C.spake2_role_alice)
	if role == "approver" {
		r = C.enum_spake2_role_t(C.spake2_role_bob)
	}
	ctx := C.SPAKE2_CTX_new(r, ptr(myName), C.size_t(len(myName)), ptr(peerName), C.size_t(len(peerName)))
	if ctx == nil {
		return nil, nil, errors.New("BoringSSL SPAKE2 上下文创建失败")
	}
	s := &boringState{ctx: ctx}
	out := make([]byte, 32)
	var n C.size_t
	if C.SPAKE2_generate_msg(ctx, ptr(out), &n, C.size_t(len(out)), ptr(code), C.size_t(len(code))) != 1 || int(n) != 32 {
		s.close()
		return nil, nil, errors.New("BoringSSL SPAKE2 消息生成失败")
	}
	return s, out, nil
}

func (s *boringState) finish(peer []byte) ([]byte, error) {
	if s.ctx == nil {
		return nil, ErrState
	}
	defer s.close()
	out := make([]byte, 64)
	var n C.size_t
	if C.SPAKE2_process_msg(s.ctx, ptr(out), &n, C.size_t(len(out)), ptr(peer), C.size_t(len(peer))) != 1 || int(n) != 64 {
		clear(out)
		return nil, errors.New("BoringSSL SPAKE2 对端消息处理失败")
	}
	return out, nil
}
func (s *boringState) close() {
	if s.ctx != nil {
		C.SPAKE2_CTX_free(s.ctx)
		s.ctx = nil
	}
}
