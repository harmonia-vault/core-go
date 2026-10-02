package pairing

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"
)

type nativeState interface {
	finish([]byte) ([]byte, error)
	close()
}

type step uint8

const (
	started step = iota
	waitingConfirmation
	confirmed
	failed
	closed
)

// Session 不可序列化，短码和原生临时私钥不持久化，所有步骤单次消费。
// 取得配对通道钥之后仍须手机显式确认环境、角色和期限并签授权。
type Session struct {
	mu               sync.Mutex
	context          Context
	role             string
	state            step
	native           nativeState
	message          []byte
	peerConfirmation []byte
	channelKey       []byte
	transcriptHash   [32]byte
	clock            func() time.Time
}

func NewInitiator(c Context, shortCode []byte) (*Session, []byte, error) {
	return start(c, shortCode, "initiator", time.Now)
}
func NewApprover(c Context, shortCode []byte) (*Session, []byte, error) {
	return start(c, shortCode, "approver", time.Now)
}

func start(c Context, code []byte, role string, clock func() time.Time) (*Session, []byte, error) {
	if role != "initiator" && role != "approver" {
		return nil, nil, ErrContext
	}
	if err := c.ValidateAt(clock()); err != nil {
		return nil, nil, err
	}
	if !validCode(code) {
		return nil, nil, ErrContext
	}
	myName, err := c.identity(role)
	if err != nil {
		return nil, nil, err
	}
	peerRole := "approver"
	if role == "approver" {
		peerRole = "initiator"
	}
	peerName, err := c.identity(peerRole)
	if err != nil {
		return nil, nil, err
	}
	native, msg, err := newNative(role, myName, peerName, code)
	if err != nil {
		return nil, nil, err
	}
	if len(msg) != 32 {
		native.close()
		return nil, nil, ErrContext
	}
	s := &Session{context: c, role: role, state: started, native: native, message: append([]byte(nil), msg...), clock: clock}
	return s, append([]byte(nil), msg...), nil
}

func (s *Session) expireLocked() error {
	expires, _ := positiveDecimal(s.context.ExpiresAt)
	if s.clock().Unix() >= int64(expires) {
		s.failLocked()
		return ErrExpired
	}
	return nil
}

func (s *Session) failLocked() {
	if s.native != nil {
		s.native.close()
		s.native = nil
	}
	clear(s.peerConfirmation)
	clear(s.channelKey)
	s.peerConfirmation = nil
	s.channelKey = nil
	s.state = failed
}

// Complete 处理对方 SPAKE2 消息并返回本端 HMAC 确认；此时不暴露通道钥。
// 错误消息、错误短码或反射不会产生被确认的配对通道。
func (s *Session) Complete(peerMessage []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != started {
		return nil, ErrState
	}
	if err := s.expireLocked(); err != nil {
		return nil, err
	}
	if len(peerMessage) != 32 {
		s.failLocked()
		return nil, ErrContext
	}
	if subtle.ConstantTimeCompare(peerMessage, s.message) == 1 {
		s.failLocked()
		return nil, ErrReflection
	}
	raw, err := s.native.finish(peerMessage)
	s.native = nil
	if err != nil {
		s.failLocked()
		return nil, err
	}
	defer clear(raw)
	if len(raw) != 64 {
		s.failLocked()
		return nil, ErrContext
	}
	initiator, approver := s.message, peerMessage
	if s.role == "approver" {
		initiator, approver = peerMessage, s.message
	}
	local, peer, channel, err := confirmationMaterial(s.context, raw, initiator, approver)
	if err != nil {
		s.failLocked()
		return nil, err
	}
	if s.role == "approver" {
		local, peer = peer, local
	}
	hash, err := transcriptDigest(s.context, initiator, approver)
	if err != nil {
		clear(channel)
		s.failLocked()
		return nil, err
	}
	s.transcriptHash = hash
	s.channelKey = channel
	s.peerConfirmation = peer
	s.state = waitingConfirmation
	return local, nil
}

func (s *Session) VerifyPeerConfirmation(peerMAC []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != waitingConfirmation {
		return ErrState
	}
	if err := s.expireLocked(); err != nil {
		return err
	}
	if len(peerMAC) != 32 || !hmac.Equal(peerMAC, s.peerConfirmation) {
		s.failLocked()
		return ErrConfirmation
	}
	clear(s.peerConfirmation)
	s.peerConfirmation = nil
	s.state = confirmed
	return nil
}

func (s *Session) SessionKey() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != confirmed {
		return nil, ErrState
	}
	if err := s.expireLocked(); err != nil {
		return nil, err
	}
	return append([]byte(nil), s.channelKey...), nil
}

func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failLocked()
	clear(s.message)
	s.message = nil
	s.state = closed
}

// TranscriptHash 只在双向密钥确认完成且挑战未到期后提供给入网证书。
func (s *Session) TranscriptHash() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != confirmed {
		return "", ErrState
	}
	if err := s.expireLocked(); err != nil {
		return "", err
	}
	return hex.EncodeToString(s.transcriptHash[:]), nil
}
