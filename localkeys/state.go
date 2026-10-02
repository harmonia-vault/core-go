package localkeys

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/harmonia-vault/core-go/localstate"
)

// StateStore 供未来可信 daemon 使用；它不读取或迁移现有明文 fixture 文件。
type StateStore struct{ vault *Vault }

func OpenEncryptedStateStore(c Config) (*StateStore, error) {
	v, err := Open(c)
	if err != nil {
		return nil, err
	}
	return &StateStore{vault: v}, nil
}
func (s *StateStore) Vault() *Vault { return s.vault }
func (s *StateStore) Close() error  { return s.vault.Close() }
func (s *StateStore) Load() (localstate.State, error) {
	s.vault.mu.Lock()
	defer s.vault.mu.Unlock()
	data, err := s.vault.loadLocked("state-v1")
	if errors.Is(err, os.ErrNotExist) {
		return localstate.EmptyState(), nil
	}
	if err != nil {
		return localstate.State{}, err
	}
	defer clear(data)
	var state localstate.State
	if err := strictJSON(data, &state); err != nil {
		return localstate.State{}, err
	}
	if state.Version != 1 {
		return localstate.State{}, ErrCorrupt
	}
	if state.Synthetic {
		return localstate.State{}, ErrFixture
	}
	if err := s.checkBindingLocked(state); err != nil {
		return localstate.State{}, err
	}
	return state, nil
}
func (s *StateStore) Save(state localstate.State) error {
	s.vault.mu.Lock()
	defer s.vault.mu.Unlock()
	if state.Synthetic {
		return ErrFixture
	}
	if state.Version != 1 {
		return ErrCorrupt
	}
	if err := s.checkBindingLocked(state); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer clear(data)
	return s.vault.saveLocked("state-v1", data)
}

// 有云数据的状态必须与同目录的已完成入网绑定一致；不能静默接管另一账号。
func (s *StateStore) checkBindingLocked(state localstate.State) error {
	if state.Cloud.AccountID == "" {
		return nil
	}
	trust, err := s.vault.loadTrustRecordLocked()
	if err != nil {
		return err
	}
	if !trust.Accepted || state.Cloud.AccountID != trust.AccountID || state.Cloud.AccountGeneration != trust.AccountGeneration {
		return ErrIdentity
	}
	return s.vault.trustBindingsLocked(trust)
}
