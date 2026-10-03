package syncclient

import (
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localkeys"
	"net/url"
	"os"
	"strconv"
	"sync"
)

type VaultDAGJournal struct {
	mu                sync.Mutex
	vault             *localkeys.Vault
	endpoint, account string
	generation        uint64
	epoch             uint64
}

func NewVaultDAGJournal(vault *localkeys.Vault, endpoint, account string, generation uint64) (*VaultDAGJournal, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || vault == nil || !enrollmentID.MatchString(account) || generation == 0 {
		return nil, cryptox.ErrInvalidWire
	}
	epoch, err := vault.RecoveryDAGOwnerEpoch(account, generation)
	if err != nil {
		return nil, err
	}
	return &VaultDAGJournal{vault: vault, endpoint: endpoint, account: account, generation: generation, epoch: epoch}, nil
}
func validateProtectedDAGOperation(p ProtectedDAGOperation) error {
	if p.Version != 1 || !enrollmentID.MatchString(p.OperationID) || p.Pin.AccountID != p.AccountID || p.Pin.AccountGeneration != strconv.FormatUint(p.AccountGeneration, 10) {
		return cryptox.ErrInvalidWire
	}
	var hash, base string
	var err error
	var record cryptox.RecoveryDAGRecord
	var bundle cryptox.RecoveryDependencyBundle
	switch p.Kind {
	case "transition-v2":
		if p.Transition == nil || p.Recovered != nil {
			return cryptox.ErrInvalidWire
		}
		t := p.Transition
		raw, _ := json.Marshal(t)
		if _, err = cryptox.DecodeRecoveryTransitionCommandV2(raw); err != nil {
			return err
		}
		if t.Submission.Transition.OperationID != p.OperationID || t.Submission.Transition.AccountID != p.AccountID || t.Submission.Transition.AccountGeneration != p.Pin.AccountGeneration {
			return cryptox.ErrInvalidWire
		}
		hash, err = cryptox.RecoveryTransitionHashV2(t.Submission)
		base = t.Submission.Transition.ExpectedSequence
		bundle = t.DependencyBundle
		r := cryptox.AcceptedRecoveryTransitionV2{Submission: t.Submission}
		record = cryptox.RecoveryDAGRecord{Kind: p.Kind, TransitionV2: &r}
	case "recovered-v2":
		if p.Recovered == nil || p.Transition != nil {
			return cryptox.ErrInvalidWire
		}
		t := p.Recovered
		raw, _ := json.Marshal(t)
		if _, err = cryptox.DecodeRecoveredDeviceCommandV2(raw); err != nil {
			return err
		}
		if t.Submission.Enrollment.OperationID != p.OperationID || t.Submission.Enrollment.AccountID != p.AccountID || t.Submission.Enrollment.AccountGeneration != p.Pin.AccountGeneration {
			return cryptox.ErrInvalidWire
		}
		hash, err = cryptox.RecoveredDeviceReferenceHashV2(t.Submission)
		base = t.Submission.Enrollment.ExpectedSequence
		bundle = t.DependencyBundle
		r := cryptox.AcceptedRecoveredDeviceV2{Submission: t.Submission}
		record = cryptox.RecoveryDAGRecord{Kind: p.Kind, RecoveredV2: &r}
	default:
		return cryptox.ErrInvalidWire
	}
	if err != nil || hash != p.ContentHash {
		return cryptox.ErrInvalidWire
	}
	expected, err := parsePositive(base)
	if err != nil || expected >= 9007199254740991 || p.AcceptedSequence != 0 && p.AcceptedSequence != expected+1 || p.Applied && p.AcceptedSequence == 0 {
		return cryptox.ErrInvalidWire
	}
	if record.TransitionV2 != nil {
		record.TransitionV2.Sequence = expected + 1
	} else {
		record.RecoveredV2.Sequence = expected + 1
	}
	bundle.Records = append(bundle.Records, record)
	_, err = cryptox.VerifyRecoveryDependencyBundle(p.Pin, bundle)
	return err
}
func (j *VaultDAGJournal) Save(p ProtectedDAGOperation) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if p.Endpoint != j.endpoint || p.AccountID != j.account || p.AccountGeneration != j.generation {
		return cryptox.ErrInvalidWire
	}
	if err := validateProtectedDAGOperation(p); err != nil {
		return err
	}
	old, err := j.load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if old.Pin != p.Pin {
			return cryptox.ErrInvalidWire
		}
		if old.OperationID == p.OperationID {
			a, c := cloneDAGOperation(old), cloneDAGOperation(p)
			a.Attempted, c.Attempted = false, false
			a.AcceptedSequence, c.AcceptedSequence = 0, 0
			a.Applied, c.Applied = false, false
			if !sameJSON(a, c) || old.Attempted && !p.Attempted || old.AcceptedSequence != 0 && old.AcceptedSequence != p.AcceptedSequence || old.Applied && !p.Applied {
				return cryptox.ErrInvalidWire
			}
		} else if !old.Applied {
			return ErrDAGRecoveryState
		}
	}
	raw, err := json.Marshal(struct {
		OwnerEpoch uint64                `json:"ownerEpoch"`
		Operation  ProtectedDAGOperation `json:"operation"`
	}{j.epoch, p})
	if err != nil {
		return cryptox.ErrInvalidWire
	}
	defer clear(raw)
	if len(raw) > cryptox.MaxRecoveryAuthorityBytes+4096 {
		return cryptox.ErrInvalidWire
	}
	return j.vault.SaveRecoveryDAGJournal(j.account, j.generation, j.epoch, raw)
}
func (j *VaultDAGJournal) Load() (ProtectedDAGOperation, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.load()
}
func (j *VaultDAGJournal) load() (ProtectedDAGOperation, error) {
	var p ProtectedDAGOperation
	raw, err := j.vault.LoadRecoveryDAGJournal(j.account, j.generation, j.epoch)
	if err != nil {
		return p, err
	}
	defer clear(raw)
	var sealed struct {
		OwnerEpoch uint64                `json:"ownerEpoch"`
		Operation  ProtectedDAGOperation `json:"operation"`
	}
	if len(raw) > cryptox.MaxRecoveryAuthorityBytes+4096 || strictJSONBytes(raw, &sealed) != nil || sealed.OwnerEpoch != j.epoch {
		return p, cryptox.ErrInvalidWire
	}
	p = sealed.Operation
	if p.Endpoint != j.endpoint || p.AccountID != j.account || p.AccountGeneration != j.generation {
		return p, cryptox.ErrInvalidWire
	}
	return p, validateProtectedDAGOperation(p)
}

// 仅检查唯一原生owner仍存活；不读取或输出设备钥匙。
func (j *VaultDAGJournal) OwnerAlive() error {
	raw, err := j.vault.LoadRecoveryDAGJournal(j.account, j.generation, j.epoch)
	clear(raw)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
