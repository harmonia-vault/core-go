package syncclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strconv"
	"sync"

	"github.com/harmonia-vault/core-go/cryptox"
)

// DAGJournalBinding 是已认证原生 owner 的范围，不是恢复或设备可信凭证。
type DAGJournalBinding struct {
	Endpoint, AccountID           string
	AccountGeneration, OwnerEpoch uint64
}

// DAGJournalStore 只由可信 Go/原生存储实现，不是 MethodChannel 输入。
// CAS 必须在同一 owner 锁内核绑定、AccountClosed/epoch、旧字节并同步原子保存。
// expected=nil 只表示槽不存在；不允许无条件覆盖，也不允许跨存储错误自动重试。
type DAGJournalStore interface {
	LoadDAGJournal(DAGJournalBinding) ([]byte, error)
	CompareAndSwapDAGJournal(DAGJournalBinding, []byte, []byte) error
}

var ErrDAGJournalConflict = errors.New("protected original DAG journal changed")

// CheckedDAGJournal 共用严格原包验证和单调状态规则；存储层负责原子 owner/CAS。
type CheckedDAGJournal struct {
	mu      sync.Mutex
	store   DAGJournalStore
	binding DAGJournalBinding
}

func validateDAGJournalBinding(b DAGJournalBinding) error {
	u, err := url.Parse(b.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !enrollmentID.MatchString(b.AccountID) || b.AccountGeneration == 0 {
		return cryptox.ErrInvalidWire
	}
	return nil
}
func NewCheckedDAGJournal(store DAGJournalStore, binding DAGJournalBinding) (*CheckedDAGJournal, error) {
	if store == nil || validateDAGJournalBinding(binding) != nil {
		return nil, cryptox.ErrInvalidWire
	}
	j := &CheckedDAGJournal{store: store, binding: binding}
	// 即使槽尚未建立，也须通过当前 owner 检查，不能复活关闭的账号。
	if err := j.OwnerAlive(); err != nil {
		return nil, err
	}
	return j, nil
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

// DecodeDAGJournal 是 native-only 原保护记录的严格解码；不提供签名或授权。
func DecodeDAGJournal(binding DAGJournalBinding, raw []byte) (ProtectedDAGOperation, error) {
	var p ProtectedDAGOperation
	var sealed struct {
		OwnerEpoch uint64                `json:"ownerEpoch"`
		Operation  ProtectedDAGOperation `json:"operation"`
	}
	if validateDAGJournalBinding(binding) != nil || len(raw) == 0 || len(raw) > cryptox.MaxRecoveryAuthorityBytes+4096 || strictJSONBytes(raw, &sealed) != nil || sealed.OwnerEpoch != binding.OwnerEpoch {
		return p, cryptox.ErrInvalidWire
	}
	p = sealed.Operation
	if p.Endpoint != binding.Endpoint || p.AccountID != binding.AccountID || p.AccountGeneration != binding.AccountGeneration {
		return ProtectedDAGOperation{}, cryptox.ErrInvalidWire
	}
	if err := validateProtectedDAGOperation(p); err != nil {
		return ProtectedDAGOperation{}, err
	}
	return p, nil
}
func (j *CheckedDAGJournal) Save(p ProtectedDAGOperation) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if p.Endpoint != j.binding.Endpoint || p.AccountID != j.binding.AccountID || p.AccountGeneration != j.binding.AccountGeneration {
		return cryptox.ErrInvalidWire
	}
	if err := validateProtectedDAGOperation(p); err != nil {
		return err
	}
	previous, err := j.store.LoadDAGJournal(j.binding)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	defer clear(previous)
	if errors.Is(err, os.ErrNotExist) {
		if len(previous) != 0 {
			return cryptox.ErrInvalidWire
		}
		previous = nil
	} else {
		old, err := DecodeDAGJournal(j.binding, previous)
		if err != nil {
			return err
		}
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
	}{j.binding.OwnerEpoch, p})
	if err != nil || len(raw) > cryptox.MaxRecoveryAuthorityBytes+4096 {
		return cryptox.ErrInvalidWire
	}
	defer clear(raw)
	// 两个 checked 对象也不能在 load/save 间覆盖彼此，CAS 由唯一存储 owner 执行。
	return j.store.CompareAndSwapDAGJournal(j.binding, previous, raw)
}
func (j *CheckedDAGJournal) Load() (ProtectedDAGOperation, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	raw, err := j.store.LoadDAGJournal(j.binding)
	if err != nil {
		clear(raw)
		return ProtectedDAGOperation{}, err
	}
	defer clear(raw)
	return DecodeDAGJournal(j.binding, raw)
}
func (j *CheckedDAGJournal) OwnerAlive() error {
	raw, err := j.store.LoadDAGJournal(j.binding)
	clear(raw)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// EqualDAGJournalBytes 保留 nil（不存在）与空记录（损坏）的区别。
func EqualDAGJournalBytes(a, b []byte) bool { return (a == nil) == (b == nil) && bytes.Equal(a, b) }
