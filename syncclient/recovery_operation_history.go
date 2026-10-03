package syncclient

import (
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
)

var ErrDAGClosedHistoryConflict = errors.New("accepted recovery history contradicts protected closed operation")

// DAGClosedOperationCheckpoint 只表达本机已保护的拒绝下界，不授予任何权限。
// 调用者必须先核账号/代际/原收据及完整来源图，不能从网络候选建立本机闭锁事实。
type DAGClosedOperationCheckpoint struct {
	OperationID string
	Sequence    uint64
}

// ValidateDAGClosedHistory 在成熟来源验证之后对完整 records 执行闭锁一致性检查。
// ID跨所有旧/新kind永久闭锁；同账号全局sequence不能同时标记closed和accepted。
func ValidateDAGClosedHistory(closed []DAGClosedOperationCheckpoint, records []cryptox.RecoveryDAGRecord) error {
	if len(closed) > 640 {
		return cryptox.ErrInvalidWire
	}
	if len(closed) == 0 {
		return nil
	}
	ids := map[string]bool{}
	sequences := map[uint64]bool{}
	for _, c := range closed {
		if !enrollmentID.MatchString(c.OperationID) || c.Sequence < 2 || c.Sequence > 9007199254740991 || ids[c.OperationID] || sequences[c.Sequence] {
			return cryptox.ErrInvalidWire
		}
		ids[c.OperationID], sequences[c.Sequence] = true, true
	}
	for _, row := range records {
		// Reference核对kind与唯一body，避免对不合法公开参数解引用nil。
		if _, e := row.Reference(); e != nil {
			return e
		}
		var id string
		var sequence uint64
		switch row.Kind {
		case "transition-v1":
			id, sequence = row.TransitionV1.Submission.Transition.OperationID, row.TransitionV1.Sequence
		case "transition-v2":
			id, sequence = row.TransitionV2.Submission.Transition.OperationID, row.TransitionV2.Sequence
		case "recovered-v1":
			id, sequence = row.RecoveredV1.Submission.Enrollment.OperationID, row.RecoveredV1.Sequence
		case "recovered-v2":
			id, sequence = row.RecoveredV2.Submission.Enrollment.OperationID, row.RecoveredV2.Sequence
		default:
			return cryptox.ErrInvalidWire
		}
		if ids[id] || sequences[sequence] {
			return ErrDAGClosedHistoryConflict
		}
	}
	return nil
}

// 开会话前复制拒绝约束；外部slice之后变化不能放松当前owner的下界。
func freezeDAGClosedHistoryConfig(c DAGRecoveryConfig) (DAGRecoveryConfig, error) {
	c.ClosedOperations = append([]DAGClosedOperationCheckpoint(nil), c.ClosedOperations...)
	if e := ValidateDAGClosedHistory(c.ClosedOperations, nil); e != nil {
		return DAGRecoveryConfig{}, e
	}
	if len(c.ClosedOperations) > 0 {
		if c.Pin == nil || c.PriorBundle == nil {
			return DAGRecoveryConfig{}, cryptox.ErrInvalidWire
		}
		for _, closed := range c.ClosedOperations {
			if closed.Sequence > c.MinimumSequence {
				return DAGRecoveryConfig{}, cryptox.ErrInvalidWire
			}
		}
	}
	return c, nil
}
