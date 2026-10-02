// Package pairing 使用固定 BoringSSL SPAKE2 profile 和标准密钥确认建立
// 实验性设备配对通道。默认构建关闭原生配对，不把账号登录当设备可信。
package pairing

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
)

const (
	Profile           = cryptox.EnrollmentPairingProfile
	BoringSSLCommit   = "fab96f87245d7c6b941515201843665122650b88"
	PurposeEnrollment = "enroll-device"
	MaxLifetime       = 2 * time.Minute
)

var (
	ErrUnavailable  = errors.New("原生 SPAKE2 尚未在本构建启用或完成平台验收")
	ErrContext      = errors.New("无效配对上下文")
	ErrExpired      = errors.New("配对挑战已过期")
	ErrState        = errors.New("配对步骤已消费或顺序不正确")
	ErrConfirmation = errors.New("配对密钥确认失败")
	ErrReflection   = errors.New("拒绝反射自身 SPAKE2 消息")
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// Context 冻结一次配对的账号、用途、挑战和两端精确身份。
// CLI 必须用自己生成的公钥，管理手机必须用自己的既有可信公钥构造它。
type Context struct {
	AccountID                   string `json:"accountId"`
	AccountGeneration           string `json:"accountGeneration"`
	Purpose                     string `json:"purpose"`
	SessionID                   string `json:"sessionId"`
	ChallengeNonce              string `json:"challengeNonce"`
	ExpiresAt                   string `json:"expiresAt"`
	InitiatorDeviceID           string `json:"initiatorDeviceId"`
	InitiatorSigningPublicKey   string `json:"initiatorSigningPublicKey"`
	InitiatorReceivingPublicKey string `json:"initiatorReceivingPublicKey"`
	ApproverDeviceID            string `json:"approverDeviceId"`
	ApproverSigningPublicKey    string `json:"approverSigningPublicKey"`
	ApproverReceivingPublicKey  string `json:"approverReceivingPublicKey"`
}

func positiveDecimal(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != s {
		return 0, ErrContext
	}
	return n, nil
}

func (c Context) validateStructure() error {
	for _, id := range []string{c.AccountID, c.SessionID, c.InitiatorDeviceID, c.ApproverDeviceID} {
		if !idPattern.MatchString(id) {
			return ErrContext
		}
	}
	if c.Purpose != PurposeEnrollment || c.InitiatorDeviceID == c.ApproverDeviceID {
		return ErrContext
	}
	if _, err := positiveDecimal(c.AccountGeneration); err != nil {
		return err
	}
	expires, err := positiveDecimal(c.ExpiresAt)
	if err != nil || expires > 253402300799 {
		return ErrContext
	}
	for _, key := range []string{c.InitiatorSigningPublicKey, c.InitiatorReceivingPublicKey, c.ApproverSigningPublicKey, c.ApproverReceivingPublicKey, c.ChallengeNonce} {
		if _, err := cryptox.DecodeBase64(key, 32, 32); err != nil {
			return ErrContext
		}
	}
	if c.InitiatorSigningPublicKey == c.InitiatorReceivingPublicKey || c.ApproverSigningPublicKey == c.ApproverReceivingPublicKey || c.InitiatorSigningPublicKey == c.ApproverSigningPublicKey {
		return ErrContext
	}
	return nil
}

func (c Context) ValidateAt(now time.Time) error {
	if err := c.validateStructure(); err != nil {
		return err
	}
	expires, _ := positiveDecimal(c.ExpiresAt)
	if now.Unix() < 0 || expires <= uint64(now.Unix()) {
		return ErrExpired
	}
	if expires-uint64(now.Unix()) > uint64(MaxLifetime/time.Second) {
		return ErrContext
	}
	return nil
}

func (c Context) CanonicalBytes() ([]byte, error) {
	if err := c.validateStructure(); err != nil {
		return nil, err
	}
	return json.Marshal([]string{"harmonia/pairing-context/v1", Profile, c.AccountID, c.AccountGeneration, c.Purpose, c.SessionID, c.ChallengeNonce, c.ExpiresAt, c.InitiatorDeviceID, c.InitiatorSigningPublicKey, c.InitiatorReceivingPublicKey, c.ApproverDeviceID, c.ApproverSigningPublicKey, c.ApproverReceivingPublicKey})
}

func (c Context) identity(role string) ([]byte, error) {
	b, err := c.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	return json.Marshal([]string{"harmonia/pairing-identity/v1", role, cryptox.EncodeBase64(b)})
}

// GenerateShortCode 创建无偏随机八位数字短码，只在本地显示和人工输入。
// 短码不属于任何可发送给服务器的 JSON 对象。
func GenerateShortCode() ([]byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("%08d", n.Int64())), nil
}

func validCode(code []byte) bool {
	if len(code) != 8 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// EnrollmentContext 复制公开字段供 HTTP 批准对象使用，不导出短码或会话钥。
func (c Context) EnrollmentContext() cryptox.EnrollmentContext {
	return cryptox.EnrollmentContext{
		AccountID: c.AccountID, AccountGeneration: c.AccountGeneration,
		Purpose: c.Purpose, SessionID: c.SessionID,
		ChallengeNonce: c.ChallengeNonce, ExpiresAt: c.ExpiresAt,
		InitiatorDeviceID:           c.InitiatorDeviceID,
		InitiatorSigningPublicKey:   c.InitiatorSigningPublicKey,
		InitiatorReceivingPublicKey: c.InitiatorReceivingPublicKey,
		ApproverDeviceID:            c.ApproverDeviceID,
		ApproverSigningPublicKey:    c.ApproverSigningPublicKey,
		ApproverReceivingPublicKey:  c.ApproverReceivingPublicKey,
	}
}
