// Package mobileworkflow 是原生系统认证之后调用的手机业务层。
// 不被当前 mobilebridge AAR 导出；其保护上下文只能在原生 AES 文件中密封，不能由 Dart 提供。
package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrNotTrusted = errors.New("mobile workflow has no confirmed trusted root")
var ErrUnsupported = errors.New("this mobile lifecycle is not connected")
var ErrPending = errors.New("server result uncertain; query the same initialization before retrying")
var ErrClosed = errors.New("native authenticated device is closed")
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Config 只供可信原生持钥代码或合成 Go 测试使用，禁止作为 MethodChannel 输入。
// ProtectedState 是原生 AES 验证解包后的完整上下文；不接受服务器或 Dart 提供的上下文。
type Config struct {
	Endpoint            string
	HTTPClient          *http.Client
	SigningKey          ed25519.PrivateKey
	ReceivingPrivateKey []byte
	ProtectedState      []byte
	Now                 func() time.Time
	SaveProtectedState  func([]byte) error
	// DAG 必须使用原生 whole-state 原子 CAS；旧 Save-only provider 不获得此能力。
	SaveProtectedStateCAS func(expectedSHA256 string, next []byte) error
	CheckProtectedState   func(expectedSHA256 string) error
}
type ViewEnvironment struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Role      localstate.Role   `json:"role"`
	Variables map[string]string `json:"variables"`
}
type View struct {
	Checkpoint   uint64            `json:"checkpoint"`
	Environments []ViewEnvironment `json:"environments"`
	DeviceID     string            `json:"deviceId"`
	Experimental bool              `json:"experimental"`
}
type Registration struct {
	AccountID            string `json:"accountId"`
	AccountGeneration    string `json:"accountGeneration"`
	VerificationRequired bool   `json:"verificationRequired"`
}
type EmailProof struct {
	AccountID         string `json:"accountId"`
	AccountGeneration string `json:"accountGeneration"`
	ChallengeID       string `json:"challengeId"`
	Token             string `json:"token"`
}
type Initialization struct {
	State          string   `json:"state"`
	ChallengeID    string   `json:"challengeId"`
	IdempotencyKey string   `json:"idempotencyKey"`
	Nonce          string   `json:"nonce"`
	ExpiresAt      int64    `json:"expiresAt"`
	ProposalHash   string   `json:"proposalHash"`
	SigningPayload []string `json:"signingPayload"`
	Sequence       *uint64  `json:"sequence"`
	Replayed       bool     `json:"replayed,omitempty"`
}
type labelState struct {
	Name       string `json:"name"`
	KeyVersion string `json:"keyVersion"`
	Sequence   uint64 `json:"sequence"`
}
type pendingInitialization struct {
	Login     syncclient.LoginResult         `json:"login"`
	Proposal  cryptox.InitializationProposal `json:"proposal"`
	Challenge *Initialization                `json:"challenge,omitempty"`
	Name      string                         `json:"name"`
}
type environmentRecord struct {
	OriginV2  *environmentOriginJournal       `json:"originV2,omitempty"`
	InputHash string                          `json:"inputHash"`
	Signed    cryptox.SignedEnvironmentChange `json:"signed"`
	Sequence  uint64                          `json:"sequence,omitempty"`
	Applied   bool                            `json:"applied"`
}
type protectedState struct {
	RecoveryDAGResolution           *recoveryDAGResolutionState   `json:"recoveryDAGResolution,omitempty"`
	DAGCASRequired                  bool                          `json:"dagCASRequired,omitempty"`
	RecoveredDAGDevice              *recoveredDAGDeviceRecord     `json:"recoveredDAGDevice,omitempty"`
	RecoveryDAGRecoveredPreparation *recoveryDAGPreparationState  `json:"recoveryDAGRecoveredPreparation,omitempty"`
	RecoveryDAGPreparation          *recoveryDAGPreparationState  `json:"recoveryDAGPreparation,omitempty"`
	RecoveryDAG                     *recoveryDAGState             `json:"recoveryDAG,omitempty"`
	PendingApprovalV4               *approvalRecordV4             `json:"pendingApprovalV4,omitempty"`
	RecoveredDevice                 *recoveredDeviceRecord        `json:"recoveredDevice,omitempty"`
	RecoveryAuthority               *recoveryAuthorityRecord      `json:"recoveryAuthority,omitempty"`
	Management                      *managementState              `json:"management,omitempty"`
	Version                         int                           `json:"version"`
	Endpoint                        string                        `json:"endpoint"`
	DeviceID                        string                        `json:"deviceId"`
	SigningPublicKey                string                        `json:"signingPublicKey"`
	ReceivingPublicKey              string                        `json:"receivingPublicKey"`
	AccountID                       string                        `json:"accountId"`
	AccountGeneration               string                        `json:"accountGeneration"`
	Root                            *cryptox.TrustRoot            `json:"root,omitempty"`
	Pending                         *pendingInitialization        `json:"pending,omitempty"`
	Cloud                           localstate.State              `json:"cloud"`
	Grants                          []cryptox.SignedGrantWire     `json:"grants"`
	Labels                          map[string]labelState         `json:"labels"`
	WriteJournal                    []byte                        `json:"writeJournal,omitempty"`
	EnvironmentWrites               map[string]*environmentRecord `json:"environmentWrites,omitempty"`
	InitialAuthorities              []cryptox.SignedGrantWire     `json:"initialAuthorities,omitempty"`
	PendingApproval                 *approvalRecord               `json:"pendingApproval,omitempty"`
	SelfRevocation                  []byte                        `json:"selfRevocation,omitempty"`
	Recovery                        *recoveryRecord               `json:"recovery,omitempty"`
	EnrollmentV3                    *mobileEnrollmentRecord       `json:"enrollmentV3,omitempty"`
	PendingApprovalV3               *approvalRecordV3             `json:"pendingApprovalV3,omitempty"`
}
type memoryStore struct{ state localstate.State }

func (s *memoryStore) Load() (localstate.State, error)   { return clone(s.state), nil }
func (s *memoryStore) Save(value localstate.State) error { s.state = clone(value); return nil }
func clone[T any](value T) T {
	b, _ := json.Marshal(value)
	var copy T
	_ = json.Unmarshal(b, &copy)
	return copy
}

type Workflow struct {
	dagDeviceCancel      context.CancelFunc
	requiresDAGCAS       bool
	dagOwnerCancel       context.CancelFunc
	dagQueryCancel       context.CancelFunc
	dagPersistenceFailed bool
	saveNativeCAS        func(string, []byte) error
	checkNativeState     func(string) error
	protectedSHA256      string
	recoverySession      *RecoverySession
	mu                   sync.Mutex
	signing              ed25519.PrivateKey
	receiving            []byte
	http                 *http.Client
	now                  func() time.Time
	state                protectedState
	store                *memoryStore
	engine               *localstate.Engine
	client               *syncclient.Client
	verifier             *syncclient.PinnedVerifier
	login                *syncclient.LoginResult
	closed               bool
	saveNative           func([]byte) error
	writer               *syncclient.Writer
}

func New(config Config) (*Workflow, error) {
	if config.SaveProtectedState == nil {
		return nil, errors.New("native encrypted state writer required")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || len(config.Endpoint) > 2048 || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.ForceQuery || endpoint.Opaque != "" || strings.ContainsAny(config.Endpoint, "\\\x00\r\n\t") {
		return nil, errors.New("mobile workflow requires a canonical HTTPS endpoint")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/")
	endpoint.RawPath = ""
	if len(config.SigningKey) != ed25519.PrivateKeySize || len(config.ReceivingPrivateKey) != 32 || !bytes.Equal(ed25519.NewKeyFromSeed(config.SigningKey.Seed()), config.SigningKey) {
		return nil, errors.New("native device keys invalid")
	}
	receive, err := ecdh.X25519().NewPrivateKey(config.ReceivingPrivateKey)
	if err != nil {
		return nil, errors.New("native receiving key invalid")
	}
	signing := config.SigningKey.Public().(ed25519.PublicKey)
	if bytes.Equal(signing, receive.PublicKey().Bytes()) {
		return nil, errors.New("device keys must be independent")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if config.HTTPClient != nil {
		*client = *config.HTTPClient
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	tr, ok := transport.(*http.Transport)
	if !ok {
		return nil, errors.New("native HTTPS transport cannot be inspected")
	}
	tr = tr.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	}
	if tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion != 0 && tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		return nil, errors.New("TLS verification cannot be weakened")
	}
	if tr.TLSClientConfig.MinVersion == 0 {
		tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	client.Transport = tr
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	id := sha256.Sum256(signing)
	state := protectedState{Version: 1, Endpoint: endpoint.String(), DeviceID: hex.EncodeToString(id[:]), SigningPublicKey: cryptox.EncodeBase64(signing), ReceivingPublicKey: cryptox.EncodeBase64(receive.PublicKey().Bytes()), Cloud: localstate.EmptyState(), Labels: map[string]labelState{}}
	if len(config.ProtectedState) > 0 {
		if len(config.ProtectedState) > 8<<20 {
			return nil, errors.New("protected mobile context too large")
		}
		decoded := protectedState{}
		if err = decode(config.ProtectedState, &decoded); err != nil {
			return nil, errors.New("protected mobile context invalid")
		}
		if decoded.Version != 1 || decoded.Endpoint != state.Endpoint || decoded.DeviceID != state.DeviceID || decoded.SigningPublicKey != state.SigningPublicKey || decoded.ReceivingPublicKey != state.ReceivingPublicKey || decoded.Cloud.Synthetic {
			return nil, errors.New("protected mobile context does not bind endpoint and device")
		}
		state = decoded
		if state.Root != nil && (state.Pending != nil || state.Cloud.AccountClosed) {
			return nil, errors.New("closed or pending context cannot claim confirmed root")
		}
		if state.Root == nil && state.Cloud.Cloud.AccountID != "" {
			return nil, errors.New("untrusted context contains a cloud account")
		}
		if len(state.EnvironmentWrites) > 32 {
			return nil, errors.New("protected environment request journal too large")
		}
		for id, record := range state.EnvironmentWrites {
			if record == nil || record.Signed.Change.IdempotencyKey != id || record.Signed.Change.AccountID != state.AccountID || record.Signed.Change.AccountGeneration != state.AccountGeneration || record.Signed.Change.DeviceID != state.DeviceID || len(record.InputHash) != 64 || cryptox.VerifyEnvironmentChange(record.Signed, signing) != nil {
				return nil, errors.New("protected environment request binding invalid")
			}
			if _, e := hex.DecodeString(record.InputHash); e != nil {
				return nil, errors.New("protected environment fingerprint invalid")
			}
			expected, _ := strconv.ParseUint(record.Signed.Change.ExpectedSequence, 10, 64)
			acceptedTail := expected + 1
			if record.Signed.Change.Operation == "rotate" {
				acceptedTail += uint64(len(record.Signed.Change.Mutations))
			}
			if record.Sequence > 9007199254740991 || record.Sequence != 0 && record.Sequence != acceptedTail || record.Applied && record.Sequence == 0 {
				return nil, errors.New("protected environment acceptance invalid")
			}
			if record.Applied {
				if err := syncclient.VerifyEnvironmentChangeCheckpoint(state.Cloud.Cloud, record.Signed, record.Sequence); err != nil {
					return nil, errors.New("protected applied environment lacks its exact transaction checkpoints")
				}
			}
		}
		if state.Root != nil {
			root := state.Root
			pub, e := cryptox.DecodeBase64(root.RecoverySigningPublicKey, 32, 32)
			if e != nil || (state.EnrollmentV3 == nil && state.RecoveredDevice == nil && state.RecoveredDAGDevice == nil && (root.RootDeviceID != state.DeviceID || root.RootSigningPublicKey != state.SigningPublicKey || root.RootReceivingPublicKey != state.ReceivingPublicKey)) || cryptox.VerifyTrustRoot(state.AccountID, state.AccountGeneration, *root, pub) != nil {
				return nil, errors.New("protected root binding invalid")
			}
		}
		if state.Cloud.Cloud.AccountID != "" && (state.Cloud.Cloud.AccountID != state.AccountID || strconv.FormatUint(state.Cloud.Cloud.AccountGeneration, 10) != state.AccountGeneration) {
			return nil, errors.New("protected checkpoint belongs to another account generation")
		}
		if state.Pending != nil {
			p := state.Pending
			if p.Login.AccountID != state.AccountID || p.Login.AccountGeneration != state.AccountGeneration || p.Proposal.Device.ID != state.DeviceID || p.Proposal.Device.SigningPublicKey != state.SigningPublicKey || p.Proposal.Device.ReceivingPublicKey != state.ReceivingPublicKey {
				return nil, errors.New("pending initialization device/account binding invalid")
			}
			if _, e := p.Proposal.Hash(state.AccountID, state.AccountGeneration); e != nil {
				return nil, errors.New("pending initialization proposal invalid")
			}
		}
	}
	if state.EnvironmentWrites == nil {
		state.EnvironmentWrites = map[string]*environmentRecord{}
	}
	if state.Labels == nil {
		state.Labels = map[string]labelState{}
	}
	store := &memoryStore{state: state.Cloud}
	engine, err := localstate.New(store)
	if err != nil {
		return nil, err
	}
	workflow := &Workflow{signing: bytes.Clone(config.SigningKey), receiving: bytes.Clone(config.ReceivingPrivateKey), http: client, now: now, state: state, store: store, engine: engine, saveNative: config.SaveProtectedState, saveNativeCAS: config.SaveProtectedStateCAS, checkNativeState: config.CheckProtectedState, protectedSHA256: protectedStateHash(config.ProtectedState)}
	workflow.requiresDAGCAS = state.RecoveryDAGResolution != nil || state.DAGCASRequired || state.RecoveryDAG != nil || state.RecoveryDAGPreparation != nil || state.RecoveryDAGRecoveredPreparation != nil || state.RecoveredDAGDevice != nil
	if err := workflow.validateRecoveredDAGDeviceLocked(); err != nil {
		workflow.Close()
		return nil, err
	}
	if err := workflow.validateDAGResolutionLocked(); err != nil {
		workflow.Close()
		return nil, err
	}
	if err := workflow.validateDAGStateLocked(); err != nil {
		workflow.Close()
		return nil, err
	}
	if len(state.SelfRevocation) > 0 {
		if _, err := workflow.restoreSelfRevocation(); err != nil {
			workflow.Close()
			return nil, err
		}
	}
	if err := workflow.validateRecoveryState(); err != nil {
		workflow.Close()
		return nil, err
	}
	if err := workflow.observeRecoveryClock(); err != nil {
		workflow.Close()
		return nil, err
	}
	if err := workflow.validateMobileEnrollment(); err != nil {
		workflow.Close()
		return nil, err
	}
	if err := workflow.observeEnrollmentClock(); err != nil {
		workflow.Close()
		return nil, err
	}
	if err := workflow.validateRecoveredDeviceRecord(); err != nil {
		workflow.Close()
		return nil, err
	}
	if err := workflow.validateOriginCache(); err != nil {
		workflow.Close()
		return nil, err
	}
	for _, record := range state.EnvironmentWrites {
		if err := workflow.validateEnvironmentOriginRecord(record); err != nil {
			workflow.Close()
			return nil, err
		}
	}
	if err := workflow.validateApprovalV4(state.PendingApprovalV4); err != nil {
		workflow.Close()
		return nil, err
	}
	if err := workflow.validateApprovalV3(state.PendingApprovalV3); err != nil {
		workflow.Close()
		return nil, err
	}
	if err := workflow.validateInitialAuthorities(); err != nil {
		workflow.Close()
		return nil, err
	}
	if err := workflow.validateApprovalRecord(state.PendingApproval); err != nil {
		workflow.Close()
		return nil, err
	}
	if err := workflow.validateManagementState(); err != nil {
		workflow.Close()
		return nil, err
	}
	return workflow, nil
}
func (w *Workflow) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dagDeviceCancel != nil {
		w.dagDeviceCancel()
	}
	if w.dagQueryCancel != nil {
		w.dagQueryCancel()
	}
	if w.dagOwnerCancel != nil {
		w.dagOwnerCancel()
	}
	w.recoverySession = nil // native registry independently owns this process resource
	if w.writer != nil {
		w.writer.Close()
		w.writer = nil
	}
	clear(w.signing)
	clear(w.receiving)
	w.signing = nil
	w.receiving = nil
	if w.verifier != nil {
		w.verifier.Close()
		w.verifier = nil
	}
	w.client = nil
	w.login = nil
	if r := w.state.EnrollmentV3; r != nil && r.Login != nil {
		r.Login.Token = ""
	}
	clear(w.state.SelfRevocation)
	if w.managementPending() {
		clear(w.state.Management.Pending.Packet)
	}
	w.clearRecovery()
	if w.http != nil {
		w.http.CloseIdleConnections()
		w.http = nil
	}
	w.state = protectedState{}
	w.store = nil
	w.engine = nil
	w.closed = true
}

// Logout 关闭此认证上下文；原生调用层仍须删除其保护钥匙和状态文件。
// 保存失败仍清进程钥并报错，不能假报退出已经持久完成。
func (w *Workflow) Logout() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	if err := w.engine.Logout(); err != nil {
		return err
	}
	return w.invalidateTrust()
}

func (w *Workflow) check() error {
	if err := w.checkWithoutManagement(); err != nil {
		return err
	}
	if w.managementPending() {
		return ErrManagementPending
	}
	return nil
}
func (w *Workflow) checkWithoutManagement() error {
	if w.dagPersistenceFailed {
		return ErrDAGPersistence
	}
	if w.state.RecoveryDAGResolution != nil || w.state.RecoveredDAGDevice != nil || w.state.RecoveryDAG != nil || w.state.RecoveryDAGPreparation != nil || w.state.RecoveryDAGRecoveredPreparation != nil {
		return ErrRecoveryRestricted
	}
	if w.closed {
		return ErrClosed
	}
	if len(w.state.SelfRevocation) > 0 {
		return ErrSelfRevocationPending
	}
	if w.state.Recovery != nil {
		return ErrRecoveryRestricted
	}
	if w.recoveredDevicePending() {
		return ErrRecoveryPending
	}
	if w.approvalV4Pending() {
		return ErrApprovalPending
	}
	if w.enrollmentPending() {
		return ErrMobileEnrollmentPending
	}
	if w.state.PendingApprovalV3 != nil && w.state.PendingApprovalV3.Sequence == 0 {
		return ErrApprovalPending
	}
	if w.state.PendingApproval != nil && w.state.PendingApproval.Sequence == 0 {
		return ErrApprovalPending
	}
	return nil
}

// ExportProtectedState 含明文业务缓存/待完成随机token，只能交原生 AES 密封；禁止交 Dart、日志、明文文件。
// 不包含软件私钥、密码、SHA256登录凭据、恢复种子或会话token；pending login token有明确独立例外。
func (w *Workflow) ExportProtectedState() ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return nil, err
	}
	w.state.Cloud = w.engine.State()
	return json.Marshal(w.state)
}
func credential(password string) (string, error) {
	if len(password) == 0 || len(password) > 16384 || !utf8.ValidString(password) {
		return "", errors.New("password input invalid")
	}
	hash := cryptox.PasswordCredential(password)
	defer clear(hash[:])
	return hex.EncodeToString(hash[:]), nil
}
func (w *Workflow) Register(ctx context.Context, email, password string) (Registration, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return Registration{}, err
	}
	if w.state.Root != nil || w.state.Pending != nil {
		return Registration{}, ErrNotTrusted
	}
	value, err := credential(password)
	if err != nil {
		return Registration{}, err
	}
	var result Registration
	err = w.request(ctx, "/v1/register", "", map[string]string{"email": email, "credential": value}, &result)
	return result, err
}
func (w *Workflow) VerifyEmail(ctx context.Context, p EmailProof) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return err
	}
	if !identifier.MatchString(p.AccountID) {
		return errors.New("proof account invalid")
	}
	var result struct {
		Verified bool `json:"verified"`
	}
	err := w.request(ctx, "/v1/accounts/"+p.AccountID+"/email-verification/complete", "", struct {
		AccountGeneration string `json:"accountGeneration"`
		ChallengeID       string `json:"challengeId"`
		Token             string `json:"token"`
	}{p.AccountGeneration, p.ChallengeID, p.Token}, &result)
	if err == nil && !result.Verified {
		return errors.New("email proof not confirmed")
	}
	return err
}
func (w *Workflow) Login(ctx context.Context, email, password string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return err
	}
	if w.state.Root != nil || w.state.Pending != nil || w.engine.State().AccountClosed {
		return errors.New("login cannot replace trusted, closed or pending context")
	}
	value, err := credential(password)
	if err != nil {
		return err
	}
	result, err := syncclient.Login(ctx, syncclient.LoginConfig{Endpoint: w.state.Endpoint, HTTPClient: w.http, Email: email, Credential: value, Now: w.now})
	if err != nil {
		return err
	}
	w.login = &result
	w.state.AccountID = result.AccountID
	w.state.AccountGeneration = result.AccountGeneration
	return nil
}
func randomID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return "env-" + hex.EncodeToString(b), err
}
func environmentName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || len([]rune(value)) > 120 || strings.ContainsRune(value, 0) {
		return "", errors.New("environment name invalid")
	}
	return value, nil
}
func (w *Workflow) BeginInitialization(ctx context.Context, name, idempotencyKey string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return "", err
	}
	if w.state.Root != nil || w.state.Pending != nil || w.login == nil || w.login.ExpiresAt <= w.now().Unix() {
		return "", ErrNotTrusted
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,58}$`).MatchString(idempotencyKey) {
		return "", errors.New("idempotency key invalid")
	}
	name, err := environmentName(name)
	if err != nil {
		return "", err
	}
	seed, err := cryptox.GenerateRecoverySeed()
	if err != nil {
		return "", err
	}
	defer clear(seed)
	recovery, err := cryptox.DeriveRecoveryKeys(seed, w.state.AccountID, w.state.AccountGeneration, "1")
	if err != nil {
		return "", err
	}
	defer clear(recovery.SigningPrivate)
	defer clear(recovery.ReceivingPrivate)
	envKey, err := cryptox.GenerateEnvironmentKey()
	if err != nil {
		return "", err
	}
	defer clear(envKey)
	envID, err := randomID()
	if err != nil {
		return "", err
	}
	grant, err := w.makeGrant(envID, "1", "1", "initial-"+idempotencyKey, envKey, "0")
	if err != nil {
		return "", err
	}
	envelope, err := cryptox.WrapEnvironmentKey(envKey, cryptox.EnvelopeContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: envID, KeyVersion: "1", RecipientType: "recovery", RecipientID: w.state.AccountID, RecipientGeneration: "1", RecipientPublicKey: cryptox.EncodeBase64(recovery.ReceivingPublic)})
	if err != nil {
		return "", err
	}
	root := cryptox.TrustRoot{RootDeviceID: w.state.DeviceID, RootSigningPublicKey: w.state.SigningPublicKey, RootReceivingPublicKey: w.state.ReceivingPublicKey, RecoveryGeneration: "1", RecoverySigningPublicKey: cryptox.EncodeBase64(recovery.SigningPublic), RecoveryReceivingPublicKey: cryptox.EncodeBase64(recovery.ReceivingPublic)}
	root, err = cryptox.SignTrustRoot(w.state.AccountID, w.state.AccountGeneration, root, recovery.SigningPrivate)
	if err != nil {
		return "", err
	}
	proposal := cryptox.InitializationProposal{IdempotencyKey: idempotencyKey, Device: cryptox.InitializationDevice{ID: w.state.DeviceID, SigningPublicKey: w.state.SigningPublicKey, ReceivingPublicKey: w.state.ReceivingPublicKey}, RecoveryGeneration: "1", RecoverySigningPublicKey: root.RecoverySigningPublicKey, RecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, TrustRootSignature: root.Signature, Environments: []cryptox.InitializationEnvironment{{EnvironmentID: envID, KeyVersion: "1", RecoveryEnvelope: cryptox.EncodeBase64(envelope), Grant: grant}}}
	w.state.Pending = &pendingInitialization{Login: *w.login, Proposal: proposal, Name: name}
	w.login = nil
	if err = w.persist(); err != nil {
		w.state.Pending = nil
		return "", err
	}
	code, err := cryptox.EncodeRecoveryCode(seed)
	if err != nil {
		return "", err
	}
	var challenge Initialization
	err = w.request(ctx, w.accountPath("/vault-initializations"), w.state.Pending.Login.Token, proposal, &challenge)
	if err != nil {
		return code, errors.Join(ErrPending, err)
	}
	if err = w.validateInitialization(challenge); err != nil {
		return code, err
	}
	w.state.Pending.Challenge = &challenge
	if err = w.persist(); err != nil {
		return code, errors.Join(ErrPending, err)
	}
	return code, nil
}
func (w *Workflow) validateInitialization(view Initialization) error {
	p := w.state.Pending
	if p == nil || view.IdempotencyKey != p.Proposal.IdempotencyKey || (view.State != "pending" && view.State != "complete") {
		return errors.New("initialization response binding invalid")
	}
	hash, err := p.Proposal.Hash(w.state.AccountID, w.state.AccountGeneration)
	if err != nil || hash != view.ProposalHash {
		return errors.New("initialization proposal hash changed")
	}
	proof, err := cryptox.NewInitializationProof(w.state.AccountID, w.state.AccountGeneration, p.Login.Token, view.ChallengeID, view.Nonce, strconv.FormatInt(view.ExpiresAt, 10), hash)
	if err != nil {
		return err
	}
	b, _ := proof.SigningBytes()
	var fields []string
	_ = json.Unmarshal(b, &fields)
	if !reflectStrings(fields, view.SigningPayload) || view.ExpiresAt > w.now().Add(5*time.Minute).Unix() || (view.State == "pending" && view.ExpiresAt <= w.now().Unix()) || (view.State == "complete" && (view.Sequence == nil || *view.Sequence == 0 || *view.Sequence > 9007199254740991)) {
		return errors.New("initialization challenge account/session/expiry invalid")
	}
	return nil
}
func reflectStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (w *Workflow) QueryInitialization(ctx context.Context) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return "", err
	}
	if w.state.Pending == nil {
		return "", ErrNotTrusted
	}
	p := w.state.Pending
	var view Initialization
	err := w.request(ctx, w.accountPath("/vault-initializations/"+p.Proposal.IdempotencyKey), p.Login.Token, nil, &view)
	if err != nil {
		return "", err
	}
	if view.State == "absent" {
		if view.IdempotencyKey != p.Proposal.IdempotencyKey {
			return "", errors.New("absent initialization id changed")
		}
		return "absent", nil
	}
	if err = w.validateInitialization(view); err != nil {
		return "", err
	}
	p.Challenge = &view
	if err = w.persist(); err != nil {
		return "", err
	}
	return view.State, nil
}
func (w *Workflow) CompleteInitialization(ctx context.Context, completeCodeReentry string) (View, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return View{}, err
	}
	p := w.state.Pending
	if p == nil {
		return View{}, ErrNotTrusted
	}
	seed, err := cryptox.DecodeRecoveryCode(completeCodeReentry)
	if err != nil {
		return View{}, err
	}
	defer clear(seed)
	recovery, err := cryptox.DeriveRecoveryKeys(seed, w.state.AccountID, w.state.AccountGeneration, "1")
	if err != nil {
		return View{}, err
	}
	defer clear(recovery.SigningPrivate)
	defer clear(recovery.ReceivingPrivate)
	if cryptox.EncodeBase64(recovery.SigningPublic) != p.Proposal.RecoverySigningPublicKey || cryptox.EncodeBase64(recovery.ReceivingPublic) != p.Proposal.RecoveryReceivingPublicKey {
		return View{}, errors.New("reentered complete code does not match pending recovery keys")
	}
	// 每次先查询，处理上一次HTTP结果不明；若从未被接受则以原proposal重试，不另造key或id。
	var view Initialization
	err = w.request(ctx, w.accountPath("/vault-initializations/"+p.Proposal.IdempotencyKey), p.Login.Token, nil, &view)
	if err != nil {
		return View{}, errors.Join(ErrPending, err)
	}
	if view.State == "absent" {
		if view.IdempotencyKey != p.Proposal.IdempotencyKey {
			return View{}, errors.New("absent initialization id changed")
		}
		err = w.request(ctx, w.accountPath("/vault-initializations"), p.Login.Token, p.Proposal, &view)
		if err != nil {
			return View{}, errors.Join(ErrPending, err)
		}
	}
	if err = w.validateInitialization(view); err != nil {
		return View{}, err
	}
	if view.State == "pending" {
		proof, err := cryptox.NewInitializationProof(w.state.AccountID, w.state.AccountGeneration, p.Login.Token, view.ChallengeID, view.Nonce, strconv.FormatInt(view.ExpiresAt, 10), view.ProposalHash)
		if err != nil {
			return View{}, err
		}
		deviceSignature, err := cryptox.SignInitializationProof(proof, w.signing)
		if err != nil {
			return View{}, err
		}
		recoverySignature, err := cryptox.SignInitializationProof(proof, recovery.SigningPrivate)
		if err != nil {
			return View{}, err
		}
		err = w.request(ctx, w.accountPath("/vault-initializations/"+p.Proposal.IdempotencyKey+"/complete"), p.Login.Token, map[string]string{"challengeId": view.ChallengeID, "deviceSignature": deviceSignature, "recoverySignature": recoverySignature}, &view)
		if err != nil {
			return View{}, errors.Join(ErrPending, err)
		}
	}
	if err = w.validateInitialization(view); err != nil || view.State != "complete" {
		return View{}, errors.Join(ErrPending, err)
	}
	root := cryptox.TrustRoot{RootDeviceID: p.Proposal.Device.ID, RootSigningPublicKey: p.Proposal.Device.SigningPublicKey, RootReceivingPublicKey: p.Proposal.Device.ReceivingPublicKey, RecoveryGeneration: "1", RecoverySigningPublicKey: p.Proposal.RecoverySigningPublicKey, RecoveryReceivingPublicKey: p.Proposal.RecoveryReceivingPublicKey, Signature: p.Proposal.TrustRootSignature}
	if err = cryptox.VerifyTrustRoot(w.state.AccountID, w.state.AccountGeneration, root, recovery.SigningPublic); err != nil {
		return View{}, err
	}
	id, name := p.Proposal.Environments[0].EnvironmentID, p.Name
	w.state.Root = &root
	previousAuthorities := w.state.InitialAuthorities
	w.state.InitialAuthorities = nil
	for _, env := range p.Proposal.Environments {
		w.state.InitialAuthorities = append(w.state.InitialAuthorities, env.Grant)
	}
	w.state.Pending = nil
	if err = w.persist(); err != nil {
		w.state.Root = nil
		w.state.InitialAuthorities = previousAuthorities
		w.state.Pending = p
		return View{}, errors.Join(ErrPending, err)
	}
	if err = w.refresh(ctx); err != nil {
		return View{}, errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	if err = w.rename(ctx, id, name, "name-"+p.Proposal.IdempotencyKey); err != nil {
		return View{}, errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	return w.view(), nil
}
func (w *Workflow) accountPath(suffix string) string {
	return "/v1/accounts/" + w.state.AccountID + suffix
}

var errMobileResponseMalformed = errors.New("mobile HTTPS response malformed")

func (w *Workflow) request(ctx context.Context, path, token string, body any, out any) error {
	endpoint, err := url.Parse(w.state.Endpoint)
	if err != nil {
		return err
	}
	requestPath, err := url.ParseRequestURI(path)
	if err != nil || requestPath.Scheme != "" || requestPath.Host != "" || requestPath.Fragment != "" || !strings.HasPrefix(requestPath.Path, "/") {
		return errors.New("mobile HTTPS request path invalid")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + requestPath.Path
	endpoint.RawPath = ""
	endpoint.RawQuery = requestPath.RawQuery
	method := "GET"
	var reader io.Reader
	var encoded []byte
	if body != nil {
		method = "POST"
		encoded, err = json.Marshal(body)
		if err != nil {
			return err
		}
		defer clear(encoded)
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return errors.New("could not create mobile HTTPS request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Harmonia-Account-Generation", w.state.AccountGeneration)
		req.Header.Set("X-Harmonia-Device-Id", w.state.DeviceID)
	}
	response, err := w.http.Do(req)
	if err != nil {
		return errors.New("mobile HTTPS request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil {
		return errors.New("mobile HTTPS response read failed")
	}
	if len(data) > 8<<20 {
		return errors.Join(errMobileResponseMalformed, errors.New("mobile HTTPS response exceeds limit"))
	}
	defer clear(data)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var wire struct {
			Error string `json:"error"`
		}
		code := "request_rejected"
		if len(data) <= 4096 && decode(data, &wire) == nil {
			code = wire.Error
		}
		return syncclient.NewRequestError(response.StatusCode, code)
	}
	if err := decode(data, out); err != nil {
		return errors.Join(errMobileResponseMalformed, err)
	}
	return nil
}
func decode(data []byte, out any) error {
	if !utf8.Valid(data) {
		return errors.New("JSON UTF8 invalid")
	}
	check := json.NewDecoder(bytes.NewReader(data))
	check.UseNumber()
	if err := uniqueJSON(check, 0); err != nil {
		return err
	}
	if _, err := check.Token(); err != io.EOF {
		return errors.New("unexpected JSON content")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("unexpected JSON content")
	}
	return nil
}
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON depth exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			token, err := d.Token()
			name, ok := token.(string)
			if err != nil || !ok || seen[name] {
				return errors.New("duplicate or invalid JSON field")
			}
			seen[name] = true
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for d.More() {
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
func (w *Workflow) boot(ctx context.Context) error {
	if w.state.Root == nil {
		return ErrNotTrusted
	}
	generation, err := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if err != nil || generation == 0 {
		return ErrNotTrusted
	}
	verifier, err := w.originVerifier()
	if err != nil {
		return err
	}
	candidate, err := syncclient.NewForBoot(syncclient.Config{Endpoint: w.state.Endpoint, HTTPClient: w.http, AccountID: w.state.AccountID, AccountGeneration: generation, DeviceID: w.state.DeviceID, Engine: w.engine, Verifier: verifier, Now: w.now})
	if err != nil {
		verifier.Close()
		return err
	}
	if w.verifier != nil {
		w.verifier.Close()
	}
	w.verifier = verifier
	w.client, err = candidate.BootDevice(ctx, w.signing)
	if errors.Is(err, syncclient.ErrTrustInvalidated) {
		return errors.Join(err, w.invalidateTrust())
	}
	return err
}

// 网络客户端已经在同epoch清Cloud并置AccountClosed，手机再清原生持久信任资料与进程中的钥。
func (w *Workflow) invalidateTrust() error {
	if w.dagDeviceCancel != nil {
		w.dagDeviceCancel()
	}
	if w.dagQueryCancel != nil {
		w.dagQueryCancel()
	}
	if w.dagOwnerCancel != nil {
		w.dagOwnerCancel()
	}
	w.state.RecoveredDAGDevice = nil
	if r := w.state.RecoveryDAGResolution; r != nil {
		r.Pending = nil
		r.OwnerEpoch = w.engine.State().SessionEpoch
	}
	w.state.RecoveryDAG = nil
	w.state.RecoveryDAGPreparation = nil
	w.state.RecoveryDAGRecoveredPreparation = nil
	if w.managementPending() {
		clear(w.state.Management.Pending.Packet)
	}
	w.state.Management = nil
	w.state.Root = nil
	w.state.Pending = nil
	w.state.InitialAuthorities = nil
	w.state.PendingApproval = nil
	w.state.PendingApprovalV3 = nil
	w.state.PendingApprovalV4 = nil
	if r := w.state.EnrollmentV3; r != nil && r.Login != nil {
		r.Login.Token = ""
	}
	w.state.EnrollmentV3 = nil
	w.state.RecoveredDevice = nil
	clear(w.state.SelfRevocation)
	w.clearRecovery()
	w.state.SelfRevocation = nil
	w.state.Grants = nil
	w.state.Labels = map[string]labelState{}
	w.state.WriteJournal = nil
	w.state.EnvironmentWrites = map[string]*environmentRecord{}
	if w.writer != nil {
		w.writer.Close()
		w.writer = nil
	}
	err := w.persist()
	clear(w.signing)
	clear(w.receiving)
	w.signing = nil
	w.receiving = nil
	if w.verifier != nil {
		w.verifier.Close()
		w.verifier = nil
	}
	w.client = nil
	w.login = nil
	w.closed = true
	return err
}
func (w *Workflow) refresh(ctx context.Context) error {
	if w.managementPending() {
		return ErrManagementPending
	}
	if w.state.Recovery != nil {
		return ErrRecoveryRestricted
	}
	if w.recoveredDevicePending() {
		return ErrRecoveryPending
	}
	if w.approvalV4Pending() {
		return ErrApprovalPending
	}
	if w.enrollmentPending() {
		return ErrMobileEnrollmentPending
	}
	if w.state.PendingApprovalV3 != nil && w.state.PendingApprovalV3.Sequence == 0 {
		return ErrApprovalPending
	}
	if w.state.PendingApproval != nil && w.state.PendingApproval.Sequence == 0 {
		return ErrApprovalPending
	}
	return w.refreshForApproval(ctx)
}
func (w *Workflow) refreshForApproval(ctx context.Context) error {
	if w.state.Root == nil {
		return ErrNotTrusted
	}
	if w.client == nil {
		if err := w.boot(ctx); err != nil {
			return err
		}
	}
	pulled, err := w.client.Pull(ctx)
	var fault *syncclient.RequestError
	if errors.As(err, &fault) && fault.Status == 401 && fault.Code == "unauthorized" {
		if err = w.boot(ctx); err == nil {
			pulled, err = w.client.Pull(ctx)
		}
	}
	if err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			return errors.Join(err, w.invalidateTrust())
		}
		return err
	}
	w.state.Grants = nil
	for _, g := range pulled.Grants {
		w.state.Grants = append(w.state.Grants, cryptox.SignedGrantWire{Grant: g.Grant, Signature: g.Signature})
	}
	for _, event := range pulled.EnvironmentEvents {
		if err := w.rememberLabel(event.Change.Change, event.Sequence); err != nil {
			return err
		}
	}
	// Submit/Writer 内部已消费过的本机事件由已验的精确checkpoint补齐标签，不能只靠第二次pull的事件列表。
	for _, record := range w.state.EnvironmentWrites {
		c := record.Signed.Change
		seen, ok := w.engine.State().Cloud.EnvironmentCheckpoints[c.DeviceID+"/"+c.IdempotencyKey]
		if !ok {
			continue
		}
		tail := seen.Sequence + uint64(len(c.Mutations))
		if err := syncclient.VerifyEnvironmentChangeCheckpoint(w.engine.State().Cloud, record.Signed, tail); err != nil {
			continue
		}
		record.Sequence = tail
		record.Applied = true
		if err := w.rememberLabel(c, seen.Sequence); err != nil {
			return err
		}
	}
	return w.persist()
}

// 只在同一签名请求已由 Client.Pull 验证并写入精确检查点后调用。
func (w *Workflow) rememberLabel(c cryptox.EnvironmentChange, sequence uint64) error {
	if c.Operation == "delete" {
		delete(w.state.Labels, c.EnvironmentID)
		return nil
	}
	if c.LabelPayload == "" {
		return nil
	}
	env, ok := w.engine.State().Cloud.Environments[c.EnvironmentID]
	if !ok || strconv.FormatUint(env.KeyVersion, 10) != c.KeyVersion {
		return nil
	}
	key, err := w.environmentKey(c.EnvironmentID)
	if err != nil {
		return err
	}
	defer clear(key)
	packet, err := cryptox.DecodeBase64(c.LabelPayload, 40, 65576)
	if err != nil {
		return err
	}
	plain, err := cryptox.DecryptEnvironmentLabel(key, cryptox.EnvironmentLabelContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: c.EnvironmentID, KeyVersion: c.KeyVersion}, packet)
	if err != nil {
		return err
	}
	defer clear(plain)
	name, err := environmentName(string(plain))
	if err != nil {
		return err
	}
	if old := w.state.Labels[c.EnvironmentID]; sequence >= old.Sequence {
		w.state.Labels[c.EnvironmentID] = labelState{Name: name, KeyVersion: c.KeyVersion, Sequence: sequence}
	}
	return nil
}
func (w *Workflow) grant(id string) (cryptox.Grant, error) {
	env, ok := w.engine.State().Cloud.Environments[id]
	if !ok || (env.ExpiresAt != nil && !w.now().Before(*env.ExpiresAt)) {
		return cryptox.Grant{}, localstate.ErrUnauthorized
	}
	for _, g := range w.state.Grants {
		if g.Grant.EnvironmentID == id && g.Grant.SubjectDeviceID == w.state.DeviceID && g.Grant.KeyVersion == strconv.FormatUint(env.KeyVersion, 10) && g.Grant.GrantGeneration == strconv.FormatUint(env.GrantGeneration, 10) {
			return g.Grant, nil
		}
	}
	return cryptox.Grant{}, ErrNotTrusted
}
func (w *Workflow) environmentKey(id string) ([]byte, error) {
	g, err := w.grant(id)
	if err != nil {
		return nil, err
	}
	packet, err := cryptox.DecodeBase64(g.Envelope, 80, 80)
	if err != nil {
		return nil, err
	}
	return cryptox.UnwrapEnvironmentKey(w.receiving, cryptox.EnvelopeContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: id, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: w.state.DeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: w.state.ReceivingPublicKey}, packet)
}
func (w *Workflow) view() View {
	snapshot := w.engine.State().Cloud
	view := View{Checkpoint: snapshot.Sequence, DeviceID: w.state.DeviceID, Experimental: true, Environments: []ViewEnvironment{}}
	ids := []string{}
	for id := range snapshot.Environments {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		env := snapshot.Environments[id]
		if env.ExpiresAt != nil && !w.now().Before(*env.ExpiresAt) {
			continue
		}
		name := id
		if label := w.state.Labels[id]; label.KeyVersion == strconv.FormatUint(env.KeyVersion, 10) {
			name = label.Name
		}
		view.Environments = append(view.Environments, ViewEnvironment{ID: id, Name: name, Role: env.Role, Variables: clone(env.Values)})
	}
	return view
}
func (w *Workflow) View() (View, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return View{}, err
	}
	if w.state.Root == nil {
		return View{}, ErrNotTrusted
	}
	if err := w.validateOriginCache(); err != nil {
		return View{}, err
	}
	if _, err := w.engine.Effective(w.now()); err != nil {
		return View{}, err
	}
	if err := w.persist(); err != nil {
		return View{}, err
	}
	return w.view(), nil
}
func (w *Workflow) Pull(ctx context.Context) (View, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return View{}, err
	}
	if err := w.refresh(ctx); err != nil {
		return View{}, err
	}
	return w.view(), nil
}
func (w *Workflow) makeGrant(env, version, generation, id string, key []byte, expires string) (cryptox.SignedGrantWire, error) {
	p, err := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, KeyVersion: version, RecipientType: "device", RecipientID: w.state.DeviceID, RecipientGeneration: generation, RecipientPublicKey: w.state.ReceivingPublicKey})
	if err != nil {
		return cryptox.SignedGrantWire{}, err
	}
	g := cryptox.Grant{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, IssuerDeviceID: w.state.DeviceID, SubjectDeviceID: w.state.DeviceID, SubjectSigningPublicKey: w.state.SigningPublicKey, SubjectReceivingPublicKey: w.state.ReceivingPublicKey, EnvironmentID: env, KeyVersion: version, GrantGeneration: generation, Role: "admin", ExpiresAt: expires, IdempotencyKey: id, Envelope: cryptox.EncodeBase64(p)}
	signed, err := cryptox.SignGrant(g, w.signing)
	return cryptox.GrantToWire(signed), err
}

type nativeJournal struct{ workflow *Workflow }

func (j nativeJournal) Load() ([]byte, error) {
	if len(j.workflow.state.WriteJournal) == 0 {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(j.workflow.state.WriteJournal), nil
}
func (j nativeJournal) Save(data []byte) error {
	j.workflow.state.WriteJournal = bytes.Clone(data)
	return j.workflow.persist()
}
func (w *Workflow) persist() error {
	w.state.Cloud = w.engine.State()
	if w.requiresDAGCAS {
		return w.saveDAGCandidateLocked(clone(w.state))
	}
	encoded, err := json.Marshal(w.state)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if len(encoded) > 8<<20 || w.saveNative(encoded) != nil {
		return errors.New("native protected state persistence failed")
	}
	w.protectedSHA256 = protectedStateHash(encoded)
	return nil
}
func (w *Workflow) ensureWriter() error {
	if w.writer != nil {
		return nil
	}
	generation, err := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if err != nil {
		return err
	}
	w.writer, err = syncclient.NewWriter(w.state.AccountID, generation, w.state.DeviceID, w.engine.State().SessionEpoch, w.signing, nativeJournal{w})
	return err
}
func (w *Workflow) mutate(ctx context.Context, env, name, value, id, operation string) (View, error) {
	if err := w.refresh(ctx); err != nil {
		return View{}, err
	}
	if err := w.ensureWriter(); err != nil {
		return View{}, err
	}
	_, err := w.writer.Execute(ctx, w.client, syncclient.WriteRequest{ID: id, Operation: operation, EnvironmentID: env, Name: name, Value: value})
	if err != nil {
		return View{}, err
	}
	if err = w.persist(); err != nil {
		return View{}, err
	}
	return w.view(), nil
}
func (w *Workflow) SetVariable(ctx context.Context, env, name, value, id string) (View, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return View{}, err
	}
	return w.mutate(ctx, env, name, value, id, "put")
}
func (w *Workflow) DeleteVariable(ctx context.Context, env, name, id string) (View, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return View{}, err
	}
	return w.mutate(ctx, env, name, "", id, "delete")
}
func (w *Workflow) submitRecord(ctx context.Context, record *environmentRecord) error {
	if record.OriginV2 != nil {
		return w.submitEnvironmentOrigin(ctx, record)
	}
	if record.Signed.Change.Operation == "create" || record.Signed.Change.Operation == "rotate" {
		return ErrLegacyEnvironmentOrigin
	}
	status, err := w.client.EnvironmentStatus(ctx, record.Signed.Change.IdempotencyKey)
	if err != nil {
		return err
	}
	var result syncclient.SubmitResult
	if status.State == "complete" {
		result, err = w.client.ConfirmEnvironmentChange(ctx, record.Signed, syncclient.Acceptance{Sequence: status.Sequence, Replayed: true})
	} else {
		result, err = w.client.SubmitEnvironmentChange(ctx, record.Signed)
	}
	if result.Accepted.Sequence > 0 {
		record.Sequence = result.Accepted.Sequence
	}
	record.Applied = result.Applied
	if saveErr := w.persist(); saveErr != nil {
		return errors.Join(syncclient.ErrAcceptedNotApplied, saveErr)
	}
	if err != nil {
		return err
	}
	if err := w.refresh(ctx); err != nil {
		return err
	}
	if err := w.rememberLabel(record.Signed.Change, record.Sequence); err != nil {
		return err
	}
	return w.persist()
}
func (w *Workflow) environmentOperation(ctx context.Context, operation, env, name, id string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`).MatchString(id) {
		return errors.New("environment request id invalid")
	}
	input, _ := json.Marshal([]string{operation, env, name, id})
	hash := sha256.Sum256(input)
	fingerprint := hex.EncodeToString(hash[:])
	if err := w.refresh(ctx); err != nil {
		return err
	}
	if record := w.state.EnvironmentWrites[id]; record != nil {
		if record.InputHash != fingerprint {
			return syncclient.ErrWriteConflict
		}
		if err := w.persist(); err != nil {
			return err
		}
		return w.submitRecord(ctx, record)
	}
	if len(w.state.EnvironmentWrites) >= 32 {
		return errors.New("protected environment request journal full")
	}
	var authority cryptox.Grant
	var err error
	if operation == "create" {
		for _, grant := range w.state.Grants {
			if grant.Grant.Role == "admin" {
				if _, e := w.grant(grant.Grant.EnvironmentID); e == nil {
					authority = grant.Grant
					break
				}
			}
		}
		if authority.EnvironmentID == "" {
			return localstate.ErrUnauthorized
		}
		env, err = randomID()
		if err != nil {
			return err
		}
	} else {
		authority, err = w.grant(env)
		if err != nil || authority.Role != "admin" {
			return localstate.ErrUnauthorized
		}
	}
	var control syncclient.EnvironmentControlView
	if operation == "create" {
		control, err = w.environmentControl(ctx, authority.EnvironmentID)
		if err != nil {
			return err
		}
	}
	change := w.baseChange(env, operation, id, authority)
	recipient, err := w.environmentRecoveryRecipient()
	if err != nil {
		return err
	}
	change.RecoveryGeneration = recipient.RecoveryGeneration
	if operation != "delete" {
		var key []byte
		if operation == "create" {
			key, err = cryptox.GenerateEnvironmentKey()
			change.PreviousKeyVersion = "0"
			change.KeyVersion = "1"
		} else {
			key, err = w.environmentKey(env)
		}
		if err != nil {
			return err
		}
		defer clear(key)
		label, err := cryptox.EncryptEnvironmentLabel(key, cryptox.EnvironmentLabelContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, KeyVersion: change.KeyVersion}, []byte(name))
		if err != nil {
			return err
		}
		change.LabelPayload = cryptox.EncodeBase64(label)
		if operation == "create" {
			grant, err := w.makeGrant(env, "1", "1", "grant-"+id, key, authority.ExpiresAt)
			if err != nil {
				return err
			}
			envelope, err := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, KeyVersion: "1", RecipientType: "recovery", RecipientID: w.state.AccountID, RecipientGeneration: recipient.RecoveryGeneration, RecipientPublicKey: recipient.RecoveryReceivingPublicKey})
			if err != nil {
				return err
			}
			change.Grants = []cryptox.SignedGrantWire{grant}
			change.RecoveryEnvelope = cryptox.EncodeBase64(envelope)
		}
	}
	signed, err := cryptox.SignEnvironmentChange(change, w.signing)
	if err != nil {
		return err
	}
	record := &environmentRecord{InputHash: fingerprint, Signed: signed}
	if operation == "create" {
		record.OriginV2, err = w.prepareEnvironmentOrigin(ctx, signed, control)
		if err != nil {
			return err
		}
	}
	w.state.EnvironmentWrites[id] = record
	if err = w.persist(); err != nil {
		return err
	}
	return w.submitRecord(ctx, record)
}
func (w *Workflow) baseChange(env, operation, id string, authority cryptox.Grant) cryptox.EnvironmentChange {
	return cryptox.EnvironmentChange{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, DeviceID: w.state.DeviceID, EnvironmentID: env, Operation: operation, AuthorityEnvironmentID: authority.EnvironmentID, AuthorityKeyVersion: authority.KeyVersion, AuthorityGrantGeneration: authority.GrantGeneration, PreviousKeyVersion: authority.KeyVersion, KeyVersion: authority.KeyVersion, ExpectedSequence: strconv.FormatUint(w.engine.State().Cloud.Sequence, 10), IdempotencyKey: id, RecoveryGeneration: w.state.Root.RecoveryGeneration}
}
func (w *Workflow) rename(ctx context.Context, env, name, id string) error {
	name, err := environmentName(name)
	if err != nil {
		return err
	}
	return w.environmentOperation(ctx, "rename", env, name, id)
}
func (w *Workflow) RenameEnvironment(ctx context.Context, env, name, id string) (View, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return View{}, err
	}
	if err := w.rename(ctx, env, name, id); err != nil {
		return View{}, err
	}
	return w.view(), nil
}
func (w *Workflow) CreateEnvironment(ctx context.Context, name, id string) (View, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return View{}, err
	}
	name, err := environmentName(name)
	if err != nil {
		return View{}, err
	}
	if err = w.environmentOperation(ctx, "create", "", name, id); err != nil {
		return View{}, err
	}
	return w.view(), nil
}
func (w *Workflow) DeleteEnvironment(ctx context.Context, env, id string) (View, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return View{}, err
	}
	if err := w.environmentOperation(ctx, "delete", env, "", id); err != nil {
		return View{}, err
	}
	return w.view(), nil
}

// 尚无可核验的多管理手机历史链与原生PAKE业务，绝不能据未签服务器目录扩大信任。
func (w *Workflow) ApproveDevice(context.Context, string) error { return ErrUnsupported }
func (w *Workflow) Recover(context.Context, string) error       { return ErrUnsupported }
