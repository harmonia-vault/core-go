package mobilebridge

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"github.com/harmonia-vault/core-go/syncclient"
)

const stateHeader = "HARMST01"
const maxState = 8 << 20
const maxWorkflowCommand = 32768

// SealedStateStore 只能由可信原生层实现；每次回调必须同步原子保存密文后返回。
// 不接受 Dart/服务器实现，不返回解密后的状态、钥匙或随机 token。
type SealedStateStore interface{ SaveSealed(packet []byte) error }

// AtomicSealedStateStore 是 DAG 的额外 native-only 合同。必须在现有 OS/slot
// owner 锁内比较当前完整密文与 expected，然后原子写入 next（包含同次 epoch）。
// callback 内先读再无锁普通写不是 CAS；旧 SaveSealed provider 不满足本合同。
type AtomicSealedStateStore interface {
	SealedStateStore
	CompareAndSwapSealed(expected, next []byte) error
	CheckSealed(expected []byte) error
}

type stateBinding struct {
	Namespace          string `json:"namespace"`
	Version            int    `json:"version"`
	Endpoint           string `json:"endpoint"`
	DeviceID           string `json:"deviceId"`
	SigningPublicKey   string `json:"signingPublicKey"`
	ReceivingPublicKey string `json:"receivingPublicKey"`
	AccountID          string `json:"accountId"`
	AccountGeneration  string `json:"accountGeneration"`
	Checkpoint         uint64 `json:"checkpoint"`
	AccountClosed      bool   `json:"accountClosed"`
}

// VaultWorkflow 每次系统强认证后创建，一次业务操作后关闭。软件 AES 状态钥只在本对象存活。
// namespace 是原生包名和文件域，附加 CA 来自原生系统证书/明确测试 CA，均禁止 Dart 提供。
type VaultWorkflow struct {
	mu               sync.Mutex
	workflow         *mobileworkflow.Workflow
	key              []byte
	binding          stateBinding
	store            SealedStateStore
	deleteDevice     bool
	saveFailed       atomic.Bool
	lastSealed       []byte
	protectedSHA256  string
	recoveryRegistry *RecoveryRegistry
	cancelMu         sync.Mutex
	cancel           context.CancelFunc
}

func WorkflowProfile() (string, error) {
	return encode(map[string]any{"version": 1, "realVaultReady": false, "experimental": true,
		"profile": "origin-aware-native-v1", "systemAuthenticationPerOperation": true,
		"approvalProfile": "explicit-certificate-version", "legacyApprovalProfile": "first-root-issuer-proof-v1",
		"approvalV3Profile": "certificate3-issuer-origin-v1", "approvalV4Profile": "certificate4-continuous-recovery-v1", "enrollmentV3Profile": "certificate3-issuer-origin-v1", "environmentKeyRotation": true, "managementProfile": "authenticated-original-transaction-v1", "recoveryAuthorityProfile": "continuous-issuer-recovery-v1-process-owner",
		"operations":  []string{"loginAccount", "restoreSession", "businessPendingInfo", "retryBusinessOperation", "register", "verifyEmail", "beginInitialization", "queryInitialization", "completeInitialization", "view", "pull", "createEnvironment", "renameEnvironment", "deleteEnvironment", "setVariable", "deleteVariable", "revokeSelf", "selfRevocationInfo", "approvePairing", "retryApproval", "approvalInfo", "cancelApproval", "approvePairingV3", "retryApprovalV3", "approvalInfoV3", "cancelApprovalV3", "approvePairingV4", "retryApprovalV4", "approvalInfoV4", "cancelApprovalV4", "enrollDeviceV3", "resumeEnrollmentV3", "enrollmentInfoV3", "rotateEnvironmentKey", "managementDevices", "prepareDeviceGrant", "prepareOtherDeviceRevocation", "managementInfo", "retryManagement", "cancelManagement", "beginRecoveryAuthority", "resumeRecoveryAuthority", "recoveryInfo", "recoveryView", "beginRecoveryTransition", "completeRecoveryTransition", "queryRecoveryTransition", "registerRecoveredDevice", "retryRecoveredDevice", "recoveredDeviceInfo", "logout"},
		"unsupported": []string{"approveDevice", "recover", "rotateRecovery", "accountReset"}})
}

func (d *Device) OpenWorkflow(endpoint, namespace string, sealed, additionalCA []byte, store SealedStateStore) (*VaultWorkflow, error) {
	canonical, err := validateEndpoint(endpoint)
	if err != nil || canonical != endpoint || namespace == "" || len(namespace) > 512 || !utf8.ValidString(namespace) || store == nil {
		return nil, errInput
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.signing) != 64 || len(d.receiving) != 32 {
		return nil, errClosed
	}
	receive, err := ecdh.X25519().NewPrivateKey(d.receiving)
	if err != nil {
		return nil, errInput
	}
	sign := d.signing.Public().(ed25519.PublicKey)
	id := sha256.Sum256(sign)
	binding := stateBinding{Namespace: namespace, Version: 1, Endpoint: endpoint, DeviceID: hex.EncodeToString(id[:]), SigningPublicKey: cryptox.EncodeBase64(sign), ReceivingPublicKey: cryptox.EncodeBase64(receive.PublicKey().Bytes())}
	// 独立用途域派生状态 AES 钥；设备签名/接收钥仍独立生成。此钥不是硬件内钥。
	// namespace+完整 endpoint+双公钥固定 KDF，跨文件/包/端点/设备替换失败。
	info, _ := json.Marshal([]string{"harmonia/native-workflow-aes/v1", namespace, endpoint, binding.SigningPublicKey, binding.ReceivingPublicKey})
	input := append(bytes.Clone(d.signing[:32]), d.receiving...)
	defer clear(input)
	key, err := hkdf.Key(sha256.New, input, nil, string(info), 32)
	if err != nil {
		return nil, errInput
	}
	v := &VaultWorkflow{key: key, binding: binding, store: store, lastSealed: bytes.Clone(sealed)}
	if len(sealed) == 0 {
		v.lastSealed = nil
	}
	var plain []byte
	if len(sealed) > 0 {
		plain, err = v.open(sealed)
		if err != nil {
			v.Close()
			return nil, errors.New("protected workflow state rejected")
		}
		defer clear(plain)
	}
	client, err := workflowHTTPClient(additionalCA)
	if err != nil {
		v.Close()
		return nil, err
	}
	h := sha256.Sum256(plain)
	v.protectedSHA256 = hex.EncodeToString(h[:])
	var atomicSave func(string, []byte) error
	var atomicCheck func(string) error
	if _, ok := store.(AtomicSealedStateStore); ok {
		atomicSave = v.saveCAS
		atomicCheck = v.checkProtected
	}
	v.workflow, err = mobileworkflow.New(mobileworkflow.Config{Endpoint: endpoint, HTTPClient: client, SigningKey: d.signing, ReceivingPrivateKey: d.receiving, ProtectedState: plain, SaveProtectedState: v.save, SaveProtectedStateCAS: atomicSave, CheckProtectedState: atomicCheck})
	if err != nil {
		v.Close()
		return nil, errors.New("protected workflow state rejected")
	}
	return v, nil
}

func workflowHTTPClient(additionalCA []byte) (*http.Client, error) {
	if len(additionalCA) > 2<<20 {
		return nil, errInput
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if len(additionalCA) > 0 && !roots.AppendCertsFromPEM(additionalCA) {
		return nil, errors.New("native CA certificates rejected")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func projectedBinding(plain []byte) (stateBinding, error) {
	var p struct {
		Version            int              `json:"version"`
		Endpoint           string           `json:"endpoint"`
		DeviceID           string           `json:"deviceId"`
		SigningPublicKey   string           `json:"signingPublicKey"`
		ReceivingPublicKey string           `json:"receivingPublicKey"`
		AccountID          string           `json:"accountId"`
		AccountGeneration  string           `json:"accountGeneration"`
		Cloud              localstate.State `json:"cloud"`
	}
	if len(plain) == 0 || len(plain) > maxState || json.Unmarshal(plain, &p) != nil {
		return stateBinding{}, errInput
	}
	if p.Cloud.Cloud.AccountID != "" && (p.Cloud.Cloud.AccountID != p.AccountID || strconv.FormatUint(p.Cloud.Cloud.AccountGeneration, 10) != p.AccountGeneration) {
		return stateBinding{}, errInput
	}
	return stateBinding{Version: p.Version, Endpoint: p.Endpoint, DeviceID: p.DeviceID, SigningPublicKey: p.SigningPublicKey, ReceivingPublicKey: p.ReceivingPublicKey, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, Checkpoint: p.Cloud.Cloud.Sequence, AccountClosed: p.Cloud.AccountClosed}, nil
}
func (v *VaultWorkflow) matches(b stateBinding) bool {
	return b.Namespace == v.binding.Namespace && b.Version == 1 && b.Endpoint == v.binding.Endpoint && b.DeviceID == v.binding.DeviceID && b.SigningPublicKey == v.binding.SigningPublicKey && b.ReceivingPublicKey == v.binding.ReceivingPublicKey
}
func (v *VaultWorkflow) aead() (cipher.AEAD, error) {
	b, e := aes.NewCipher(v.key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func (v *VaultWorkflow) save(plain []byte) error { return v.saveProtected(plain, nil) }
func (v *VaultWorkflow) saveCAS(expected string, plain []byte) error {
	return v.saveProtected(plain, &expected)
}

// 当前原生密文必须仍是本次认证解包的完整状态；旧对象不能只凭 RAM epoch 存活。
func (v *VaultWorkflow) checkProtected(expected string) (err error) {
	if v.saveFailed.Load() {
		return errClosed
	}
	defer func() {
		if err != nil {
			v.saveFailed.Store(true)
			v.invalidateRecoveryOwner()
			v.cancelOperation()
		}
	}()
	atomicStore, ok := v.store.(AtomicSealedStateStore)
	if !ok {
		return mobileworkflow.ErrDAGAtomicStoreRequired
	}
	if expected != v.protectedSHA256 {
		return errInput
	}
	return atomicStore.CheckSealed(bytes.Clone(v.lastSealed))
}
func (v *VaultWorkflow) saveProtected(plain []byte, expected *string) (err error) {
	if v.saveFailed.Load() {
		return errClosed
	}
	defer func() {
		if err != nil {
			v.saveFailed.Store(true)
			v.invalidateRecoveryOwner()
			v.cancelOperation()
		}
	}()
	if expected != nil && *expected != v.protectedSHA256 {
		return errInput
	}
	b, err := projectedBinding(plain)
	b.Namespace = v.binding.Namespace
	if err != nil || !v.matches(b) {
		return errInput
	}
	if v.binding.AccountID != "" && (v.binding.AccountID != b.AccountID || v.binding.AccountGeneration != b.AccountGeneration || !b.AccountClosed && b.Checkpoint < v.binding.Checkpoint) {
		return errInput
	}
	metadata, _ := json.Marshal(b)
	if len(metadata) > 4096 {
		return errInput
	}
	aad := make([]byte, 12+len(metadata))
	copy(aad, stateHeader)
	binary.BigEndian.PutUint32(aad[8:12], uint32(len(metadata)))
	copy(aad[12:], metadata)
	gcm, err := v.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	packet := append(bytes.Clone(aad), nonce...)
	packet = gcm.Seal(packet, nonce, plain, aad)
	if expected != nil {
		atomicStore, ok := v.store.(AtomicSealedStateStore)
		if !ok {
			return mobileworkflow.ErrDAGAtomicStoreRequired
		}
		err = atomicStore.CompareAndSwapSealed(bytes.Clone(v.lastSealed), packet)
	} else {
		err = v.store.SaveSealed(packet)
	}
	if err != nil {
		return errors.New("native atomic protected save failed")
	}
	clear(v.lastSealed)
	v.lastSealed = bytes.Clone(packet)
	h := sha256.Sum256(plain)
	v.protectedSHA256 = hex.EncodeToString(h[:])
	v.binding = b
	return nil
}
func (v *VaultWorkflow) open(packet []byte) ([]byte, error) {
	if len(packet) < 12+12+16 || len(packet) > maxState+8192 || string(packet[:8]) != stateHeader {
		return nil, errInput
	}
	n := int(binary.BigEndian.Uint32(packet[8:12]))
	if n < 1 || n > 4096 || 12+n+28 > len(packet) {
		return nil, errInput
	}
	aad := packet[:12+n]
	var b stateBinding
	dec := json.NewDecoder(bytes.NewReader(packet[12 : 12+n]))
	dec.DisallowUnknownFields()
	if dec.Decode(&b) != nil || !v.matches(b) {
		return nil, errInput
	}
	expected, _ := json.Marshal(b)
	if !bytes.Equal(expected, packet[12:12+n]) {
		return nil, errInput
	}
	gcm, err := v.aead()
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, packet[12+n:24+n], packet[24+n:], aad)
	if err != nil {
		return nil, errInput
	}
	actual, err := projectedBinding(plain)
	actual.Namespace = v.binding.Namespace
	if err != nil || actual != b {
		clear(plain)
		return nil, errInput
	}
	v.binding = b
	return plain, nil
}

func (v *VaultWorkflow) Cancel() {
	v.clearRecoveryOwner()
	v.cancelOperation()
}
func (v *VaultWorkflow) cancelOperation() {
	v.cancelMu.Lock()
	defer v.cancelMu.Unlock()
	if v.cancel != nil {
		v.cancel()
	}
}

func (v *VaultWorkflow) Close() {
	v.cancelOperation()
	v.mu.Lock()
	defer func() {
		v.mu.Unlock()
		if v.saveFailed.Load() {
			v.clearRecoveryOwner()
		}
	}()
	// OpenWorkflow 错误路径没有锁；外部调用在原生串行 worker 中运行。
	if v.workflow != nil {
		v.workflow.Close()
		v.workflow = nil
	}
	clear(v.key)
	v.key = nil
	v.store = nil
	clear(v.lastSealed)
	v.lastSealed = nil
	v.protectedSHA256 = ""
}
func (v *VaultWorkflow) RequiresDeviceDeletion() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.deleteDevice
}

type workflowCommand struct {
	endpoint  string
	operation string
	fields    map[string]string
}

var operationFields = map[string][]string{
	"register": {"email", "password"}, "verifyEmail": {"accountId", "accountGeneration", "challengeId", "token"},
	"beginInitialization": {"email", "password", "name", "id"}, "completeInitialization": {"recoveryCode"},
	"revokeSelf":         {"id"},
	"selfRevocationInfo": {},
	"approvePairing":     {"pairingId", "selections"}, "retryApproval": {"pairingId"}, "approvalInfo": {}, "cancelApproval": {"pairingId"},
	"approvePairingV3": {"pairingId", "selections"}, "retryApprovalV3": {"pairingId"}, "approvalInfoV3": {}, "cancelApprovalV3": {"pairingId"},
	"approvePairingV4": {"pairingId", "selections"}, "retryApprovalV4": {"pairingId"}, "approvalInfoV4": {}, "cancelApprovalV4": {"pairingId"},
	"enrollDeviceV3": {"email", "password", "pairingId", "approverDeviceId"}, "resumeEnrollmentV3": {"pairingId"}, "enrollmentInfoV3": {},
	"rotateEnvironmentKey": {"environmentId", "id"},
	"queryInitialization":  {}, "pull": {}, "view": {}, "logout": {},
	"setVariable": {"environmentId", "name", "value", "id"}, "deleteVariable": {"environmentId", "name", "id"},
	"createEnvironment": {"name", "id"}, "renameEnvironment": {"environmentId", "name", "id"}, "deleteEnvironment": {"environmentId", "id"},
}

func parseWorkflowCommand(raw string) (workflowCommand, error) {
	c := workflowCommand{fields: map[string]string{}}
	if len(raw) == 0 || len(raw) > maxWorkflowCommand || !utf8.ValidString(raw) {
		return c, errInput
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	t, e := dec.Token()
	if e != nil || t != json.Delim('{') {
		return c, errInput
	}
	seen := map[string]bool{}
	version := false
	for dec.More() {
		t, e = dec.Token()
		name, ok := t.(string)
		if e != nil || !ok || seen[name] {
			return c, errInput
		}
		seen[name] = true
		if name == "version" {
			var n int
			if dec.Decode(&n) != nil || n != 1 {
				return c, errInput
			}
			version = true
			continue
		}
		var s string
		if dec.Decode(&s) != nil {
			return c, errInput
		}
		if name == "operation" {
			c.operation = s
		} else {
			c.fields[name] = s
		}
	}
	if _, e = dec.Token(); e != nil {
		return c, errInput
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || !version {
		return c, errInput
	}
	endpoint, exists := c.fields["endpoint"]
	if !exists {
		return c, errInput
	}
	if canonical, e := validateEndpoint(endpoint); e != nil || canonical != endpoint {
		return c, errInput
	}
	c.endpoint = endpoint
	delete(c.fields, "endpoint")
	fields, ok := operationFields[c.operation]
	if !ok {
		fields, ok = managementFields[c.operation]
		if !ok {
			fields, ok = recoveryFields[c.operation]
			if !ok {
				fields, ok = businessIntentFields[c.operation]
			}
		}
	}
	if !ok || len(fields) != len(c.fields) {
		return c, errInput
	}
	for _, name := range fields {
		if _, ok = c.fields[name]; !ok {
			return c, errInput
		}
	}
	return c, nil
}

// Execute 只返回已验签业务视图或本次新恢复码；随机会话/保护状态/私钥没有导出路径。
func (v *VaultWorkflow) Execute(raw string) (string, error) {
	return v.execute(raw, nil, "")
}

// ExecuteApproval 的短码独立字节参数只在一次成功系统认证后的调用内存活。
// command 不允许包含短码、root、证书或服务器签包。调用结束清理可控缓冲。
func (v *VaultWorkflow) ExecuteApproval(raw string, shortCode []byte) (string, error) {
	defer clear(shortCode)
	return v.execute(raw, shortCode, "approval")
}

// ExecuteEnrollment只接受显式cert3候选入网，同次登录及完整PAKE。
// 未应用的已接受receipt只能原id Resume，不能据approved或accepted输出可信view。
func (v *VaultWorkflow) ExecuteEnrollment(raw string, shortCode []byte) (string, error) {
	defer clear(shortCode)
	return v.execute(raw, shortCode, "enrollment")
}

func (v *VaultWorkflow) execute(raw string, shortCode []byte, mode string) (string, error) {
	c, err := parseWorkflowCommand(raw)
	if err != nil {
		return "", err
	}
	approval := c.operation == "approvePairing" || c.operation == "approvePairingV3" || c.operation == "approvePairingV4"
	enrollment := c.operation == "enrollDeviceV3"
	if mode == "approval" && !approval || mode == "enrollment" && !enrollment || mode == "" && (approval || enrollment) {
		return "", errInput
	}
	var choices []mobileworkflow.ApprovalSelection
	if approval {
		choices, err = parseApprovalSelections(c.fields["selections"])
		if err != nil {
			return "", errInput
		}
	}
	if approval || enrollment {
		if len(shortCode) != 8 {
			return "", errInput
		}
		for _, b := range shortCode {
			if b < '0' || b > '9' {
				return "", errInput
			}
		}
	}
	v.mu.Lock()
	defer func() {
		v.mu.Unlock()
		if v.saveFailed.Load() {
			v.clearRecoveryOwner()
		}
	}()
	if v.saveFailed.Load() {
		return "", errClosed
	}
	if c.endpoint != v.binding.Endpoint {
		return "", errInput
	}
	if v.workflow == nil || len(v.key) != 32 {
		return "", errClosed
	}
	duration := 30 * time.Second
	if approval || enrollment {
		duration = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	v.cancelMu.Lock()
	v.cancel = cancel
	v.cancelMu.Unlock()
	defer func() { cancel(); v.cancelMu.Lock(); v.cancel = nil; v.cancelMu.Unlock() }()
	f := c.fields
	var data any
	var code string
	switch c.operation {
	case "register":
		data, err = v.workflow.Register(ctx, f["email"], f["password"])
	case "verifyEmail":
		err = v.workflow.VerifyEmail(ctx, mobileworkflow.EmailProof{AccountID: f["accountId"], AccountGeneration: f["accountGeneration"], ChallengeID: f["challengeId"], Token: f["token"]})
	case "beginInitialization":
		err = v.workflow.Login(ctx, f["email"], f["password"])
		if err == nil {
			code, err = v.workflow.BeginInitialization(ctx, f["name"], f["id"])
		}
	case "completeInitialization":
		data, err = v.workflow.CompleteInitialization(ctx, f["recoveryCode"])
	case "queryInitialization":
		var state string
		state, err = v.workflow.QueryInitialization(ctx)
		data = map[string]string{"state": state}
	case "view":
		data, err = v.workflow.View()
	case "pull":
		data, err = v.workflow.Pull(ctx)
	case "setVariable":
		data, err = v.workflow.SetVariable(ctx, f["environmentId"], f["name"], f["value"], f["id"])
	case "deleteVariable":
		data, err = v.workflow.DeleteVariable(ctx, f["environmentId"], f["name"], f["id"])
	case "createEnvironment":
		data, err = v.workflow.CreateEnvironment(ctx, f["name"], f["id"])
	case "renameEnvironment":
		data, err = v.workflow.RenameEnvironment(ctx, f["environmentId"], f["name"], f["id"])
	case "deleteEnvironment":
		data, err = v.workflow.DeleteEnvironment(ctx, f["environmentId"], f["id"])
	case "approvePairing":
		data, err = v.workflow.ApprovePairing(ctx, mobileworkflow.ApprovalInput{PairingID: f["pairingId"], ShortCode: shortCode, Selections: choices})
	case "retryApproval":
		data, err = v.workflow.RetryApproval(ctx, f["pairingId"])
	case "approvalInfo":
		data, err = v.workflow.ApprovalInfo()
	case "cancelApproval":
		err = v.workflow.CancelApproval(f["pairingId"])
	case "approvePairingV3":
		data, err = v.workflow.ApprovePairingV3(ctx, mobileworkflow.ApprovalInput{PairingID: f["pairingId"], ShortCode: shortCode, Selections: choices})
	case "retryApprovalV3":
		data, err = v.workflow.RetryApprovalV3(ctx, f["pairingId"])
	case "approvalInfoV3":
		data, err = v.workflow.ApprovalInfoV3()
	case "cancelApprovalV3":
		err = v.workflow.CancelApprovalV3(f["pairingId"])
	case "approvePairingV4":
		data, err = v.workflow.ApprovePairingV4(ctx, mobileworkflow.ApprovalInput{PairingID: f["pairingId"], ShortCode: shortCode, Selections: choices})
	case "retryApprovalV4":
		data, err = v.workflow.RetryApprovalV4(ctx, f["pairingId"])
	case "approvalInfoV4":
		data, err = v.workflow.ApprovalInfoV4()
	case "cancelApprovalV4":
		err = v.workflow.CancelApprovalV4(f["pairingId"])
	case "enrollDeviceV3":
		err = v.workflow.Login(ctx, f["email"], f["password"])
		if err == nil {
			data, err = v.workflow.EnrollDevice(ctx, mobileworkflow.EnrollmentInput{PairingID: f["pairingId"], ApproverDeviceID: f["approverDeviceId"], ShortCode: shortCode})
		}
	case "resumeEnrollmentV3":
		data, err = v.workflow.ResumeEnrollment(ctx, f["pairingId"])
	case "enrollmentInfoV3":
		data, err = v.workflow.EnrollmentInfo()
	case "rotateEnvironmentKey":
		data, err = v.workflow.RotateEnvironment(ctx, f["environmentId"], f["id"])
	case "selfRevocationInfo":
		data, err = v.workflow.SelfRevocationInfo()
	case "revokeSelf":
		var result mobileworkflow.SelfRevocationResult
		result, err = v.workflow.RevokeSelf(ctx, f["id"])
		data = result
		if result.DeviceInvalidated {
			v.deleteDevice = true
		}
	case "logout":
		v.clearRecoveryOwner()
		v.deleteDevice = true
		err = v.workflow.Logout()
	default:
		if recoveryOperation(c.operation) {
			data, code, err = v.executeRecovery(ctx, c)
		} else if businessIntentOperation(c.operation) {
			data, err = v.executeBusinessIntent(ctx, c)
		} else {
			data, err = v.executeManagement(ctx, c)
		}
	}
	out := map[string]any{"version": 1, "ok": err == nil, "experimental": true}
	if code != "" {
		out["recoveryCode"] = code
	}
	if (c.operation == "retryBusinessOperation" || c.operation == "revokeSelf" || c.operation == "approvePairing" || c.operation == "retryApproval" || c.operation == "approvePairingV3" || c.operation == "retryApprovalV3" || c.operation == "approvePairingV4" || c.operation == "retryApprovalV4" || c.operation == "retryManagement" || recoveryOperation(c.operation) && c.operation != "recoveryView") && data != nil {
		out["data"] = data
	}
	if err == nil {
		if data != nil {
			out["data"] = data
		}
	} else {
		status := "REJECTED"
		switch {
		case errors.Is(err, syncclient.ErrTrustInvalidated):
			status = "TRUST_INVALIDATED"
			v.deleteDevice = true
			v.clearRecoveryOwner()
		case errors.Is(err, mobileworkflow.ErrRecoverySession):
			status = "RECOVERY_RESTART_REQUIRED"
			out["requiresRecoveryRestart"] = true
		case errors.Is(err, mobileworkflow.ErrRecoveryExpired):
			status = "RECOVERY_EXPIRED_PENDING"
		case errors.Is(err, mobileworkflow.ErrRecoveryRestricted):
			status = "RECOVERY_RESTRICTED"
		case errors.Is(err, mobileworkflow.ErrRecoveryEvidence):
			status = "RECOVERY_EVIDENCE_REQUIRED"
		case errors.Is(err, mobileworkflow.ErrPending), errors.Is(err, syncclient.ErrAcceptedNotApplied), errors.Is(err, syncclient.ErrWritePending), errors.Is(err, mobileworkflow.ErrSelfRevocationPending), errors.Is(err, mobileworkflow.ErrApprovalPending), errors.Is(err, mobileworkflow.ErrMobileEnrollmentPending), errors.Is(err, mobileworkflow.ErrManagementPending), errors.Is(err, mobileworkflow.ErrRecoveryPending):
			status = "PENDING"
			out["retrySameId"] = true
		case errors.Is(err, mobileworkflow.ErrMobileEnrollmentExpired):
			status = "ENROLLMENT_EXPIRED_PENDING"
		case errors.Is(err, mobileworkflow.ErrApprovalEvidence):
			status = "APPROVAL_EVIDENCE_REQUIRED"
		case errors.Is(err, mobileworkflow.ErrNotTrusted):
			status = "NOT_TRUSTED"
		case errors.Is(err, syncclient.ErrSelfRevocationExpired):
			status = "REVOCATION_EXPIRED_PENDING"
			if managementOperation(c.operation) {
				status = "MANAGEMENT_EXPIRED_PENDING"
			}
		case errors.Is(err, mobileworkflow.ErrClosed):
			status = "CLOSED"
		case errors.Is(err, localstate.ErrUnauthorized), errors.Is(err, syncclient.ErrWritePermission):
			status = "UNAUTHORIZED"
		case errors.Is(err, mobileworkflow.ErrManagementLimit):
			status = "MANAGEMENT_LIMIT"
		case errors.Is(err, syncclient.ErrWriteConflict), errors.Is(err, mobileworkflow.ErrManagementConflict), errors.Is(err, syncclient.ErrGrantUpdateConflict):
			status = "ID_CONFLICT"
		}
		if c.operation == "createEnvironment" || c.operation == "renameEnvironment" || c.operation == "deleteEnvironment" || c.operation == "setVariable" || c.operation == "deleteVariable" || c.operation == "beginInitialization" || c.operation == "revokeSelf" || c.operation == "approvePairing" || c.operation == "retryApproval" || c.operation == "approvePairingV3" || c.operation == "retryApprovalV3" || c.operation == "approvePairingV4" || c.operation == "retryApprovalV4" || c.operation == "enrollDeviceV3" || c.operation == "resumeEnrollmentV3" || c.operation == "rotateEnvironmentKey" || c.operation == "prepareDeviceGrant" || c.operation == "prepareOtherDeviceRevocation" || c.operation == "retryManagement" || c.operation == "retryBusinessOperation" {
			out["retrySameId"] = true
		}
		out["code"] = status
	}
	return encode(out)
}
