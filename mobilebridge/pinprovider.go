package mobilebridge

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/harmonia-vault/core-go/appsecurity"
	"github.com/harmonia-vault/core-go/cryptox"
)

var errPINLifecycle = errors.New("native local PIN owner retirement failed")

// LocalPINLifecycle 只能由固定原生适配器实现，同步取消/清理本 slot 的
// Workflow/Recovery RAM owners。不能来自 Dart，也不能以 bool 表示系统认证。
type LocalPINLifecycle interface{ RetireOwners() error }

// LocalPINStore 的尝试记录必须已被原生 Keystore MAC 验证。Acquire/Release
// 是跨进程整个尝试独占锁；Commit 必须 CAS、fsync、原子保存并读回相同记录。
// SaveWorkflowSealed 使用同 slot 的独立密文文件，不能由 Dart 实现。
type LocalPINStore interface {
	Acquire() error
	Release() error
	LoadAttempts() (string, error)
	CommitAttempts(expectedRevision int64, nextJSON string) error
	SaveWorkflowSealed(packet []byte) error
}

// LocalPINCore 仅供原生私有 PinNativeCore 适配。它不能判断 Android 认证能力：
// Kotlin 必须先用实际 classifier 确认 NO_SYSTEM_AUTH，且检查持久升级 latch。
// 没有系统认证失败后的回退入口，没有设备材料/lease 或任意签名导出。
type LocalPINCore struct {
	mu        sync.Mutex
	cancelMu  sync.Mutex
	cancel    context.CancelFunc
	binding   appsecurity.Binding
	lifecycle LocalPINLifecycle
	setup     *Device
	created   bool
	closed    bool
}

func (*LocalPINCore) String() string               { return "native local PIN core (opaque)" }
func (*LocalPINCore) GoString() string             { return "native local PIN core (opaque)" }
func (*LocalPINCore) MarshalJSON() ([]byte, error) { return nil, appsecurity.ErrNativeOnly }
func (*LocalPINCore) GobEncode() ([]byte, error)   { return nil, appsecurity.ErrNativeOnly }
func (*LocalPINCore) GobDecode([]byte) error       { return appsecurity.ErrNativeOnly }

func nativePINBindingJSON(raw string, pkg, namespace, slot, endpoint string) (appsecurity.Binding, error) {
	var b appsecurity.Binding
	if strictPINJSON([]byte(raw), 4096, &b) != nil || b.Package != pkg || b.Namespace != namespace || b.Slot != slot || b.Endpoint != endpoint || b.Mode != "pin" {
		return b, appsecurity.ErrConfiguration
	}
	canonical, err := validateEndpoint(endpoint)
	if err != nil || canonical != endpoint || b.AuthGeneration == b.KeyEpoch {
		return b, appsecurity.ErrConfiguration
	}
	// 与成熟 Record.Validate 一起核验。这里不执行任何 KDF，不提升设备信任。
	r := appsecurity.Record{Profile: "harmonia/local-pin/v1", Version: 1, Binding: b,
		KDF:  appsecurity.KDFParameters{Algorithm: "argon2id", Version: 19, MemoryKiB: 65536, Iterations: 3, Parallelism: 1, KeyBytes: 32},
		Salt: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), KeyNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		WrappedVaultKey: base64.RawURLEncoding.EncodeToString(make([]byte, 48)), MaterialNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 12)), SealedMaterial: base64.RawURLEncoding.EncodeToString(make([]byte, 88))}
	if r.Validate(b) != nil {
		return b, appsecurity.ErrConfiguration
	}
	return b, nil
}

// NewLocalPINSetup 生成临时新设备及独立 gen/epoch。调用前原生必须证明真正
// 无系统认证、fresh slot 且没有旧系统钥/状态；此函数本身没有认证或信任含义。
func NewLocalPINSetup(pkg, namespace, slot, endpoint string, lifecycle LocalPINLifecycle) (*LocalPINCore, error) {
	if lifecycle == nil {
		return nil, appsecurity.ErrConfiguration
	}
	d, err := NewDevice()
	if err != nil {
		_ = lifecycle.RetireOwners()
		return nil, err
	}
	material, err := d.ExportProtectedMaterial()
	if err != nil {
		d.Close()
		_ = lifecycle.RetireOwners()
		return nil, err
	}
	defer clear(material)
	gen := make([]byte, 32)
	if _, err = rand.Read(gen); err != nil {
		d.Close()
		_ = lifecycle.RetireOwners()
		return nil, appsecurity.ErrConfiguration
	}
	receive, err := ecdh.X25519().NewPrivateKey(material[40:])
	if err != nil {
		d.Close()
		_ = lifecycle.RetireOwners()
		return nil, appsecurity.ErrConfiguration
	}
	b := appsecurity.Binding{Package: pkg, Namespace: namespace, Slot: slot, Endpoint: endpoint, Mode: "pin", AuthGeneration: hex.EncodeToString(gen[:16]), KeyEpoch: hex.EncodeToString(gen[16:]), SigningPublicKey: cryptox.EncodeBase64(d.signing.Public().(ed25519.PublicKey)), ReceivingPublicKey: cryptox.EncodeBase64(receive.PublicKey().Bytes())}
	raw, _ := json.Marshal(b)
	if _, err = nativePINBindingJSON(string(raw), pkg, namespace, slot, endpoint); err != nil {
		d.Close()
		_ = lifecycle.RetireOwners()
		return nil, err
	}
	return &LocalPINCore{binding: b, lifecycle: lifecycle, setup: d}, nil
}

// OpenLocalPINCore 只能接原生实际 MAC 验过的 public scope；固定 pkg/namespace/
// slot/endpoint 不从 Dart 传入。Record 与解包材料还会逐次独立核验同一 binding。
func OpenLocalPINCore(pkg, namespace, slot, endpoint, protectedScopeJSON string, lifecycle LocalPINLifecycle) (*LocalPINCore, error) {
	if lifecycle == nil {
		return nil, appsecurity.ErrConfiguration
	}
	b, err := nativePINBindingJSON(protectedScopeJSON, pkg, namespace, slot, endpoint)
	if err != nil {
		if lifecycle.RetireOwners() != nil {
			return nil, errPINLifecycle
		}
		return nil, err
	}
	return &LocalPINCore{binding: b, lifecycle: lifecycle, created: true}, nil
}

// ScopeJSON 只有固定 public metadata，没有 token、私钥、PIN 或许可 bool。
func (p *LocalPINCore) ScopeJSON() (string, error) {
	if p == nil {
		return "", appsecurity.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return "", appsecurity.ErrClosed
	}
	data, err := json.Marshal(p.binding)
	return string(data), err
}

// Create 返回仅供 native 存储的 canonical Record 密文字节(base64)和 AttemptState。
// native 必须把 record+limiter 同事务 MAC/原子发布；失败必须 Close，不能发业务许可。
// 完整 setup PIN 重输一次；临时新 Device 无论成功/失败都立即关闭。
func (p *LocalPINCore) Create(pin, fullReentry []byte) (out []byte, err error) {
	defer clear(pin)
	defer clear(fullReentry)
	if p == nil {
		return nil, appsecurity.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.created || p.setup == nil {
		return nil, appsecurity.ErrClosed
	}
	d := p.setup
	p.setup = nil
	p.created = true
	defer d.Close()
	material, err := d.ExportProtectedMaterial()
	if err != nil {
		return nil, err
	}
	defer clear(material)
	r, attempts, err := appsecurity.CreateRecord(pin, fullReentry, p.binding, material)
	if err != nil {
		p.closed = true
		if p.lifecycle.RetireOwners() != nil {
			return nil, errPINLifecycle
		}
		return nil, err
	}
	record, err := r.Encode()
	if err != nil {
		p.closed = true
		_ = p.lifecycle.RetireOwners()
		return nil, err
	}
	return json.Marshal(struct {
		Profile  string                   `json:"profile"`
		Record   string                   `json:"recordBase64"`
		Attempts appsecurity.AttemptState `json:"attempts"`
	}{"harmonia/native-pin-provision/v1", base64.RawURLEncoding.EncodeToString(record), attempts})
}

func strictPINJSON(data []byte, limit int, into any) error {
	if cryptox.ValidateStrictJSON(data, limit) != nil {
		return appsecurity.ErrState
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(into) != nil {
		return appsecurity.ErrState
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return appsecurity.ErrState
	}
	return nil
}

type localPINAttempts struct{ native LocalPINStore }

func (s localPINAttempts) Acquire() error { return s.native.Acquire() }
func (s localPINAttempts) Release() error { return s.native.Release() }
func pinAttemptsBounded(a appsecurity.AttemptState) bool {
	return a.Revision > 0 && a.Revision <= math.MaxInt64 && a.Total <= math.MaxInt64 && a.Failures <= math.MaxInt64
}
func (s localPINAttempts) Load() (appsecurity.AttemptState, error) {
	var a appsecurity.AttemptState
	raw, err := s.native.LoadAttempts()
	if err != nil {
		return a, err
	}
	if strictPINJSON([]byte(raw), 1024, &a) != nil || !pinAttemptsBounded(a) {
		return a, appsecurity.ErrState
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &fields) != nil {
		return a, appsecurity.ErrState
	}
	for _, key := range []string{"revision", "recordHash", "total", "failures", "delaySeconds"} {
		if _, ok := fields[key]; !ok {
			return a, appsecurity.ErrState
		}
	}
	for key := range fields {
		if key != "revision" && key != "recordHash" && key != "total" && key != "failures" && key != "pendingAttempt" && key != "delaySeconds" {
			return a, appsecurity.ErrState
		}
	}
	return a, nil
}
func (s localPINAttempts) Commit(expected uint64, next appsecurity.AttemptState) error {
	if expected == 0 || expected > math.MaxInt64 || !pinAttemptsBounded(next) {
		return appsecurity.ErrState
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return appsecurity.ErrState
	}
	return s.native.CommitAttempts(int64(expected), string(raw))
}

type localPINSealed struct{ native LocalPINStore }

func (s localPINSealed) SaveSealed(packet []byte) error { return s.native.SaveWorkflowSealed(packet) }

func pinIntent(binding appsecurity.Binding, raw, short []byte, mode string) (string, string, error) {
	c, err := parseWorkflowCommand(string(raw))
	if err != nil || c.endpoint != binding.Endpoint || recoveryOperation(c.operation) {
		return "", "", errInput
	}
	approval := c.operation == "approvePairing" || c.operation == "approvePairingV3" || c.operation == "approvePairingV4"
	enrollment := c.operation == "enrollDeviceV3"
	if mode == "approval" && !approval || mode == "enrollment" && !enrollment || mode == "" && (approval || enrollment) {
		return "", "", errInput
	}
	if approval || enrollment {
		if len(short) != 8 {
			return "", "", errInput
		}
		for _, b := range short {
			if b < '0' || b > '9' {
				return "", "", errInput
			}
		}
		if approval {
			if _, err = parseApprovalSelections(c.fields["selections"]); err != nil {
				return "", "", errInput
			}
		}
	} else if len(short) != 0 {
		return "", "", errInput
	}
	fields := make(map[string]any, len(c.fields)+3)
	fields["version"] = 1
	fields["operation"] = c.operation
	fields["endpoint"] = c.endpoint
	for key, value := range c.fields {
		fields[key] = value
	}
	canonical, err := json.Marshal(fields)
	if err != nil {
		return "", "", errInput
	}
	intent, _ := json.Marshal([]any{"harmonia/native-pin-operation/v1", binding, mode, string(canonical), string(short)})
	hash := sha256.Sum256(intent)
	clear(intent)
	return string(canonical), hex.EncodeToString(hash[:]), nil
}

// Execute 系列仅消费本次 PIN one-use lease，不返回 Go Device 或 lease。
// Recovery process owner 尚未接，所有 recovery operation 显式拒绝，不降级。
func (p *LocalPINCore) Execute(pin, completeIntent, record, sealedWorkflow, nativeCA []byte, store LocalPINStore) (string, error) {
	return p.execute(pin, completeIntent, nil, record, sealedWorkflow, nativeCA, store, "")
}
func (p *LocalPINCore) ExecuteApproval(pin, completeIntent, shortCode, record, sealedWorkflow, nativeCA []byte, store LocalPINStore) (string, error) {
	return p.execute(pin, completeIntent, shortCode, record, sealedWorkflow, nativeCA, store, "approval")
}
func (p *LocalPINCore) ExecuteEnrollment(pin, completeIntent, shortCode, record, sealedWorkflow, nativeCA []byte, store LocalPINStore) (string, error) {
	return p.execute(pin, completeIntent, shortCode, record, sealedWorkflow, nativeCA, store, "enrollment")
}

func (p *LocalPINCore) execute(pin, input, short, record, sealed, ca []byte, store LocalPINStore, mode string) (out string, err error) {
	defer clear(pin)
	defer clear(input)
	defer clear(short)
	if p == nil {
		return "", appsecurity.ErrClosed
	}
	if !p.mu.TryLock() {
		p.cancelOperation()
		if p.lifecycle.RetireOwners() != nil {
			return "", errPINLifecycle
		}
		return "", appsecurity.ErrBusy
	}
	defer p.mu.Unlock()
	defer func() {
		if err != nil && p.lifecycle.RetireOwners() != nil {
			p.closed = true
			err = errPINLifecycle
			out = ""
		}
	}()
	if p.closed || !p.created || store == nil {
		return "", appsecurity.ErrClosed
	}
	ownedPIN, ownedInput, ownedShort := bytes.Clone(pin), bytes.Clone(input), bytes.Clone(short)
	defer clear(ownedPIN)
	defer clear(ownedInput)
	defer clear(ownedShort)
	command, operationHash, err := pinIntent(p.binding, ownedInput, ownedShort, mode)
	if err != nil || len(sealed) > maxState+8192 || len(ca) > 2<<20 {
		return "", errInput
	}
	r, err := appsecurity.DecodeRecord(record, p.binding)
	if err != nil {
		return "", err
	}
	canonicalRecord, err := r.Encode()
	if err != nil || !bytes.Equal(record, canonicalRecord) {
		return "", appsecurity.ErrRecord
	}
	duration := 30 * time.Second
	if mode != "" {
		duration = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	p.cancelMu.Lock()
	p.cancel = cancel
	p.cancelMu.Unlock()
	defer func() { cancel(); p.cancelMu.Lock(); p.cancel = nil; p.cancelMu.Unlock() }()
	var retirementFailed atomic.Bool
	provider, err := appsecurity.NewProvider(r, p.binding, localPINAttempts{store}, func() {
		if p.lifecycle.RetireOwners() != nil {
			retirementFailed.Store(true)
		}
	})
	if err != nil {
		return "", err
	}
	defer provider.Close()
	lease, err := provider.Unlock(ctx, ownedPIN, operationHash)
	if err != nil {
		if retirementFailed.Load() {
			p.closed = true
			return "", errPINLifecycle
		}
		return "", err
	}
	defer lease.Close()
	ns, _ := json.Marshal([]any{"harmonia/native-pin-workflow/v1", p.binding})
	nsHash := sha256.Sum256(ns)
	workflowNamespace := "harmonia/native-pin-workflow/v1:" + hex.EncodeToString(nsHash[:])
	err = lease.Consume(ctx, p.binding, operationHash, func(operationCtx context.Context, material []byte) error {
		d, e := ImportProtectedMaterial(material)
		if e != nil {
			return e
		}
		defer d.Close()
		v, e := d.OpenWorkflow(p.binding.Endpoint, workflowNamespace, sealed, ca, localPINSealed{store})
		if e != nil {
			return e
		}
		defer v.Close()
		stop := context.AfterFunc(operationCtx, v.Cancel)
		defer stop()
		if e = operationCtx.Err(); e != nil {
			return e
		}
		switch mode {
		case "approval":
			out, e = v.ExecuteApproval(command, ownedShort)
		case "enrollment":
			out, e = v.ExecuteEnrollment(command, ownedShort)
		default:
			out, e = v.Execute(command)
		}
		if e != nil {
			return e
		}
		var result map[string]any
		if json.Unmarshal([]byte(out), &result) != nil {
			return errInput
		}
		if v.RequiresDeviceDeletion() {
			p.closed = true
			result["requiresDeviceDeletion"] = true
			out, e = encode(result)
		}
		if result["ok"] != true || v.RequiresDeviceDeletion() {
			if p.lifecycle.RetireOwners() != nil {
				return errPINLifecycle
			}
		}
		return e
	})
	if retirementFailed.Load() {
		p.closed = true
		return "", errPINLifecycle
	}
	if err != nil {
		out = ""
	}
	return out, err
}

// Cancel/Close 同步关闭本实例，取消正在执行的成熟 workflow，并退役原生
// Recovery owners。保存或清理失败不能报告持久成功；磁盘删除由固定原生清理完成。
func (p *LocalPINCore) Close() error {
	if p == nil {
		return nil
	}
	p.cancelOperation()
	err := p.lifecycle.RetireOwners()
	p.mu.Lock()
	p.closed = true
	if p.setup != nil {
		p.setup.Close()
		p.setup = nil
	}
	p.mu.Unlock()
	if err != nil {
		return errPINLifecycle
	}
	return nil
}
func (p *LocalPINCore) Cancel() error { return p.Close() }
func (p *LocalPINCore) cancelOperation() {
	p.cancelMu.Lock()
	defer p.cancelMu.Unlock()
	if p.cancel != nil {
		p.cancel()
	}
}
