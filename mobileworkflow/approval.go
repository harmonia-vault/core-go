package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/pairing"
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrApprovalPending = errors.New("original approval result pending; only explicit original query/retry or logout allowed")
var ErrApprovalEvidence = errors.New("initial root environment authority evidence required")

// ApprovalInput 只能由系统认证后的原生层构造，Selections 为用户明确选择。
// ShortCode 不允许 JSON 序列化；只交给本机成熟 SPAKE2，不发送网络或存储。
type ApprovalInput struct {
	PairingID  string
	ShortCode  []byte `json:"-"`
	Selections []ApprovalSelection
}
type ApprovalSelection struct {
	EnvironmentID string `json:"environmentId"`
	Role          string `json:"role"`
	ExpiresAt     string `json:"expiresAt"`
}
type ApprovalResult struct {
	State     string `json:"state"`
	PairingID string `json:"pairingId"`
	DeviceID  string `json:"deviceId,omitempty"`
	Sequence  uint64 `json:"sequence,omitempty"`
}
type ApprovalInfo struct {
	State      string              `json:"state"`
	PairingID  string              `json:"pairingId,omitempty"`
	DeviceID   string              `json:"deviceId,omitempty"`
	Selections []ApprovalSelection `json:"selections,omitempty"`
	ExpiresAt  string              `json:"expiresAt,omitempty"`
	Sequence   uint64              `json:"sequence,omitempty"`
}
type approvalRecord struct {
	Version             int                          `json:"version"`
	SessionEpoch        uint64                       `json:"sessionEpoch"`
	PairingID           string                       `json:"pairingId"`
	ChoicesHash         string                       `json:"choicesHash"`
	CreatedAt           int64                        `json:"createdAt"`
	Attempted           bool                         `json:"attempted"`
	Approval            cryptox.EnrollmentApprovalV2 `json:"approval"`
	Sequence            uint64                       `json:"sequence,omitempty"`
	CompletionSignature string                       `json:"completionSignature,omitempty"`
}

func choicesHash(id string, choices []ApprovalSelection) (string, error) {
	if !identifier.MatchString(id) || len(choices) < 1 || len(choices) > 16 {
		return "", errors.New("explicit approval selections required")
	}
	ordered := append([]ApprovalSelection(nil), choices...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].EnvironmentID < ordered[j].EnvironmentID })
	rows := make([][]string, 0, len(ordered))
	for i, s := range ordered {
		n, err := strconv.ParseUint(s.ExpiresAt, 10, 64)
		if !identifier.MatchString(s.EnvironmentID) || i > 0 && ordered[i-1].EnvironmentID == s.EnvironmentID || s.Role != "ro" && s.Role != "rw" && s.Role != "admin" || err != nil || strconv.FormatUint(n, 10) != s.ExpiresAt || n > 253402300799 {
			return "", errors.New("approval role/expiry/environment invalid")
		}
		rows = append(rows, []string{s.EnvironmentID, s.Role, s.ExpiresAt})
	}
	b, _ := json.Marshal([]any{"harmonia/local-approval-choices/v1", id, rows})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func approvalSelections(r *approvalRecord) []ApprovalSelection {
	out := make([]ApprovalSelection, 0, len(r.Approval.Grants))
	for _, s := range r.Approval.Grants {
		g := s.Grant
		out = append(out, ApprovalSelection{g.EnvironmentID, g.Role, g.ExpiresAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnvironmentID < out[j].EnvironmentID })
	return out
}
func (w *Workflow) validateInitialAuthorities() error {
	if len(w.state.InitialAuthorities) == 0 {
		return nil
	}
	if w.state.Root == nil || len(w.state.InitialAuthorities) > 16 {
		return ErrApprovalEvidence
	}
	seen := map[string]bool{}
	for _, s := range w.state.InitialAuthorities {
		g := s.Grant
		if g.AccountID != w.state.AccountID || g.AccountGeneration != w.state.AccountGeneration || g.IssuerDeviceID != w.state.DeviceID || g.SubjectDeviceID != w.state.DeviceID || g.SubjectSigningPublicKey != w.state.SigningPublicKey || g.SubjectReceivingPublicKey != w.state.ReceivingPublicKey || g.KeyVersion != "1" || g.GrantGeneration != "1" || g.Role != "admin" || g.ExpiresAt != "0" || seen[g.EnvironmentID] || cryptox.VerifyGrant(s.SignedGrant(), w.signing.Public().(ed25519.PublicKey)) != nil {
			return ErrApprovalEvidence
		}
		seen[g.EnvironmentID] = true
	}
	return nil
}
func (w *Workflow) initialAuthority(env string) (cryptox.SignedGrantWire, error) {
	for _, g := range w.state.InitialAuthorities {
		if g.Grant.EnvironmentID == env {
			return g, nil
		}
	}
	return cryptox.SignedGrantWire{}, ErrApprovalEvidence
}
func sameSignedGrant(a, b cryptox.SignedGrantWire) bool {
	x, e := cryptox.IssuerAuthorityHash(a)
	y, f := cryptox.IssuerAuthorityHash(b)
	return e == nil && f == nil && x == y
}
func (w *Workflow) validateApprovalRecord(r *approvalRecord) error {
	if r == nil {
		return nil
	}
	if w.state.Root == nil || w.state.Cloud.AccountClosed || len(w.state.SelfRevocation) > 0 || r.Version != 1 || r.SessionEpoch != w.engine.State().SessionEpoch || r.CreatedAt <= 0 || r.Approval.InitiatorSignature != "" || r.Approval.Context.ApproverDeviceID != w.state.DeviceID || r.Approval.Context.ApproverSigningPublicKey != w.state.SigningPublicKey || r.Approval.Context.ApproverReceivingPublicKey != w.state.ReceivingPublicKey || r.Approval.Context.AccountID != w.state.AccountID || r.Approval.Context.AccountGeneration != w.state.AccountGeneration || len(r.Approval.IssuerProof.Path) != 0 {
		return errors.New("protected approval exact manager/account/epoch invalid")
	}
	expiry, expiryErr := strconv.ParseInt(r.Approval.Context.ExpiresAt, 10, 64)
	if expiryErr != nil || r.CreatedAt >= expiry || expiry-r.CreatedAt > 120 || r.CreatedAt > w.now().Unix()+5 {
		return errors.New("protected approval deadline/creation binding invalid")
	}
	h, err := choicesHash(r.PairingID, approvalSelections(r))
	if err != nil || h != r.ChoicesHash {
		return errors.New("protected approval choices changed")
	}
	raw, err := json.Marshal(r.Approval)
	if err != nil {
		return err
	}
	if _, err = cryptox.DecodeEnrollmentApprovalV2(raw); err != nil {
		return err
	}
	anchor := cryptox.ConfirmedEnrollmentAnchor{Context: r.Approval.Context, TranscriptHash: r.Approval.TranscriptHash}
	if _, err = cryptox.VerifyHistoricalEnrollmentApprovalV2(anchor, r.Approval); err != nil {
		return err
	}
	root := r.Approval.IssuerProof.TrustRoot
	if root.RootDeviceID != w.state.Root.RootDeviceID || root.RootSigningPublicKey != w.state.Root.RootSigningPublicKey || root.RootReceivingPublicKey != w.state.Root.RootReceivingPublicKey {
		return ErrApprovalEvidence
	}
	if len(r.Approval.IssuerProof.Authorities) != len(r.Approval.Grants) {
		return ErrApprovalEvidence
	}
	for _, source := range r.Approval.IssuerProof.Authorities {
		initial, err := w.initialAuthority(source.Grant.Grant.EnvironmentID)
		if err != nil || source.ParentHash != "" || !sameSignedGrant(initial, source.Grant) {
			return ErrApprovalEvidence
		}
	}
	if r.Sequence != 0 {
		if !r.Attempted || r.Sequence > 9007199254740991 || r.CompletionSignature == "" {
			return errors.New("protected approval completion invalid")
		}
		a := r.Approval
		a.InitiatorSignature = r.CompletionSignature
		if _, err = cryptox.VerifyCompletedEnrollmentV2(anchor, a); err != nil {
			return err
		}
	} else if r.CompletionSignature != "" {
		return errors.New("approval signature without completion")
	}
	return nil
}
func (w *Workflow) currentApprovalAuthorities(r *approvalRecord) error {
	if w.state.Root == nil || w.engine.State().AccountClosed {
		return ErrNotTrusted
	}
	for _, s := range approvalSelections(r) {
		g, err := w.grant(s.EnvironmentID)
		if err != nil || g.Role != "admin" {
			return localstate.ErrUnauthorized
		}
		initial, err := w.initialAuthority(s.EnvironmentID)
		if err != nil {
			return err
		}
		matched := false
		for _, cur := range w.state.Grants {
			if cur.Grant.EnvironmentID == s.EnvironmentID && cur.Grant.SubjectDeviceID == w.state.DeviceID && sameSignedGrant(cur, initial) {
				matched = true
			}
		}
		if !matched {
			return ErrApprovalEvidence
		}
		if s.ExpiresAt != "0" {
			expiry, _ := strconv.ParseInt(s.ExpiresAt, 10, 64)
			if expiry <= w.now().Unix() {
				return pairing.ErrExpired
			}
		}
	}
	return nil
}
func (w *Workflow) ApprovalInfo() (ApprovalInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.approvalV4Pending() {
		return ApprovalInfo{}, ErrApprovalPending
	}
	if w.closed {
		return ApprovalInfo{}, ErrClosed
	}
	if len(w.state.SelfRevocation) > 0 {
		return ApprovalInfo{}, ErrSelfRevocationPending
	}
	if w.state.Recovery != nil {
		return ApprovalInfo{}, ErrRecoveryRestricted
	}
	if w.enrollmentPending() {
		return ApprovalInfo{}, ErrMobileEnrollmentPending
	}
	if w.state.PendingApprovalV3 != nil && w.state.PendingApprovalV3.Sequence == 0 {
		return ApprovalInfo{}, ErrApprovalPending
	}
	r := w.state.PendingApproval
	if r == nil {
		return ApprovalInfo{State: "none"}, nil
	}
	if err := w.validateApprovalRecord(r); err != nil {
		return ApprovalInfo{}, err
	}
	state := "prepared"
	if r.Attempted {
		state = "unknown"
	}
	if r.Sequence != 0 {
		state = "complete"
	} else if expiry, _ := strconv.ParseInt(r.Approval.Context.ExpiresAt, 10, 64); expiry <= w.now().Unix() {
		state = "expired-pending"
	}
	return ApprovalInfo{State: state, PairingID: r.PairingID, DeviceID: r.Approval.Context.InitiatorDeviceID, Selections: approvalSelections(r), ExpiresAt: r.Approval.Context.ExpiresAt, Sequence: r.Sequence}, nil
}
func (w *Workflow) approvalResult(r *approvalRecord, state string) ApprovalResult {
	return ApprovalResult{State: state, PairingID: r.PairingID, DeviceID: r.Approval.Context.InitiatorDeviceID, Sequence: r.Sequence}
}
func (w *Workflow) acceptApprovalStatus(r *approvalRecord, client *syncclient.ApproverV2, s syncclient.PairingStatusV2) (ApprovalResult, error) {
	if err := client.MatchApproval(s, r.Approval); err != nil {
		return w.approvalResult(r, "unknown"), errors.Join(ErrApprovalPending, err)
	}
	if s.State != "complete" {
		return w.approvalResult(r, "approved"), nil
	}
	oldSeq, oldSig := r.Sequence, r.CompletionSignature
	r.Sequence = *s.Sequence
	r.CompletionSignature = s.Approval.InitiatorSignature
	if err := w.persist(); err != nil {
		r.Sequence = oldSeq
		r.CompletionSignature = oldSig
		return w.approvalResult(r, "unknown"), errors.Join(ErrApprovalPending, err)
	}
	return w.approvalResult(r, "complete"), nil
}

// ApprovePairing 是一次系统认证后的完整原生操作；输入短码只在当前调用存活。
func (w *Workflow) ApprovePairing(ctx context.Context, input ApprovalInput) (ApprovalResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.approvalV4Pending() {
		return ApprovalResult{}, ErrApprovalPending
	}
	if w.closed {
		return ApprovalResult{}, ErrClosed
	}
	if len(w.state.SelfRevocation) > 0 {
		return ApprovalResult{}, ErrSelfRevocationPending
	}
	if w.state.Recovery != nil {
		return ApprovalResult{}, ErrRecoveryRestricted
	}
	if w.enrollmentPending() {
		return ApprovalResult{}, ErrMobileEnrollmentPending
	}
	if w.state.PendingApprovalV3 != nil && w.state.PendingApprovalV3.Sequence == 0 {
		return ApprovalResult{}, ErrApprovalPending
	}
	fingerprint, err := choicesHash(input.PairingID, input.Selections)
	if err != nil {
		return ApprovalResult{}, err
	}
	if old := w.state.PendingApproval; old != nil && old.Sequence == 0 {
		if old.PairingID != input.PairingID || old.ChoicesHash != fingerprint {
			return ApprovalResult{}, syncclient.ErrWriteConflict
		}
		return w.approvalResult(old, "unknown"), ErrApprovalPending
	}
	if !pairing.NativeAvailable() {
		return ApprovalResult{}, pairing.ErrUnavailable
	}
	if len(input.ShortCode) != 8 {
		return ApprovalResult{}, pairing.ErrContext
	}
	for _, b := range input.ShortCode {
		if b < '0' || b > '9' {
			return ApprovalResult{}, pairing.ErrContext
		}
	}
	if len(w.state.InitialAuthorities) == 0 {
		return ApprovalResult{}, ErrApprovalEvidence
	}
	if err = w.refresh(ctx); err != nil {
		return ApprovalResult{}, err
	}
	// 先验证所有显式选项和当前精确来源，避免做完PAKE后才发现本地无权。
	checkRecord := &approvalRecord{Approval: cryptox.EnrollmentApprovalV2{Grants: make([]cryptox.SignedGrantWire, 0, len(input.Selections))}}
	for _, s := range input.Selections {
		checkRecord.Approval.Grants = append(checkRecord.Approval.Grants, cryptox.SignedGrantWire{Grant: cryptox.Grant{EnvironmentID: s.EnvironmentID, Role: s.Role, ExpiresAt: s.ExpiresAt}})
	}
	if err = w.currentApprovalAuthorities(checkRecord); err != nil {
		return ApprovalResult{}, err
	}
	approver, err := w.client.NewApproverV2(input.PairingID, w.signing)
	if err != nil {
		return ApprovalResult{}, err
	}
	defer approver.Close()
	anchor, err := approver.Confirm(ctx, input.ShortCode)
	if err != nil {
		return ApprovalResult{}, err
	}
	if err = w.refresh(ctx); err != nil {
		return ApprovalResult{}, err
	}
	if err = w.currentApprovalAuthorities(checkRecord); err != nil {
		return ApprovalResult{}, err
	}
	proof := cryptox.IssuerProof{Profile: cryptox.IssuerProofProfile, AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, TrustRoot: *w.state.Root, Path: []cryptox.IssuerEnrollment{}, Authorities: []cryptox.IssuerAuthority{}, Targets: []cryptox.IssuerTarget{}}
	approval := cryptox.EnrollmentApprovalV2{CertificateVersion: "2", Context: anchor.Context, PairingProfile: pairing.Profile, TranscriptHash: anchor.TranscriptHash, Grants: []cryptox.SignedGrantWire{}}
	ordered := append([]ApprovalSelection(nil), input.Selections...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].EnvironmentID < ordered[j].EnvironmentID })
	for i, s := range ordered {
		source, err := w.initialAuthority(s.EnvironmentID)
		if err != nil {
			return ApprovalResult{}, err
		}
		h, err := cryptox.IssuerAuthorityHash(source)
		if err != nil {
			return ApprovalResult{}, err
		}
		key, err := w.environmentKey(s.EnvironmentID)
		if err != nil {
			return ApprovalResult{}, err
		}
		envelope, e := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: s.EnvironmentID, KeyVersion: source.Grant.KeyVersion, RecipientType: "device", RecipientID: anchor.Context.InitiatorDeviceID, RecipientGeneration: "1", RecipientPublicKey: anchor.Context.InitiatorReceivingPublicKey})
		clear(key)
		if e != nil {
			return ApprovalResult{}, e
		}
		// 操作ID从原配对ID摘要与排序索引生成，不包含短码/值，不会在未知重试重建。
		idSum := sha256.Sum256([]byte(input.PairingID))
		id := "pair-grant-" + hex.EncodeToString(idSum[:16]) + "-" + strconv.Itoa(i)
		g := cryptox.Grant{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, IssuerDeviceID: w.state.DeviceID, SubjectDeviceID: anchor.Context.InitiatorDeviceID, SubjectSigningPublicKey: anchor.Context.InitiatorSigningPublicKey, SubjectReceivingPublicKey: anchor.Context.InitiatorReceivingPublicKey, EnvironmentID: s.EnvironmentID, KeyVersion: source.Grant.KeyVersion, GrantGeneration: "1", Role: s.Role, ExpiresAt: s.ExpiresAt, IdempotencyKey: id, Envelope: cryptox.EncodeBase64(envelope)}
		signed, e := cryptox.SignGrant(g, w.signing)
		if e != nil {
			return ApprovalResult{}, e
		}
		approval.Grants = append(approval.Grants, cryptox.GrantToWire(signed))
		proof.Authorities = append(proof.Authorities, cryptox.IssuerAuthority{Grant: source, ParentHash: ""})
		proof.Targets = append(proof.Targets, cryptox.IssuerTarget{EnvironmentID: s.EnvironmentID, AuthorityHash: h})
	}
	approval.IssuerProof = proof
	rootPin := cryptox.PinnedIssuerRoot{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, DeviceID: w.state.Root.RootDeviceID, SigningPublicKey: w.state.Root.RootSigningPublicKey, ReceivingPublicKey: w.state.Root.RootReceivingPublicKey}
	approval, err = cryptox.SignEnrollmentApprovalV2(approval, rootPin, anchor, w.signing, w.now())
	if err != nil {
		return ApprovalResult{}, err
	}
	record := &approvalRecord{Version: 1, SessionEpoch: w.engine.State().SessionEpoch, PairingID: input.PairingID, ChoicesHash: fingerprint, CreatedAt: w.now().Unix(), Approval: approval}
	w.state.PendingApproval = record
	if err = w.persist(); err != nil {
		return w.approvalResult(record, "unknown"), err
	}
	return w.retryApproval(ctx, record)
}
func (w *Workflow) RetryApproval(ctx context.Context, id string) (ApprovalResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.approvalV4Pending() {
		return ApprovalResult{}, ErrApprovalPending
	}
	if w.closed {
		return ApprovalResult{}, ErrClosed
	}
	if len(w.state.SelfRevocation) > 0 {
		return ApprovalResult{}, ErrSelfRevocationPending
	}
	if w.state.Recovery != nil {
		return ApprovalResult{}, ErrRecoveryRestricted
	}
	if w.enrollmentPending() {
		return ApprovalResult{}, ErrMobileEnrollmentPending
	}
	if w.state.PendingApprovalV3 != nil && w.state.PendingApprovalV3.Sequence == 0 {
		return ApprovalResult{}, ErrApprovalPending
	}
	r := w.state.PendingApproval
	if r == nil || r.PairingID != id {
		return ApprovalResult{}, syncclient.ErrWriteConflict
	}
	return w.retryApproval(ctx, r)
}
func (w *Workflow) retryApproval(ctx context.Context, r *approvalRecord) (ApprovalResult, error) {
	unknown := w.approvalResult(r, "unknown")
	if err := w.validateApprovalRecord(r); err != nil {
		return unknown, err
	}
	if r.Sequence != 0 {
		return w.approvalResult(r, "complete"), nil
	}
	if w.client == nil {
		if err := w.boot(ctx); err != nil {
			return unknown, errors.Join(ErrApprovalPending, err)
		}
	}
	approver, err := w.client.NewApproverV2(r.PairingID, w.signing)
	if err != nil {
		return unknown, err
	}
	defer approver.Close()
	if err = approver.BindProtectedApproval(r.Approval); err != nil {
		return unknown, err
	}
	status, err := approver.Query(ctx)
	// 一个设备会话失效可以重新持钥boot；只查询原context，不改变签包或配对会话。
	var fault *syncclient.RequestError
	if errors.As(err, &fault) && fault.Status == 401 && fault.Code == "unauthorized" {
		if err = w.boot(ctx); err == nil {
			approver.Close()
			approver, err = w.client.NewApproverV2(r.PairingID, w.signing)
			if err == nil {
				defer approver.Close()
				err = approver.BindProtectedApproval(r.Approval)
				if err == nil {
					status, err = approver.Query(ctx)
				}
			}
		}
	}
	if err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			return unknown, errors.Join(err, w.invalidateTrust())
		}
		return unknown, errors.Join(ErrApprovalPending, err)
	}
	if status.Approval != nil {
		return w.acceptApprovalStatus(r, approver, status)
	}
	if err = w.refreshForApproval(ctx); err != nil {
		return unknown, errors.Join(ErrApprovalPending, err)
	}
	if err = w.currentApprovalAuthorities(r); err != nil {
		return unknown, errors.Join(ErrApprovalPending, err)
	}
	if err = ctx.Err(); err != nil {
		return unknown, err
	}
	// attempted先真正密封，再发POST；未知结果不能用一次空status查询证明可取消。
	r.Attempted = true
	if err = w.persist(); err != nil {
		return unknown, err
	}
	status, err = approver.Submit(ctx, r.Approval)
	if err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			return unknown, errors.Join(err, w.invalidateTrust())
		}
		return unknown, errors.Join(ErrApprovalPending, err)
	}
	return w.acceptApprovalStatus(r, approver, status)
}

// CancelApproval 只清理确定尚未尝试HTTP发送的prepared记录；在途/未知记录
// 缺少服务端终止栅栏，必须保留门槛而不能以本地取消冒充服务器撤销。
func (w *Workflow) CancelApproval(id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.approvalV4Pending() {
		return ErrApprovalPending
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
	if w.enrollmentPending() {
		return ErrMobileEnrollmentPending
	}
	if w.state.PendingApprovalV3 != nil && w.state.PendingApprovalV3.Sequence == 0 {
		return ErrApprovalPending
	}
	r := w.state.PendingApproval
	if r == nil || r.PairingID != id {
		return syncclient.ErrWriteConflict
	}
	if r.Attempted || r.Sequence != 0 {
		return ErrApprovalPending
	}
	w.state.PendingApproval = nil
	if err := w.persist(); err != nil {
		w.state.PendingApproval = r
		return err
	}
	return nil
}

// 用于测试/原生封装的原包比较，不返回包或会话给界面。
func sameApprovalPackage(a, b cryptox.EnrollmentApprovalV2) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
