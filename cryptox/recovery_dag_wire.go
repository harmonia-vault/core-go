package cryptox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strconv"
)

const (
	RecoveryDAGCapability     = "issuer-recovery-dag-v1"
	IssuerRecoveryDAGProfile  = "harmonia/issuer-proof/v4"
	RecoverySourceViewProfile = "harmonia/issuer-proof/v3-source/v1"
	MaxRecoveryDAGNodes       = 256
	MaxRecoveryDAGEdges       = 8192
)

// 来源是有界叶；不允许在此嵌入完整 DAG 或其它来源。
type RecoverySource struct {
	Kind  string              `json:"kind"`
	Proof *IssuerProofV2      `json:"proof,omitempty"`
	View  *RecoverySourceView `json:"view,omitempty"`
}
type RecoveryDependency struct {
	Kind          string `json:"kind"`
	ReferenceHash string `json:"referenceHash"`
}
type RecoverySourceView struct {
	Profile            string                    `json:"profile"`
	AccountID          string                    `json:"accountId"`
	AccountGeneration  string                    `json:"accountGeneration"`
	InitializationHash string                    `json:"initializationHash"`
	TrustRoot          TrustRoot                 `json:"trustRoot"`
	RecoveryHeadHash   string                    `json:"recoveryHeadHash"`
	Path               []IssuerRecoveryArchive   `json:"path"`
	Authorities        []IssuerRecoveryAuthority `json:"authorities"`
	Targets            []IssuerTarget            `json:"targets"`
	Origins            []SignedEnvironmentOrigin `json:"origins"`
	IdentityPaths      [][]IssuerRecoveryArchive `json:"identityPaths"`
	Dependencies       []RecoveryDependency      `json:"dependencies"`
}
type RecoveryAuthorityTransitionV2 RecoveryAuthorityTransition
type RecoveryTransitionSubmissionV2 struct {
	Transition             RecoveryAuthorityTransitionV2 `json:"transition"`
	EnvironmentManifest    []RecoveryEnvironmentVersion  `json:"environmentManifest"`
	AuthoritySet           []RecoveryAdminAuthority      `json:"authoritySet"`
	IssuerEvidence         *RecoverySource               `json:"issuerEvidence"`
	Envelopes              []RecoveryEnvelope            `json:"envelopes"`
	NewTrustRoot           TrustRoot                     `json:"newTrustRoot"`
	LegacyState            *RecoveryLegacyState          `json:"legacyState"`
	AuthorizationSignature string                        `json:"authorizationSignature"`
	NewRecoverySignature   string                        `json:"newRecoverySignature"`
}
type AcceptedRecoveryTransitionV2 struct {
	Submission RecoveryTransitionSubmissionV2 `json:"submission"`
	Sequence   uint64                         `json:"sequence"`
}
type RecoveredDeviceEnrollmentV2 RecoveredDeviceEnrollment
type RecoveredDeviceSubmissionV2 struct {
	CertificateVersion string                      `json:"certificateVersion"`
	Capabilities       []string                    `json:"capabilities"`
	Enrollment         RecoveredDeviceEnrollmentV2 `json:"enrollment"`
	SelectedRights     []RecoveredDeviceRight      `json:"selectedRights"`
	Grants             []SignedGrantWire           `json:"grants"`
	IssuerEvidence     RecoverySource              `json:"issuerEvidence"`
	Envelopes          []RecoveryEnvelope          `json:"envelopes"`
	RecoverySignature  string                      `json:"recoverySignature"`
	DeviceSignature    string                      `json:"deviceSignature"`
}
type AcceptedRecoveredDeviceV2 struct {
	Submission RecoveredDeviceSubmissionV2 `json:"submission"`
	Sequence   uint64                      `json:"sequence"`
}

// Record 各分支只保留自己的类型。JSON 始终是 exact {kind,record}。
type RecoveryDAGRecord struct {
	Kind         string
	TransitionV1 *AcceptedRecoveryTransition
	RecoveredV1  *AcceptedRecoveredDevice
	TransitionV2 *AcceptedRecoveryTransitionV2
	RecoveredV2  *AcceptedRecoveredDeviceV2
}
type RecoveryDependencyBundle struct {
	Initialization OriginalInitialization `json:"initialization"`
	Records        []RecoveryDAGRecord    `json:"records"`
}
type IssuerRecoveryDAG struct {
	Profile           string                 `json:"profile"`
	AccountID         string                 `json:"accountId"`
	AccountGeneration string                 `json:"accountGeneration"`
	Initialization    OriginalInitialization `json:"initialization"`
	Source            RecoverySource         `json:"source"`
	Records           []RecoveryDAGRecord    `json:"records"`
}
type RecoveryTransitionCommandV2 struct {
	Submission       RecoveryTransitionSubmissionV2 `json:"submission"`
	DependencyBundle RecoveryDependencyBundle       `json:"dependencyBundle"`
}
type RecoveredDeviceCommandV2 struct {
	Submission       RecoveredDeviceSubmissionV2 `json:"submission"`
	DependencyBundle RecoveryDependencyBundle    `json:"dependencyBundle"`
}
type EnrollmentCertificateV5 struct {
	EnrollmentCertificate
	IssuerProofHash string `json:"issuerProofHash"`
}

func replaceRecoveryDomain(b []byte, domain string, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	var fields []string
	if json.Unmarshal(b, &fields) != nil || len(fields) == 0 {
		return nil, ErrInvalidWire
	}
	fields[0] = domain
	return json.Marshal(fields)
}
func (t RecoveryAuthorityTransitionV2) SigningBytes() ([]byte, error) {
	b, e := (RecoveryAuthorityTransition(t)).SigningBytes()
	return replaceRecoveryDomain(b, "harmonia/recovery-authority-transition/v2", e)
}
func (c RecoveredDeviceEnrollmentV2) SigningBytes() ([]byte, error) {
	b, e := (RecoveredDeviceEnrollment(c)).SigningBytes()
	return replaceRecoveryDomain(b, "harmonia/recovered-device-enrollment/v2", e)
}
func (c EnrollmentCertificateV5) SigningBytes() ([]byte, error) {
	b, e := (EnrollmentCertificateV4{c.EnrollmentCertificate, c.IssuerProofHash}).SigningBytes()
	return replaceRecoveryDomain(b, "harmonia/device-enrollment/v5", e)
}
func SignEnrollmentCertificateV5(c EnrollmentCertificateV5, key ed25519.PrivateKey) (string, error) {
	b, e := c.SigningBytes()
	if e != nil {
		return "", e
	}
	if len(key) != ed25519.PrivateKeySize {
		return "", ErrInvalidWire
	}
	pub := EncodeBase64(key.Public().(ed25519.PublicKey))
	if pub != c.ApproverSigningPublicKey && pub != c.InitiatorSigningPublicKey {
		return "", ErrInvalidSignature
	}
	return signRecoveryPurpose(key, pub, b)
}
func dagArchiveBytes(n IssuerEnrollment) ([]byte, error) {
	if n.CertificateVersion != "5" {
		return issuerRecoveryArchiveBytes(n)
	}
	c, e := n.Approval.Certificate()
	if e != nil {
		return nil, e
	}
	return (EnrollmentCertificateV5{c, n.IssuerProofHash}).SigningBytes()
}
func dagPathRows(path []IssuerRecoveryArchive) ([][]string, error) {
	if path == nil || len(path) > MaxIssuerProofPath {
		return nil, ErrInvalidWire
	}
	out := make([][]string, 0, len(path))
	for i, n := range path {
		if n.Kind == "recovered" {
			if i != 0 || n.Enrollment != nil || !tokenHashPattern.MatchString(n.RecoveryEnrollmentHash) {
				return nil, ErrInvalidWire
			}
			out = append(out, []string{"recovered", n.RecoveryEnrollmentHash})
			continue
		}
		if n.Kind != "paired" || n.Enrollment == nil || n.RecoveryEnrollmentHash != "" {
			return nil, ErrInvalidWire
		}
		b, e := dagArchiveBytes(*n.Enrollment)
		if e != nil {
			return nil, e
		}
		for _, s := range []string{n.Enrollment.Approval.ApproverSignature, n.Enrollment.Approval.InitiatorSignature} {
			if _, e = DecodeBase64(s, 64, 64); e != nil {
				return nil, e
			}
		}
		out = append(out, []string{"paired", n.Enrollment.CertificateVersion, EncodeBase64(b), n.Enrollment.Approval.ApproverSignature, n.Enrollment.Approval.InitiatorSignature})
	}
	return out, nil
}
func (s RecoverySource) CanonicalBytes() ([]byte, error) {
	switch s.Kind {
	case "proof2":
		if s.Proof == nil || s.View != nil {
			return nil, ErrInvalidWire
		}
		b, e := s.Proof.CanonicalBytes()
		if e != nil {
			return nil, e
		}
		return json.Marshal([]string{"harmonia/recovery-source/v1", "proof2", IssuerProofV2Profile, EncodeBase64(b)})
	case "proof3":
		if s.View == nil || s.Proof != nil {
			return nil, ErrInvalidWire
		}
		b, e := s.View.CanonicalBytes()
		if e != nil {
			return nil, e
		}
		return json.Marshal([]string{"harmonia/recovery-source/v1", "proof3", RecoverySourceViewProfile, EncodeBase64(b)})
	default:
		return nil, ErrInvalidWire
	}
}
func (s RecoverySource) Hash() (string, error) {
	b, e := s.CanonicalBytes()
	if e != nil {
		return "", e
	}
	return dagHashBytes(b), nil
}
func validDAGKind(s string) bool {
	return s == "transition-v1" || s == "recovered-v1" || s == "transition-v2" || s == "recovered-v2"
}
func recoveryRecordHash(domain string, b []byte, a, z string, e error) (string, error) {
	if e != nil {
		return "", e
	}
	for _, s := range []string{a, z} {
		if _, e = DecodeBase64(s, 64, 64); e != nil {
			return "", e
		}
	}
	return hashCanonical([]string{domain, EncodeBase64(b), a, z})
}
func RecoveryTransitionHashV2(s RecoveryTransitionSubmissionV2) (string, error) {
	b, e := s.Transition.SigningBytes()
	return recoveryRecordHash("harmonia/recovery-authority-transition-ref/v2", b, s.AuthorizationSignature, s.NewRecoverySignature, e)
}
func RecoveredDeviceReferenceHashV2(s RecoveredDeviceSubmissionV2) (string, error) {
	b, e := s.Enrollment.SigningBytes()
	return recoveryRecordHash("harmonia/recovered-device-enrollment-ref/v2", b, s.RecoverySignature, s.DeviceSignature, e)
}
func (r RecoveryDAGRecord) body() (any, error) {
	n := 0
	for _, x := range []bool{r.TransitionV1 != nil, r.RecoveredV1 != nil, r.TransitionV2 != nil, r.RecoveredV2 != nil} {
		if x {
			n++
		}
	}
	if n != 1 {
		return nil, ErrInvalidWire
	}
	switch r.Kind {
	case "transition-v1":
		if r.TransitionV1 != nil {
			return r.TransitionV1, nil
		}
	case "recovered-v1":
		if r.RecoveredV1 != nil {
			return r.RecoveredV1, nil
		}
	case "transition-v2":
		if r.TransitionV2 != nil {
			return r.TransitionV2, nil
		}
	case "recovered-v2":
		if r.RecoveredV2 != nil {
			return r.RecoveredV2, nil
		}
	}
	return nil, ErrInvalidWire
}
func (r RecoveryDAGRecord) MarshalJSON() ([]byte, error) {
	body, e := r.body()
	if e != nil {
		return nil, e
	}
	return json.Marshal(struct {
		Kind   string `json:"kind"`
		Record any    `json:"record"`
	}{r.Kind, body})
}
func (r RecoveryDAGRecord) row() ([]string, error) {
	if _, e := r.body(); e != nil {
		return nil, e
	}
	var h string
	var b []byte
	var a, z string
	var seq uint64
	var e error
	switch r.Kind {
	case "transition-v1":
		s := r.TransitionV1.Submission
		h, e = RecoveryTransitionHash(s)
		b, _ = s.Transition.SigningBytes()
		a, z, seq = s.AuthorizationSignature, s.NewRecoverySignature, r.TransitionV1.Sequence
	case "recovered-v1":
		s := r.RecoveredV1.Submission
		h, e = RecoveredDeviceReferenceHash(s)
		b, _ = s.Enrollment.SigningBytes()
		a, z, seq = s.RecoverySignature, s.DeviceSignature, r.RecoveredV1.Sequence
	case "transition-v2":
		s := r.TransitionV2.Submission
		h, e = RecoveryTransitionHashV2(s)
		b, _ = s.Transition.SigningBytes()
		a, z, seq = s.AuthorizationSignature, s.NewRecoverySignature, r.TransitionV2.Sequence
	case "recovered-v2":
		s := r.RecoveredV2.Submission
		h, e = RecoveredDeviceReferenceHashV2(s)
		b, _ = s.Enrollment.SigningBytes()
		a, z, seq = s.RecoverySignature, s.DeviceSignature, r.RecoveredV2.Sequence
	}
	if e != nil {
		return nil, e
	}
	if seq < 2 || seq > 9007199254740991 {
		return nil, ErrInvalidWire
	}
	return []string{r.Kind, h, EncodeBase64(b), a, z, strconv.FormatUint(seq, 10)}, nil
}
func (r RecoveryDAGRecord) Reference() (RecoveryDependency, error) {
	row, e := r.row()
	if e != nil {
		return RecoveryDependency{}, e
	}
	return RecoveryDependency{row[0], row[1]}, nil
}
func recordRows(records []RecoveryDAGRecord) ([][]string, error) {
	if records == nil || len(records) > MaxRecoveryDAGNodes {
		return nil, ErrInvalidWire
	}
	rows := make([][]string, 0, len(records))
	seen := map[string]bool{}
	counts := map[string]int{}
	for _, r := range records {
		row, e := r.row()
		if e != nil || seen[row[1]] {
			return nil, ErrInvalidWire
		}
		seen[row[1]] = true
		family := r.Kind[:len(r.Kind)-3]
		counts[family]++
		if counts[family] > MaxRecoveryTransitions {
			return nil, ErrInvalidWire
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i][0] != rows[j][0] {
			return rows[i][0] < rows[j][0]
		}
		return rows[i][1] < rows[j][1]
	})
	return rows, nil
}
func initializationDAGRow(o OriginalInitialization) ([]string, error) {
	h, e := o.Hash()
	if e != nil {
		return nil, e
	}
	p, e := o.proposalBytes()
	if e != nil {
		return nil, e
	}
	q, e := o.Proof.SigningBytes()
	if e != nil {
		return nil, e
	}
	return []string{h, EncodeBase64(p), EncodeBase64(q), o.DeviceSignature, o.RecoverySignature, "1"}, nil
}
func (p IssuerRecoveryDAG) CanonicalBytes() ([]byte, error) {
	if p.Profile != IssuerRecoveryDAGProfile || p.AccountID != p.Initialization.Proof.AccountID || p.AccountGeneration != p.Initialization.Proof.AccountGeneration {
		return nil, ErrInvalidWire
	}
	init, e := initializationDAGRow(p.Initialization)
	if e != nil {
		return nil, e
	}
	source, e := p.Source.Hash()
	if e != nil {
		return nil, e
	}
	rows, e := recordRows(p.Records)
	if e != nil {
		return nil, e
	}
	b, e := json.Marshal([]any{p.Profile, p.AccountID, p.AccountGeneration, init, source, rows})
	if e != nil || len(b) > MaxRecoveryAuthorityBytes {
		return nil, ErrInvalidWire
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > MaxRecoveryAuthorityBytes {
		return nil, ErrInvalidWire
	}
	return b, nil
}
func (p IssuerRecoveryDAG) Hash() (string, error) {
	b, e := p.CanonicalBytes()
	if e != nil {
		return "", e
	}
	return dagHashBytes(b), nil
}

func strictDAGObject(data []byte, keys ...string) (map[string]json.RawMessage, error) {
	if ValidateStrictJSON(data, MaxRecoveryAuthorityBytes) != nil {
		return nil, ErrInvalidWire
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil || len(m) != len(keys) {
		return nil, ErrInvalidWire
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return nil, ErrInvalidWire
		}
	}
	return m, nil
}
func strictDAGDecode(data []byte, out any) error {
	if ValidateStrictJSON(data, MaxRecoveryAuthorityBytes) != nil {
		return ErrInvalidWire
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalidWire
	}
	var rest any
	if d.Decode(&rest) != io.EOF {
		return ErrInvalidWire
	}
	return nil
}
func (s *RecoverySource) UnmarshalJSON(data []byte) error {
	type plain RecoverySource
	var p plain
	if validateRecoveryJSONShape(data, reflect.TypeOf(p), nil) != nil {
		return ErrInvalidWire
	}
	if strictDAGDecode(data, &p) != nil {
		return ErrInvalidWire
	}
	*s = RecoverySource(p)
	_, e := s.CanonicalBytes()
	return e
}
func (r *RecoveryDAGRecord) UnmarshalJSON(data []byte) error {
	m, e := strictDAGObject(data, "kind", "record")
	if e != nil {
		return e
	}
	var kind string
	if json.Unmarshal(m["kind"], &kind) != nil {
		return ErrInvalidWire
	}
	fresh := RecoveryDAGRecord{Kind: kind}
	var out any
	nullable := map[string]bool{"$.submission.issuerEvidence": true, "$.submission.legacyState": true}
	switch kind {
	case "transition-v1":
		fresh.TransitionV1 = &AcceptedRecoveryTransition{}
		out = fresh.TransitionV1
	case "recovered-v1":
		fresh.RecoveredV1 = &AcceptedRecoveredDevice{}
		out = fresh.RecoveredV1
	case "transition-v2":
		fresh.TransitionV2 = &AcceptedRecoveryTransitionV2{}
		out = fresh.TransitionV2
	case "recovered-v2":
		fresh.RecoveredV2 = &AcceptedRecoveredDeviceV2{}
		out = fresh.RecoveredV2
	default:
		return ErrInvalidWire
	}
	if validateRecoveryJSONShape(m["record"], reflect.TypeOf(out).Elem(), nullable) != nil || strictDAGDecode(m["record"], out) != nil {
		return ErrInvalidWire
	}
	*r = fresh
	_, e = r.row()
	return e
}
func DecodeIssuerRecoveryDAG(data []byte) (IssuerRecoveryDAG, error) {
	var p IssuerRecoveryDAG
	if _, e := strictDAGObject(data, "profile", "accountId", "accountGeneration", "initialization", "source", "records"); e != nil {
		return p, e
	}
	if e := strictDAGDecode(data, &p); e != nil {
		return p, e
	}
	_, e := p.CanonicalBytes()
	return p, e
}
