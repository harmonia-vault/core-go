package mobileworkflow

import (
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
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrLegacyEnvironmentOrigin = errors.New("legacy create/rotate package has no signed origin; automatic upgrade forbidden")

type environmentOriginJournal struct {
	Packet      cryptox.EnvironmentChangeV2 `json:"packet"`
	ContentHash string                      `json:"contentHash"`
	Authority   cryptox.SignedGrantWire     `json:"authority"`
	Before      []cryptox.SignedGrantWire   `json:"before"`
	Control     cryptox.IssuerRecoveryDAG   `json:"control"`
}

func (w *Workflow) validateEnvironmentOriginRecord(record *environmentRecord) error {
	r := record.OriginV2
	if r == nil {
		return nil
	}
	if !sameJSONValue(record.Signed, cryptox.SignedEnvironmentChange{Change: r.Packet.Change, Signature: r.Packet.Signature}) {
		return errors.New("protected environment data/origin packages differ")
	}
	hash, err := cryptox.EnvironmentSubmissionHash(r.Packet)
	if err != nil || hash != r.ContentHash {
		return errors.New("protected environment V2 content hash changed")
	}
	client, close, err := w.environmentJournalClient()
	if err != nil {
		return err
	}
	defer close()
	sequence, err := strconv.ParseUint(record.Signed.Change.ExpectedSequence, 10, 64)
	if err != nil {
		return err
	}
	grants := append([]cryptox.SignedGrantWire{}, r.Before...)
	found := false
	for _, grant := range grants {
		if sameJSONValue(grant, r.Authority) {
			found = true
		}
	}
	if !found {
		grants = append(grants, r.Authority)
	}
	graph, err := client.VerifyEnvironmentControl(syncclient.EnvironmentControlView{Sequence: sequence, Grants: grants, IssuerDAGEvidence: &r.Control}, r.Authority.Grant.EnvironmentID, true)
	if err != nil {
		return err
	}
	if err = graph.VerifyHistoricalGrant(r.Authority); err != nil {
		return err
	}
	if err = graph.VerifyTarget(r.Authority, w.state.DeviceID, w.state.SigningPublicKey, w.state.ReceivingPublicKey); err != nil {
		return err
	}
	for _, before := range r.Before {
		if err = graph.VerifyHistoricalGrant(before); err != nil {
			return err
		}
	}
	return cryptox.VerifyEnvironmentOriginChange(record.Signed, r.Packet.Origin, r.Authority, r.Before, w.signing.Public().(ed25519.PublicKey))
}
func (w *Workflow) prepareEnvironmentOrigin(ctx context.Context, signed cryptox.SignedEnvironmentChange, control syncclient.EnvironmentControlView) (*environmentOriginJournal, error) {
	var authority cryptox.SignedGrantWire
	for _, g := range control.Grants {
		if g.Grant.SubjectDeviceID == w.state.DeviceID {
			authority = g
		}
	}
	before := []cryptox.SignedGrantWire{}
	if signed.Change.Operation == "rotate" {
		before = control.Grants
	}
	packet, err := cryptox.NewEnvironmentChangeV2(signed, authority, before, w.signing)
	if err != nil {
		return nil, err
	}
	hash, err := cryptox.EnvironmentSubmissionHash(packet)
	if err != nil {
		return nil, err
	}
	if control.IssuerDAGEvidence == nil {
		return nil, ErrRecoveryEvidence
	}
	encoded, err := json.Marshal(control.IssuerDAGEvidence)
	if err != nil {
		return nil, err
	}
	proof, err := cryptox.DecodeIssuerRecoveryDAG(encoded)
	if err != nil {
		return nil, err
	}
	record := &environmentOriginJournal{Packet: packet, ContentHash: hash, Authority: authority, Before: before, Control: proof}
	return record, nil
}
func (w *Workflow) environmentControl(ctx context.Context, env string) (syncclient.EnvironmentControlView, error) {
	control, err := w.client.EnvironmentControl(ctx, env)
	if err != nil {
		return control, err
	}
	if control.Sequence != w.engine.State().Cloud.Sequence {
		return control, syncclient.ErrWriteConflict
	}
	root, err := w.environmentRecoveryRecipient()
	if err != nil {
		return control, err
	}
	if control.IssuerDAGEvidence == nil || control.IssuerDAGEvidence.Source.View == nil || control.IssuerDAGEvidence.Source.View.TrustRoot != root {
		return control, ErrRecoveryEvidence
	}
	return control, nil
}
func (w *Workflow) submitEnvironmentOrigin(ctx context.Context, record *environmentRecord) error {
	r := record.OriginV2
	if r == nil {
		return ErrLegacyEnvironmentOrigin
	}
	if err := w.validateEnvironmentOriginRecord(record); err != nil {
		return err
	}
	if err := w.persist(); err != nil {
		return err
	}
	status, err := w.client.EnvironmentStatusV4(ctx, record.Signed.Change.IdempotencyKey)
	if err != nil {
		return err
	}
	var result syncclient.SubmitResult
	if status.State == "complete" {
		if status.ContentHash != r.ContentHash {
			return syncclient.ErrWriteConflict
		}
		result, err = w.client.ConfirmEnvironmentChangeV4(ctx, r.Packet, syncclient.Acceptance{Sequence: status.Sequence, Replayed: true})
	} else {
		result, err = w.client.SubmitEnvironmentChangeV4(ctx, r.Packet)
	}

	if result.Accepted.Sequence > 0 {
		record.Sequence = result.Accepted.Sequence
	}
	record.Applied = result.Applied
	if saveErr := w.persist(); saveErr != nil {
		record.Applied = false
		return errors.Join(syncclient.ErrAcceptedNotApplied, saveErr)
	}
	if err != nil {
		return err
	}
	if err = w.refresh(ctx); err != nil {
		record.Applied = false
		return errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	if err = w.rememberLabel(record.Signed.Change, record.Sequence); err != nil {
		record.Applied = false
		return errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	if err = w.persist(); err != nil {
		record.Applied = false
		return errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	return nil
}
func (w *Workflow) RotateEnvironment(ctx context.Context, env, id string) (View, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return View{}, err
	}
	if !identifier.MatchString(id) || len(id) > 64 {
		return View{}, errors.New("rotation operation id invalid")
	}
	input, _ := json.Marshal([]string{"rotate", env, "", id})
	sum := sha256.Sum256(input)
	fingerprint := hex.EncodeToString(sum[:])
	if err := w.refresh(ctx); err != nil {
		return View{}, err
	}
	if old := w.state.EnvironmentWrites[id]; old != nil {
		if old.InputHash != fingerprint {
			return View{}, syncclient.ErrWriteConflict
		}
		if err := w.submitEnvironmentOrigin(ctx, old); err != nil {
			return View{}, err
		}
		return w.view(), nil
	}
	if len(w.state.EnvironmentWrites) >= 32 {
		return View{}, errors.New("protected environment request journal full")
	}
	authority, err := w.grant(env)
	if err != nil || authority.Role != "admin" {
		return View{}, localstate.ErrUnauthorized
	}
	control, err := w.environmentControl(ctx, env)
	if err != nil {
		return View{}, err
	}
	oldVersion, err := strconv.ParseUint(authority.KeyVersion, 10, 64)
	if err != nil || oldVersion == ^uint64(0) {
		return View{}, errors.New("environment key version exhausted")
	}
	newVersion := strconv.FormatUint(oldVersion+1, 10)
	key, err := cryptox.GenerateEnvironmentKey()
	if err != nil {
		return View{}, err
	}
	defer clear(key)
	change := w.baseChange(env, "rotate", id, authority)
	recipient, err := w.environmentRecoveryRecipient()
	if err != nil {
		return View{}, err
	}
	change.RecoveryGeneration = recipient.RecoveryGeneration
	change.KeyVersion = newVersion
	name := env
	if label, ok := w.state.Labels[env]; ok {
		name = label.Name
	}
	label, err := cryptox.EncryptEnvironmentLabel(key, cryptox.EnvironmentLabelContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, KeyVersion: newVersion}, []byte(name))
	if err != nil {
		return View{}, err
	}
	change.LabelPayload = cryptox.EncodeBase64(label)
	operationSum := sha256.Sum256([]byte(id))
	prefix := "rotate-" + hex.EncodeToString(operationSum[:16])
	ownGeneration := ""
	for i, old := range control.Grants {
		g := old.Grant
		n, err := strconv.ParseUint(g.GrantGeneration, 10, 64)
		if err != nil || n == ^uint64(0) {
			return View{}, errors.New("recipient grant generation exhausted")
		}
		g.IssuerDeviceID = w.state.DeviceID
		g.KeyVersion = newVersion
		g.GrantGeneration = strconv.FormatUint(n+1, 10)
		g.IdempotencyKey = prefix + "-g-" + strconv.Itoa(i)
		envelope, err := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, KeyVersion: newVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey})
		if err != nil {
			return View{}, err
		}
		g.Envelope = cryptox.EncodeBase64(envelope)
		signed, err := cryptox.SignGrant(g, w.signing)
		if err != nil {
			return View{}, err
		}
		change.Grants = append(change.Grants, cryptox.GrantToWire(signed))
		if g.SubjectDeviceID == w.state.DeviceID {
			ownGeneration = g.GrantGeneration
		}
	}
	if ownGeneration == "" {
		return View{}, localstate.ErrUnauthorized
	}
	recovery, err := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, KeyVersion: newVersion, RecipientType: "recovery", RecipientID: w.state.AccountID, RecipientGeneration: recipient.RecoveryGeneration, RecipientPublicKey: recipient.RecoveryReceivingPublicKey})
	if err != nil {
		return View{}, err
	}
	change.RecoveryEnvelope = cryptox.EncodeBase64(recovery)
	values := w.engine.State().Cloud.Environments[env].Values
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		payload, err := cryptox.EncryptValue(key, cryptox.ValueContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, KeyVersion: newVersion, Name: name}, []byte(values[name]))
		if err != nil {
			return View{}, err
		}
		m := cryptox.Mutation{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, DeviceID: w.state.DeviceID, EnvironmentID: env, KeyVersion: newVersion, GrantGeneration: ownGeneration, Operation: "put", IdempotencyKey: prefix + "-v-" + strconv.Itoa(i), Name: name, Payload: cryptox.EncodeBase64(payload)}
		signed, err := cryptox.SignMutation(m, w.signing)
		if err != nil {
			return View{}, err
		}
		change.Mutations = append(change.Mutations, cryptox.MutationToWire(signed))
	}
	signed, err := cryptox.SignEnvironmentChange(change, w.signing)
	if err != nil {
		return View{}, err
	}
	origin, err := w.prepareEnvironmentOrigin(ctx, signed, control)
	if err != nil {
		return View{}, err
	}
	record := &environmentRecord{InputHash: fingerprint, Signed: signed, OriginV2: origin}
	w.state.EnvironmentWrites[id] = record
	if err = w.persist(); err != nil {
		return View{}, err
	}
	if err = w.submitEnvironmentOrigin(ctx, record); err != nil {
		return View{}, err
	}
	return w.view(), nil
}
