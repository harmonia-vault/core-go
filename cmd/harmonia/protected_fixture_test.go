package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/internal/dagfixture"
	"github.com/harmonia-vault/core-go/syncclient"
)

// The daemon fixture uses the same explicit source evidence as a current pairing.
func signedDaemonReceipt(t *testing.T, approval cryptox.EnrollmentApproval, manager, device ed25519.PrivateKey) (syncclient.EnrollmentReceiptV5, *cryptox.IssuerRecoveryDAG) {
	t.Helper()
	c := cryptox.EnrollmentContext(approval.Context)
	recovery := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	receiving, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{78}, 32))
	mustCLI(t, err)
	root, err := cryptox.SignTrustRoot(c.AccountID, c.AccountGeneration, cryptox.TrustRoot{
		RootDeviceID: c.ApproverDeviceID, RootSigningPublicKey: c.ApproverSigningPublicKey,
		RootReceivingPublicKey: c.ApproverReceivingPublicKey, RecoveryGeneration: "1",
		RecoverySigningPublicKey:   cryptox.EncodeBase64(recovery.Public().(ed25519.PublicKey)),
		RecoveryReceivingPublicKey: cryptox.EncodeBase64(receiving.PublicKey().Bytes()),
	}, recovery)
	mustCLI(t, err)
	initial := []cryptox.InitializationEnvironment{}
	for _, child := range approval.Grants {
		g := child.Grant
		g.SubjectDeviceID = c.ApproverDeviceID
		g.SubjectSigningPublicKey = c.ApproverSigningPublicKey
		g.SubjectReceivingPublicKey = c.ApproverReceivingPublicKey
		g.Role, g.IdempotencyKey, g.ExpiresAt = "admin", "root-"+g.EnvironmentID, "0"
		signed, err := cryptox.SignGrant(g, manager)
		mustCLI(t, err)
		wire := cryptox.GrantToWire(signed)
		initial = append(initial, cryptox.InitializationEnvironment{EnvironmentID: g.EnvironmentID, KeyVersion: "1", RecoveryEnvelope: cryptox.EncodeBase64(make([]byte, 80)), Grant: wire})
	}
	proof := dagfixture.Root(t, c.AccountID, root, manager, recovery, initial)
	a, proof := dagfixture.Enroll(t, proof, c, approval.Grants, manager, device)
	receipt := syncclient.EnrollmentReceiptV5{IdempotencyKey: "pair-1", Approval: a}
	return receipt, &proof
}
