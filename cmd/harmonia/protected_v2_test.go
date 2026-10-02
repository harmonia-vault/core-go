//go:build darwin || linux

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/syncclient"
)

func TestProtectedV2ReceiptRestartRejectsProofAndGlobalManagers(t *testing.T) {
	directory := protectedTestDirectory(t)
	store, err := protectedStore(protectedOptions{directory: directory})
	mustCLI(t, err)
	data, err := os.ReadFile("../../cryptox/testdata/issuer-proof-v1.json")
	mustCLI(t, err)
	var vector struct {
		Approval cryptox.EnrollmentApprovalV2 `json:"approval"`
	}
	mustCLI(t, json.Unmarshal(data, &vector))
	signing := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	receiving, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{13}, 32))
	mustCLI(t, err)
	keys := localkeys.DeviceKeys{DeviceID: "device-C", SigningSeed: signing.Seed(), SigningPublic: signing.Public().(ed25519.PublicKey), ReceivingPrivate: receiving.Bytes(), ReceivingPublic: receiving.PublicKey().Bytes()}
	mustCLI(t, store.Vault().SaveDeviceKeys(keys))
	session := localkeys.LoginSession{Endpoint: "https://synthetic.invalid", AccountID: "account-chain", AccountGeneration: 1, Token: cryptox.EncodeBase64(make([]byte, 32)), ExpiresAt: "2034-01-01T00:00:00Z"}
	mustCLI(t, store.Vault().SaveSession(session))
	receipt := syncclient.EnrollmentReceiptV2{IdempotencyKey: "pair-C", Approval: vector.Approval}
	mustCLI(t, saveReceiptV2(store.Vault(), session, keys, receipt, false))
	trust, err := store.Vault().LoadTrustContext()
	mustCLI(t, err)
	if _, err = verifiedStoredContext(trust, keys); err == nil {
		t.Fatal("pending proof enabled daemon")
	}
	mustCLI(t, saveReceiptV2(store.Vault(), session, keys, receipt, true))
	mustCLI(t, store.Close())
	store, err = protectedStore(protectedOptions{directory: directory})
	mustCLI(t, err)
	defer store.Close()
	trust, err = store.Vault().LoadTrustContext()
	mustCLI(t, err)
	v, err := verifiedStoredContext(trust, keys)
	mustCLI(t, err)
	v.Close()
	if trust.CertificateVersion != "2" || len(trust.Managers) != 0 {
		t.Fatal("restart expanded manager map")
	}
	for _, field := range []string{"managers", "proof", "local-key", "version"} {
		t.Run(field, func(t *testing.T) {
			candidate := trust
			local := keys
			switch field {
			case "managers":
				candidate.Managers = map[string][]byte{"device-A": keys.SigningPublic}
			case "proof":
				r := receipt
				r.Approval.IssuerProof.Targets = nil
				candidate.EnrollmentCertificate, _ = json.Marshal(r)
			case "local-key":
				local.SigningPublic = bytes.Repeat([]byte{8}, 32)
			case "version":
				candidate.CertificateVersion = "1"
			}
			if vv, err := verifiedStoredContext(candidate, local); err == nil {
				vv.Close()
				t.Fatal("changed stored proof trusted")
			}
		})
	}
}
