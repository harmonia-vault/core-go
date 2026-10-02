//go:build harmonia_boringssl && cgo && (darwin || linux)

package syncclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/pairing"
)

// 本测试使用真实成熟 SPAKE2、Ed25519、HPKE 与 TLS；服务业务原子性另由
// workspace 的 Go -> TypeScript -> SQLite 集成测试验证。
func TestNativeEnrollmentConfirmationReceiptAndUnknownCompletion(t *testing.T) {
	for _, wrongCode := range []bool{false, true} {
		t.Run(strconv.FormatBool(wrongCode), func(t *testing.T) {
			f := newCryptoFixture(t)
			managerReceiving, _, err := cryptox.GenerateReceivingKey()
			check(t, err)
			var mu sync.Mutex
			var status PairingStatus
			var manager *pairing.Session
			var completeCalls int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				body, _ := io.ReadAll(io.LimitReader(r.Body, 65537))
				if strings.Contains(string(body), "12345678") {
					t.Error("secret pairing code reached HTTP")
				}
				if strings.HasSuffix(r.URL.Path, "/pairings") {
					var proposal struct{ IdempotencyKey, DeviceID, SigningPublicKey, ReceivingPublicKey, ApproverDeviceID string }
					_ = json.Unmarshal(body, &proposal)
					status = PairingStatus{State: "pending", IdempotencyKey: proposal.IdempotencyKey, PairingProfile: pairing.Profile,
						Context: pairing.Context{AccountID: "acct", AccountGeneration: "1", Purpose: pairing.PurposeEnrollment, SessionID: "challenge-1", ChallengeNonce: cryptox.EncodeBase64(make([]byte, 32)), ExpiresAt: strconv.FormatInt(time.Now().Add(110*time.Second).Unix(), 10), InitiatorDeviceID: proposal.DeviceID, InitiatorSigningPublicKey: proposal.SigningPublicKey, InitiatorReceivingPublicKey: proposal.ReceivingPublicKey, ApproverDeviceID: "manager", ApproverSigningPublicKey: cryptox.EncodeBase64(f.managerPrivate.Public().(ed25519.PublicKey)), ApproverReceivingPublicKey: cryptox.EncodeBase64(managerReceiving)}, Messages: map[string]string{}, Confirmations: map[string]string{}}
				} else if strings.HasSuffix(r.URL.Path, "/relay") {
					var relay struct{ Side, Kind, Payload, Signature string }
					_ = json.Unmarshal(body, &relay)
					proof := cryptox.PairingRelay{AccountID: "acct", AccountGeneration: "1", SessionID: status.Context.SessionID, ChallengeNonce: status.Context.ChallengeNonce, Side: relay.Side, Kind: relay.Kind, Payload: relay.Payload}
					if cryptox.VerifyPairingRelay(proof, relay.Signature, f.devicePublic) != nil {
						http.Error(w, "invalid relay proof", 403)
						return
					}
					if relay.Kind == "message" {
						code := []byte("12345678")
						if wrongCode {
							code = []byte("87654321")
						}
						var message []byte
						manager, message, err = pairing.NewApprover(status.Context, code)
						if err != nil {
							t.Error(err)
							http.Error(w, "native failed", 500)
							return
						}
						peer, _ := cryptox.DecodeBase64(relay.Payload, 32, 32)
						mac, e := manager.Complete(peer)
						if e != nil {
							t.Error(e)
							http.Error(w, "native failed", 500)
							return
						}
						status.Messages["initiator"] = relay.Payload
						status.Messages["approver"] = cryptox.EncodeBase64(message)
						status.Confirmations["approver"] = cryptox.EncodeBase64(mac)
					} else {
						status.Confirmations["initiator"] = relay.Payload
						mac, _ := cryptox.DecodeBase64(relay.Payload, 32, 32)
						if err := manager.VerifyPeerConfirmation(mac); err != nil {
							if !wrongCode {
								t.Error(err)
							}
							_ = json.NewEncoder(w).Encode(status)
							return
						}
						transcript, e := manager.TranscriptHash()
						if e != nil {
							t.Error(e)
							http.Error(w, "confirmation failed", 500)
							return
						}
						approval := &EnrollmentApproval{Context: status.Context, PairingProfile: pairing.Profile, TranscriptHash: transcript, Grants: []cryptox.SignedGrantWire{{Grant: f.grant.Grant, Signature: f.grant.Signature}}}
						cert, e := certificate(*approval)
						if e != nil {
							t.Error(e)
							http.Error(w, "certificate failed", 500)
							return
						}
						approval.ApproverSignature, e = cryptox.SignEnrollmentCertificate(cert, f.managerPrivate)
						if e != nil {
							t.Error(e)
							http.Error(w, "certificate failed", 500)
							return
						}
						status.Approval = approval
						status.State = "approved"
					}
				} else if strings.HasSuffix(r.URL.Path, "/complete") {
					completeCalls++
					var finish struct{ Signature string }
					_ = json.Unmarshal(body, &finish)
					cert, e := certificate(*status.Approval)
					if e != nil || cryptox.VerifyEnrollmentCertificate(cert, finish.Signature, f.devicePublic) != nil {
						http.Error(w, "invalid completion proof", 403)
						return
					}
					status.Approval.InitiatorSignature = finish.Signature
					status.State = "complete"
					sequence := uint64(3)
					status.Sequence = &sequence
					// 已接受后故意返回不明结果，客户端必须保存 receipt 并先查询。
					w.WriteHeader(504)
					_, _ = w.Write([]byte(`{"error":"request_rejected"}`))
					return
				}
				_ = json.NewEncoder(w).Encode(status)
			}))
			defer server.Close()
			defer func() {
				if manager != nil {
					manager.Close()
				}
			}()
			config := EnrollmentConfig{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: "acct", AccountGeneration: 1, DeviceID: "dev", LoginToken: cryptox.EncodeBase64(make([]byte, 32)), SigningKey: f.devicePrivate, ReceivingPrivateKey: f.receivingPrivate, Engine: testEngine(t)}
			e, err := NewEnrollment(config)
			check(t, err)
			_, err = e.Begin(context.Background(), "manager", "pair-1", []byte("12345678"))
			check(t, err)
			_, err = e.Advance(context.Background())
			if wrongCode {
				if !errors.Is(err, pairing.ErrConfirmation) {
					t.Fatal("wrong code established pairing", err)
				}
				if _, err = e.Receipt(); err == nil {
					t.Fatal("wrong code yielded a trusted receipt")
				}
				e.Close()
				mu.Lock()
				calls := completeCalls
				mu.Unlock()
				if calls != 0 {
					t.Fatal("wrong code submitted completion")
				}
				return
			}
			check(t, err)
			receipt, err := e.Receipt()
			check(t, err)
			if receipt.Approval.InitiatorSignature == "" || config.Engine.State().Cloud.AccountID != "" {
				t.Fatal("receipt missing proof or enrollment injected cloud authority")
			}
			if _, err = e.Complete(context.Background()); !errors.Is(err, ErrEnrollmentPending) {
				t.Fatal("unknown result did not preserve pending state", err)
			}
			e.Close()
			resumed, err := ResumeEnrollment(config, receipt)
			check(t, err)
			defer resumed.Close()
			result, err := resumed.Complete(context.Background())
			check(t, err)
			mu.Lock()
			calls := completeCalls
			mu.Unlock()
			if result.Sequence != 3 || calls != 1 || result.Verifier == nil || config.Engine.State().Cloud.AccountID != "" {
				t.Fatal("query retried an accepted write or injected cloud snapshot")
			}
			modified := receipt
			modified.Approval.TranscriptHash = strings.Repeat("0", 64)
			if rejected, err := ResumeEnrollment(config, modified); err == nil {
				rejected.Close()
				t.Fatal("modified pending receipt accepted")
			}
		})
	}
}
