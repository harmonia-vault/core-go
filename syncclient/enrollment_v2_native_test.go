//go:build harmonia_boringssl && cgo && (darwin || linux)

package syncclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
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

// 合成 A→B 历史证明 + 实际 B↔C SPAKE2/TLS；真正业务原子性另测 SQLite。
func TestNativeEnrollmentV2ConfirmedProofAndUnknownCompletion(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-code", "downgrade"} {
		t.Run(mode, func(t *testing.T) {
			f := issuerClientVector(t)
			var mu sync.Mutex
			var status PairingStatusV2
			var manager *pairing.Session
			var completeCalls int
			bk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
			defer clear(bk)
			rootReceive, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{11}, 32))
			check(t, err)
			rootPin := cryptox.PinnedIssuerRoot{AccountID: "account-chain", AccountGeneration: "1", DeviceID: "device-A", SigningPublicKey: cryptox.EncodeBase64(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)), ReceivingPublicKey: cryptox.EncodeBase64(rootReceive.PublicKey().Bytes())}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				body, err := io.ReadAll(io.LimitReader(r.Body, cryptox.MaxIssuerProofBytes+513))
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				if bytes.Contains(body, []byte("12345678")) || bytes.Contains(body, []byte("87654321")) {
					t.Error("short code reached HTTP")
				}
				if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/pairings-v2") {
					var proposal struct {
						IdempotencyKey     string   `json:"idempotencyKey"`
						DeviceID           string   `json:"deviceId"`
						SigningPublicKey   string   `json:"signingPublicKey"`
						ReceivingPublicKey string   `json:"receivingPublicKey"`
						ApproverDeviceID   string   `json:"approverDeviceId"`
						CertificateVersion string   `json:"certificateVersion"`
						Capabilities       []string `json:"capabilities"`
					}
					d := json.NewDecoder(bytes.NewReader(body))
					d.DisallowUnknownFields()
					if d.Decode(&proposal) != nil || proposal.CertificateVersion != "2" || len(proposal.Capabilities) != 1 || proposal.Capabilities[0] != cryptox.IssuerProofCapability {
						t.Error("wrong v2 begin schema")
						w.WriteHeader(400)
						return
					}
					c := pairing.Context(f.Approval.Context)
					c.SessionID = "real-SPAKE-C"
					c.ExpiresAt = strconv.FormatInt(time.Now().Add(90*time.Second).Unix(), 10)
					c.ChallengeNonce = cryptox.EncodeBase64(bytes.Repeat([]byte{28}, 32))
					if proposal.DeviceID != c.InitiatorDeviceID || proposal.SigningPublicKey != c.InitiatorSigningPublicKey || proposal.ReceivingPublicKey != c.InitiatorReceivingPublicKey || proposal.ApproverDeviceID != c.ApproverDeviceID {
						t.Error("wrong exact local keys")
					}
					status = PairingStatusV2{State: "pending", IdempotencyKey: proposal.IdempotencyKey, CertificateVersion: "2", Capabilities: []string{cryptox.IssuerProofCapability}, PairingProfile: pairing.Profile, Context: c, Messages: map[string]string{}, Confirmations: map[string]string{}}
					if mode == "downgrade" {
						status.CertificateVersion = "1"
						status.Capabilities = nil
					}
				} else if strings.HasSuffix(r.URL.Path, "/relay") {
					var input struct{ Side, Kind, Payload, Signature string }
					if json.Unmarshal(body, &input) != nil {
						w.WriteHeader(400)
						return
					}
					relay := cryptox.PairingRelay{AccountID: status.Context.AccountID, AccountGeneration: status.Context.AccountGeneration, SessionID: status.Context.SessionID, ChallengeNonce: status.Context.ChallengeNonce, Side: input.Side, Kind: input.Kind, Payload: input.Payload}
					ck := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)).Public().(ed25519.PublicKey)
					if cryptox.VerifyPairingRelay(relay, input.Signature, ck) != nil {
						t.Error("relay unbound")
						w.WriteHeader(403)
						return
					}
					if input.Kind == "message" {
						code := []byte("12345678")
						if mode == "wrong-code" {
							code = []byte("87654321")
						}
						var message []byte
						manager, message, err = pairing.NewApprover(status.Context, code)
						if err != nil {
							t.Error(err)
							w.WriteHeader(500)
							return
						}
						peer, _ := cryptox.DecodeBase64(input.Payload, 32, 32)
						mac, e := manager.Complete(peer)
						if e != nil {
							t.Error(e)
							w.WriteHeader(500)
							return
						}
						status.Messages["initiator"] = input.Payload
						status.Messages["approver"] = cryptox.EncodeBase64(message)
						status.Confirmations["approver"] = cryptox.EncodeBase64(mac)
					} else {
						status.Confirmations["initiator"] = input.Payload
						mac, _ := cryptox.DecodeBase64(input.Payload, 32, 32)
						if e := manager.VerifyPeerConfirmation(mac); e == nil {
							transcript, e := manager.TranscriptHash()
							if e != nil {
								t.Error(e)
								w.WriteHeader(500)
								return
							}
							a := f.Approval
							a.Context = cryptox.EnrollmentContext(status.Context)
							a.TranscriptHash = transcript
							a.ApproverSignature = ""
							a.InitiatorSignature = ""
							confirmed := cryptox.ConfirmedEnrollmentAnchor{Context: a.Context, TranscriptHash: transcript}
							a, e = cryptox.SignEnrollmentApprovalV2(a, rootPin, confirmed, bk, time.Now())
							if e != nil {
								t.Error(e)
								w.WriteHeader(500)
								return
							}
							status.Approval = &a
							status.State = "approved"
						} else if mode != "wrong-code" {
							t.Error(e)
						}
					}
				} else if strings.HasSuffix(r.URL.Path, "/complete") {
					completeCalls++
					var input struct {
						Signature string `json:"signature"`
					}
					_ = json.Unmarshal(body, &input)
					a := *status.Approval
					cert, e := a.Certificate()
					if e != nil || cryptox.VerifyEnrollmentCertificateV2(cert, input.Signature, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)).Public().(ed25519.PublicKey)) != nil {
						t.Error("invalid initiator exact v2 signature")
						w.WriteHeader(403)
						return
					}
					a.InitiatorSignature = input.Signature
					status.Approval = &a
					status.State = "complete"
					seq := uint64(5)
					status.Sequence = &seq
					// 已原子接受但断开结果：只能查询同一回执，不能重新取得短码或扩大证明。
					w.WriteHeader(503)
					return
				} else if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/pairings-v2/pair-C") {
					t.Error("wrong v2 route")
					w.WriteHeader(404)
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
			cfg := EnrollmentConfig{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: "account-chain", AccountGeneration: 1, DeviceID: "device-C", LoginToken: cryptox.EncodeBase64(make([]byte, 32)), SigningKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)), ReceivingPrivateKey: bytes.Repeat([]byte{13}, 32), Engine: testEngine(t), Now: func() time.Time { return time.Now() }}
			enrollment, err := NewEnrollmentV2(cfg)
			check(t, err)
			defer enrollment.Close()
			_, err = enrollment.Begin(context.Background(), "device-B", "pair-C", []byte("12345678"))
			if mode == "downgrade" {
				if err == nil {
					t.Fatal("silently downgraded")
				}
				return
			}
			check(t, err)
			_, err = enrollment.Advance(context.Background())
			if mode == "wrong-code" {
				if !errors.Is(err, pairing.ErrConfirmation) || completeCalls != 0 {
					t.Fatal("wrong code accepted", err)
				}
				return
			}
			check(t, err)
			receipt, err := enrollment.Receipt()
			check(t, err)
			if receipt.Approval.InitiatorSignature == "" || len(receipt.Approval.IssuerProof.Path) != 1 {
				t.Fatal("missing real PAKE dual-signed proof")
			}
			if _, err = enrollment.Complete(context.Background()); !errors.Is(err, ErrEnrollmentPending) {
				t.Fatal("unknown result mistaken as accepted", err)
			}
			resumed, err := ResumeEnrollmentV2(cfg, receipt)
			check(t, err)
			defer resumed.Close()
			result, err := resumed.Complete(context.Background())
			check(t, err)
			defer result.Verifier.Close()
			if completeCalls != 1 || result.Sequence != 5 || resumed.session != nil || len(result.Verifier.IssuerBindings()) != 2 {
				t.Fatal("resume rewrote completion/trust")
			}
			state, err := result.Verifier.VerifyPull(context.Background(), issuerClientPull(f), cfg.Engine.State().Cloud)
			check(t, err)
			if state.Environments["env-fixture"].Values["FIXTURE_KEY"] != "synthetic-only" {
				t.Fatal("confirmed enrollment cannot read A history")
			}
		})
	}
}
