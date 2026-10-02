package syncclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// 本测试只隔离已验证检查点与批量确认合同；真实签名/AEAD/HTTPS
// 轮换由来源证明测试和 workspace 原生联合验收覆盖。
type environmentBatchVerifier struct {
	snapshot localstate.CloudSnapshot
}

func (v environmentBatchVerifier) VerifyPull(context.Context, Pull, localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	return v.snapshot, nil
}
func TestEnvironmentBatchConfirmationBindsHeadTailAndEveryInnerCheckpoint(t *testing.T) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	check(t, e)
	change := environmentWrapperChange(t).Change
	change.Operation = "rotate"
	change.KeyVersion = "2"
	change.RecoveryEnvelope = cryptox.EncodeBase64(make([]byte, 80))
	for _, item := range []struct{ name, id string }{{"FIRST_VALUE", "rotate-first"}, {"SECOND_VALUE", "rotate-second"}} {
		m, e := cryptox.SignMutation(cryptox.Mutation{AccountID: "acct", AccountGeneration: "1", DeviceID: "dev", EnvironmentID: "env", KeyVersion: "2", GrantGeneration: "2", Operation: "put", IdempotencyKey: item.id, Name: item.name, Payload: cryptox.EncodeBase64(make([]byte, 40))}, key)
		check(t, e)
		change.Mutations = append(change.Mutations, cryptox.MutationToWire(m))
	}
	signed, e := cryptox.SignEnvironmentChange(change, key)
	check(t, e)
	for _, name := range []string{"complete", "permuted-inner-order", "missing-inner", "wrong-inner-hash", "duplicate-inner-sequence", "inner-at-head", "inner-past-tail", "wrong-environment-head", "wrong-receipt-tail"} {
		t.Run(name, func(t *testing.T) {
			wire, e := change.SigningBytes()
			check(t, e)
			snapshot := localstate.CloudSnapshot{AccountID: "acct", AccountGeneration: 1, Sequence: 10, Environments: map[string]localstate.Environment{}, EnvironmentCheckpoints: map[string]localstate.MutationCheckpoint{"dev/env-write": {Sequence: 8, Fingerprint: digest(wire)}}, SeenMutations: map[string]localstate.MutationCheckpoint{}}
			for i, m := range change.Mutations {
				b, e := m.Mutation.SigningBytes()
				check(t, e)
				snapshot.SeenMutations["dev/"+m.Mutation.IdempotencyKey] = localstate.MutationCheckpoint{Sequence: uint64(9 + i), Fingerprint: digest(b)}
			}
			point := snapshot.SeenMutations["dev/rotate-first"]
			tail := uint64(10)
			switch name {
			case "permuted-inner-order":
				point.Sequence = 10
				second := snapshot.SeenMutations["dev/rotate-second"]
				second.Sequence = 9
				snapshot.SeenMutations["dev/rotate-second"] = second
			case "missing-inner":
				delete(snapshot.SeenMutations, "dev/rotate-second")
			case "wrong-inner-hash":
				point.Fingerprint = digest([]byte("different-synthetic-mutation"))
			case "duplicate-inner-sequence":
				point.Sequence = 10
			case "inner-at-head":
				point.Sequence = 8
			case "inner-past-tail":
				point.Sequence = 11
			case "wrong-environment-head":
				p := snapshot.EnvironmentCheckpoints["dev/env-write"]
				p.Sequence = 10
				snapshot.EnvironmentCheckpoints["dev/env-write"] = p
			case "wrong-receipt-tail":
				tail = 9
			}
			snapshot.SeenMutations["dev/rotate-first"] = point
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(Pull{AccountID: "acct", AccountGeneration: "1", Sequence: 10})
			}))
			defer server.Close()
			client := testClient(t, server, testEngine(t), environmentBatchVerifier{snapshot})
			result, e := client.ConfirmEnvironmentChange(context.Background(), signed, Acceptance{Sequence: tail})
			good := name == "complete" || name == "permuted-inner-order"
			if good && (e != nil || !result.Applied) || !good && (!errors.Is(e, ErrAcceptedNotApplied) || result.Applied) {
				t.Fatal("batch confirmed without exact original checkpoints", e)
			}
		})
	}
}
