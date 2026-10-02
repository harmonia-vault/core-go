package pairing

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// 此向量只校验应用层编码、HKDF 与 HMAC，不冒充上游 SPAKE2 固定向量。
func TestApplicationConfirmationVector(t *testing.T) {
	data, err := os.ReadFile("testdata/pairing-application-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Context                  Context `json:"context"`
		CanonicalContext         string  `json:"canonicalContext"`
		InitiatorIdentity        string  `json:"initiatorIdentity"`
		ApproverIdentity         string  `json:"approverIdentity"`
		RawKeyHex                string  `json:"syntheticRawKeyHex"`
		InitiatorMessageHex      string  `json:"syntheticInitiatorMessageHex"`
		ApproverMessageHex       string  `json:"syntheticApproverMessageHex"`
		InitiatorConfirmationHex string  `json:"initiatorConfirmationHex"`
		ApproverConfirmationHex  string  `json:"approverConfirmationHex"`
		ChannelKeyHex            string  `json:"channelKeyHex"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	context, err := v.Context.CanonicalBytes()
	if err != nil || string(context) != v.CanonicalContext {
		t.Fatalf("上下文编码不同: %v", err)
	}
	for role, expected := range map[string]string{"initiator": v.InitiatorIdentity, "approver": v.ApproverIdentity} {
		identity, err := v.Context.identity(role)
		if err != nil || string(identity) != expected {
			t.Fatalf("身份编码不同 %s: %v", role, err)
		}
	}
	decode := func(value string) []byte {
		b, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	raw, amsg, bmsg := decode(v.RawKeyHex), decode(v.InitiatorMessageHex), decode(v.ApproverMessageHex)
	a, b, channel, err := confirmationMaterial(v.Context, raw, amsg, bmsg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, decode(v.InitiatorConfirmationHex)) || !bytes.Equal(b, decode(v.ApproverConfirmationHex)) || !bytes.Equal(channel, decode(v.ChannelKeyHex)) {
		t.Fatal("HKDF/HMAC 应用层向量不匹配")
	}
	if bytes.Equal(a, b) {
		t.Fatal("两角色确认值未分离")
	}
	_, _, swapped, err := confirmationMaterial(v.Context, raw, bmsg, amsg)
	if err != nil || bytes.Equal(swapped, channel) {
		t.Fatal("交换消息未改变通道绑定")
	}
}
