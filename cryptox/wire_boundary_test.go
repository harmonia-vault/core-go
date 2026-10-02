package cryptox

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestMaximumPacketCrossLanguageVector(t *testing.T) {
	b, err := os.ReadFile("testdata/max-packet-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Mutation      Mutation `json:"mutationTemplate"`
		PacketBytes   int      `json:"packetBytes"`
		FillByte      byte     `json:"syntheticPacketFillByte"`
		SigningSHA256 string   `json:"signingSha256"`
		Signature     string   `json:"signature"`
		SeedHex       string   `json:"syntheticSigningSeedHex"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.PacketBytes != MaxValueBytes+40 {
		t.Fatal("maximum packet contract drift")
	}
	packet := make([]byte, v.PacketBytes)
	for i := range packet {
		packet[i] = v.FillByte
	}
	v.Mutation.Payload = EncodeBase64(packet)
	encoded, err := v.Mutation.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(encoded)
	if hex.EncodeToString(hash[:]) != v.SigningSHA256 {
		t.Fatal("maximum signing bytes drift")
	}
	sk := ed25519.NewKeyFromSeed(mustHex(t, v.SeedHex))
	signed, err := SignMutation(v.Mutation, sk)
	if err != nil || signed.Signature != v.Signature {
		t.Fatal("maximum packet signature mismatch")
	}
	v.Mutation.Payload = EncodeBase64(append(packet, 0))
	if _, err := v.Mutation.SigningBytes(); err == nil {
		t.Fatal("accepted packet over maximum")
	}
}
