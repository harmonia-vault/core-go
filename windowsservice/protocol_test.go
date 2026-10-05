package windowsservice

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestProtocolRejectsPrivilegeAndAmbiguity(t *testing.T) {
	for _, s := range []string{`{"op":"set","name":"A","value":"x","expand":false,"path":"HKLM"}`, `{"op":"read","name":"A","name":"B"}`, `{"op":"notify","name":"A"}`, `{"op":"read","name":"__harmonia_private"}`, `{"op":"read","name":null}`, `{"op":"set","name":"A","value":"x\u0000y","expand":false}`, `{"op":"delete","name":"A"} {}`} {
		if _, e := decodeRequest([]byte(s)); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	for _, r := range []request{{Op: "set", Name: "A", Value: "", Expand: false}, {Op: "set", Name: "A", Value: "%PATH%", Expand: true}, {Op: "notify"}, {Op: "read", Name: "A"}} {
		b, e := encodeRequest(r)
		if e != nil {
			t.Fatal(e)
		}
		got, e := decodeRequest(b)
		if e != nil || got != r {
			t.Fatalf("%#v %v", got, e)
		}
	}
}
func TestFrameLimitsAndShortRead(t *testing.T) {
	var b bytes.Buffer
	if writeFrame(&b, []byte("test")) != nil {
		t.Fatal("write")
	}
	got, e := readFrame(&b)
	if e != nil || string(got) != "test" {
		t.Fatal(e)
	}
	for _, size := range []uint32{0, maxFrame + 1} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], size)
		if _, e = readFrame(bytes.NewReader(h[:])); e == nil {
			t.Fatal("unbounded frame")
		}
	}
	if _, e = readFrame(bytes.NewReader([]byte{0, 0, 0, 4, 'x'})); e == nil {
		t.Fatal("short body")
	}
}
