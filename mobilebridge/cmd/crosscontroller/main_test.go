package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/harmonia-vault/core-go/pairing"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestAnonymousCLIOutputConsumedAndSecretCleared(t *testing.T) {
	code, e := pairing.GenerateShortCode()
	if e != nil {
		t.Fatal("synthetic generation failed")
	}
	defer clear(code)
	var raw bytes.Buffer
	raw.WriteString(prefixID + "pair-test\n" + prefixCode)
	raw.Write(code)
	raw.WriteString("\nother CLI output is discarded\n")
	calls := 0
	var reference []byte
	e = consumeCLI(&raw, func(id string, value []byte) error {
		calls++
		reference = value
		if id != "pair-test" || !bytes.Equal(value, code) {
			t.Fatal("pipe payload mismatch")
		}
		return nil
	})
	if e != nil || calls != 1 || !bytes.Equal(reference, make([]byte, 8)) {
		t.Fatal("pipe did not clear or failed")
	}
}
func TestMalformedCLIOutputFailsClosed(t *testing.T) {
	for _, value := range []string{prefixCode + "\n", prefixID + "../invalid\n", string(bytes.Repeat([]byte{'x'}, 4097)), prefixID + "pair-test\n" + prefixCode + "not-digits\n"} {
		if consumeCLI(bytes.NewBufferString(value), func(string, []byte) error { t.Fatal("invalid pipe forwarded"); return nil }) == nil {
			t.Fatal("invalid output accepted")
		}
	}
}
func TestBoundedLocalSocketFrameAndMetadataAcknowledgement(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal("listener unavailable")
	}
	defer listener.Close()
	code, e := pairing.GenerateShortCode()
	if e != nil {
		t.Fatal("synthetic generation failed")
	}
	defer clear(code)
	received := make(chan bool, 1)
	go func() {
		connection, e := listener.Accept()
		if e != nil {
			received <- false
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 8)
		_, e = io.ReadFull(connection, header)
		valid := e == nil && string(header) == pipeMagic
		var n uint16
		_ = binary.Read(connection, binary.BigEndian, &n)
		id := make([]byte, n)
		_, _ = io.ReadFull(connection, id)
		_ = binary.Read(connection, binary.BigEndian, &n)
		env := make([]byte, n)
		_, _ = io.ReadFull(connection, env)
		var expiry uint64
		_ = binary.Read(connection, binary.BigEndian, &expiry)
		tail := make([]byte, 9)
		_, e = io.ReadFull(connection, tail)
		valid = valid && e == nil && string(id) == "pair-test" && string(env) == "synthetic-env" && tail[0] == 2 && bytes.Equal(tail[1:], code) && expiry > uint64(time.Now().Unix())
		clear(tail)
		_, _ = io.WriteString(connection, "RECEIVED\n")
		received <- valid
	}()
	_, portString, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portString)
	state, e := relay(context.Background(), port, intent{id: "pair-test", environment: "synthetic-env", expiry: uint64(time.Now().Add(time.Hour).Unix()), code: code})
	if e != nil || state != "RECEIVED" || !<-received {
		t.Fatal("local transport did not validate")
	}
}
