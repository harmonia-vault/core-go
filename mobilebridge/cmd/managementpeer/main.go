// 仅本机合成管理对端；真实Go入网/Pull/权限，私钥/短码/缓存只在进程内，不打印。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"github.com/harmonia-vault/core-go/pairing"
	"github.com/harmonia-vault/core-go/syncclient"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

var errFixture = errors.New("synthetic management peer failed")

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "synthetic management peer failed")
		os.Exit(1)
	}
}
func connection(port int) (net.Conn, error) {
	c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if e == nil {
		c.SetDeadline(time.Now().Add(240 * time.Second))
	}
	return c, e
}
func run() error {
	endpoint := flag.String("endpoint", "", "explicit loopback HTTPS")
	caFile := flag.String("ca-file", "", "public synthetic CA PEM")
	port := flag.Int("port", 0, "ADB local test socket port")
	flag.Parse()
	if *endpoint != "https://127.0.0.1:4443" || *port < 1024 || *port > 65535 {
		return errFixture
	}
	ca, e := os.ReadFile(*caFile)
	if e != nil {
		return errFixture
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errFixture
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, 240*time.Second)
	defer deadline()
	c, e := connection(*port)
	if e != nil {
		return errFixture
	}
	if _, e = io.WriteString(c, "HARMQR01"); e != nil {
		c.Close()
		return errFixture
	}
	var meta struct {
		Email       string `json:"email"`
		Approver    string `json:"approver"`
		Environment string `json:"environment"`
		Expiry      uint64 `json:"expiry"`
	}
	raw, e := bufio.NewReader(io.LimitReader(c, 2049)).ReadBytes('\n')
	c.Close()
	if e != nil || len(raw) > 2048 || cryptox.ValidateStrictJSON(raw, 2048) != nil || json.Unmarshal(raw, &meta) != nil {
		clear(raw)
		return errFixture
	}
	clear(raw)
	if meta.Email == "" || meta.Approver == "" || meta.Environment == "" {
		return errFixture
	}
	password, e := bufio.NewReader(io.LimitReader(os.Stdin, 16385)).ReadBytes('\n')
	if e != nil {
		return errFixture
	}
	defer clear(password)
	password = bytes.TrimSpace(password)
	_, sign, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return errFixture
	}
	defer clear(sign)
	_, receive, e := cryptox.GenerateReceivingKey()
	if e != nil {
		return errFixture
	}
	defer clear(receive)
	var protected []byte
	defer func() { clear(protected) }()
	w, e := mobileworkflow.New(mobileworkflow.Config{Endpoint: *endpoint, HTTPClient: client, SigningKey: sign, ReceivingPrivateKey: receive, SaveProtectedState: func(b []byte) error { clear(protected); protected = bytes.Clone(b); return nil }})
	if e != nil {
		return errFixture
	}
	defer w.Close()
	clear(sign)
	clear(receive)
	if w.Login(ctx, meta.Email, string(password)) != nil {
		return errFixture
	}
	clear(password)
	code, e := pairing.GenerateShortCode()
	if e != nil {
		return errFixture
	}
	defer clear(code)
	idbytes := make([]byte, 16)
	if _, e = rand.Read(idbytes); e != nil {
		return errFixture
	}
	id := "management-pair-" + hex.EncodeToString(idbytes)
	enrolled := make(chan error, 1)
	go func() {
		v, e := w.EnrollDevice(ctx, mobileworkflow.EnrollmentInput{PairingID: id, ApproverDeviceID: meta.Approver, ShortCode: code})
		if e == nil && (len(v.Environments) != 1 || v.Environments[0].ID != meta.Environment || v.Environments[0].Role != localstate.ReadWrite || v.Environments[0].Variables["SYNTHETIC_CROSS"] != "synthetic-cross-value") {
			e = errFixture
		}
		enrolled <- e
	}()
	defer func() { cancel(); w.Close() }()
	c, e = connection(*port)
	if e != nil {
		return errFixture
	}
	defer c.Close()
	var frame bytes.Buffer
	frame.WriteString("HARMPR01")
	binary.Write(&frame, binary.BigEndian, uint16(len(id)))
	frame.WriteString(id)
	binary.Write(&frame, binary.BigEndian, uint16(len(meta.Environment)))
	frame.WriteString(meta.Environment)
	binary.Write(&frame, binary.BigEndian, meta.Expiry)
	frame.WriteByte(2)
	frame.Write(code)
	if _, e = c.Write(frame.Bytes()); e != nil {
		clear(frame.Bytes())
		return errFixture
	}
	clear(frame.Bytes())
	ack, e := bufio.NewReader(io.LimitReader(c, 32)).ReadBytes('\n')
	if e != nil || string(ack) != "APPROVED\n" {
		clear(ack)
		return errFixture
	}
	clear(ack)
	select {
	case e = <-enrolled:
		if e != nil {
			return errFixture
		}
	case <-ctx.Done():
		return errFixture
	}
	clear(code)
	c.Close()
	c, e = connection(*port)
	if e != nil {
		return errFixture
	}
	if _, e = c.Write(append([]byte("HARMDN01"), 1)); e != nil {
		c.Close()
		return errFixture
	}
	ack, e = bufio.NewReader(io.LimitReader(c, 4)).ReadBytes('\n')
	c.Close()
	if e != nil || string(ack) != "OK\n" {
		clear(ack)
		return errFixture
	}
	clear(ack)
	fmt.Println("synthetic Go peer cert3 verified enrollment/Pull passed; no desktop OS authentication claim")
	c, e = connection(*port)
	if e != nil {
		return errFixture
	}
	defer c.Close()
	if _, e = io.WriteString(c, "HARMCT01"); e != nil {
		return errFixture
	}
	for _, expected := range []string{"ro", "rw", "none", "ro-newkey", "revoked"} {
		var n uint16
		if binary.Read(c, binary.BigEndian, &n) != nil || n == 0 || n > 256 {
			return errFixture
		}
		raw := make([]byte, n)
		if _, e = io.ReadFull(c, raw); e != nil {
			return errFixture
		}
		var control struct {
			State    string `json:"state"`
			Sequence uint64 `json:"sequence"`
		}
		if cryptox.ValidateStrictJSON(raw, 256) != nil || json.Unmarshal(raw, &control) != nil || control.State != expected || control.Sequence == 0 {
			return errFixture
		}
		clear(raw)
		view, e := w.Pull(ctx)
		if expected == "revoked" {
			if !errors.Is(e, syncclient.ErrTrustInvalidated) {
				return errFixture
			}
			if _, e = w.View(); !errors.Is(e, mobileworkflow.ErrClosed) {
				return errFixture
			}
		} else {
			if e != nil || view.Checkpoint < control.Sequence {
				return errFixture
			}
			if expected == "none" {
				if len(view.Environments) != 0 {
					return errFixture
				}
			} else {
				if len(view.Environments) != 1 || view.Environments[0].ID != meta.Environment {
					return errFixture
				}
			}
			switch expected {
			case "ro", "ro-newkey":
				if view.Environments[0].Role != localstate.ReadOnly {
					return errFixture
				}
				if _, e = w.SetVariable(ctx, meta.Environment, "SYNTHETIC_FORBIDDEN", "synthetic-denied", "management-peer-denied-"+expected); !errors.Is(e, localstate.ErrUnauthorized) && !errors.Is(e, syncclient.ErrWritePermission) {
					return errFixture
				}
			case "rw":
				if view.Environments[0].Role != localstate.ReadWrite {
					return errFixture
				}
				if _, e = w.SetVariable(ctx, meta.Environment, "SYNTHETIC_MANAGEMENT", "synthetic-management-value", "management-peer-write"); e != nil {
					return errFixture
				}
			case "none":
				if _, e = w.SetVariable(ctx, meta.Environment, "SYNTHETIC_FORBIDDEN", "synthetic-denied", "management-peer-denied-none"); !errors.Is(e, localstate.ErrUnauthorized) && !errors.Is(e, syncclient.ErrWritePermission) {
					return errFixture
				}
			}
		}
		if _, e = c.Write([]byte{1}); e != nil {
			return errFixture
		}
		fmt.Println("synthetic management peer verified stage", expected)
	}
	return nil
}
