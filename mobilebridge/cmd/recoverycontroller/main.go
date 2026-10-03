// 仅独立合成Android连续恢复/cert4夹具；完整码仅本机RAM/socket，不进入参数/日志/磁盘。
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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
)

var errFixture = errors.New("synthetic recovery controller failed")

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "synthetic recovery controller failed")
		os.Exit(1)
	}
}
func run() error {
	endpoint := flag.String("endpoint", "", "explicit loopback HTTPS endpoint")
	caFile := flag.String("ca-file", "", "public synthetic CA PEM")
	port := flag.Int("port", 0, "local ADB test socket port")
	flag.Parse()
	if *endpoint != "https://127.0.0.1:4443" || *port < 1024 || *port > 65535 || *caFile == "" {
		return errFixture
	}
	ca, err := os.ReadFile(*caFile)
	if err != nil {
		return errFixture
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errFixture
	}
	httpClient := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, 480*time.Second)
	defer deadline()
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errFixture
	}
	defer clear(sign)
	_, receive, err := cryptox.GenerateReceivingKey()
	if err != nil {
		return errFixture
	}
	defer clear(receive)
	var protected []byte
	defer func() { clear(protected) }()
	w, err := mobileworkflow.New(mobileworkflow.Config{Endpoint: *endpoint, HTTPClient: httpClient, SigningKey: sign, ReceivingPrivateKey: receive, SaveProtectedState: func(b []byte) error { clear(protected); protected = bytes.Clone(b); return nil }})
	if err != nil {
		return errFixture
	}
	defer w.Close()
	clear(sign)
	clear(receive)
	email := "native-recovery-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "@example.invalid"
	password := "synthetic-cross-password-only"
	if _, err = w.Register(ctx, email, password); err != nil {
		return errFixture
	}
	request, err := http.NewRequestWithContext(ctx, "GET", *endpoint+"/test/emails", nil)
	if err != nil {
		return errFixture
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return errFixture
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		clear(raw)
		return errFixture
	}
	var emails []struct {
		To   string `json:"to"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &emails) != nil {
		clear(raw)
		return errFixture
	}
	clear(raw)
	var proof mobileworkflow.EmailProof
	found := false
	for _, mail := range emails {
		if mail.To == email {
			for _, line := range strings.Split(mail.Text, "\n") {
				if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &proof) == nil {
					found = true
				}
			}
		}
	}
	if !found || w.VerifyEmail(ctx, proof) != nil || w.Login(ctx, email, password) != nil {
		return errFixture
	}
	recoveryCode, err := w.BeginInitialization(ctx, "合成X", "native-recovery-init")
	if err != nil {
		return errFixture
	}
	view, err := w.CompleteInitialization(ctx, recoveryCode)
	if err != nil || len(view.Environments) != 1 {
		return errFixture
	}
	x := view.Environments[0].ID
	view, err = w.CreateEnvironment(ctx, "合成Y", "native-recovery-y")
	if err != nil || len(view.Environments) != 2 {
		return errFixture
	}
	y := ""
	for _, environment := range view.Environments {
		if environment.ID != x {
			y = environment.ID
		}
	}
	if y == "" {
		return errFixture
	}
	if _, err = w.SetVariable(ctx, x, "SYNTHETIC_X_ONLY", "synthetic-x-denied", "native-recovery-x-value"); err != nil {
		return errFixture
	}
	if _, err = w.SetVariable(ctx, y, "SYNTHETIC_CROSS", "synthetic-cross-value", "native-recovery-y-value"); err != nil {
		return errFixture
	}
	if _, err = w.RotateEnvironment(ctx, x, "native-recovery-rotate-x"); err != nil {
		return errFixture
	}
	result, err := w.RevokeSelf(ctx, "native-recovery-revoke-a")
	if err != nil || !result.Completed || !result.DeviceInvalidated {
		return errFixture
	}
	w.Close()
	oldCode := []byte(recoveryCode)
	recoveryCode = ""
	defer clear(oldCode)
	public, err := json.Marshal(map[string]string{"email": email, "x": x, "y": y})
	if err != nil || len(public) > 2048 {
		return errFixture
	}
	send := func(phase byte, code []byte) (net.Conn, error) {
		var c net.Conn
		for {
			c, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)), time.Second)
			if err == nil {
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				ready := make([]byte, 6)
				_, err = io.ReadFull(c, ready)
				if err == nil && string(ready) == "READY\n" {
					break
				}
				c.Close()
			}
			select {
			case <-ctx.Done():
				return nil, errFixture
			case <-time.After(100 * time.Millisecond):
			}
		}
		c.SetDeadline(time.Now().Add(180 * time.Second))
		var packet bytes.Buffer
		packet.WriteString("HARMRC0")
		packet.WriteByte(phase)
		binary.Write(&packet, binary.BigEndian, uint16(len(public)))
		packet.Write(public)
		binary.Write(&packet, binary.BigEndian, uint16(len(code)))
		packet.Write(code)
		_, err = c.Write(packet.Bytes())
		clear(packet.Bytes())
		if err != nil {
			c.Close()
			return nil, errFixture
		}
		return c, nil
	}
	c, err := send('1', oldCode)
	clear(oldCode)
	if err != nil {
		return errFixture
	}
	fmt.Println("synthetic root A X/Y initialized, X keyVersion2, all prior devices revoked; old code RAM relay")
	input := bufio.NewReader(c)
	magic := make([]byte, 8)
	if _, err = io.ReadFull(input, magic); err != nil || string(magic) != "HARMRN01" {
		c.Close()
		return errFixture
	}
	var n uint16
	if binary.Read(input, binary.BigEndian, &n) != nil || n == 0 || n > 1024 {
		c.Close()
		return errFixture
	}
	newCode := make([]byte, n)
	defer clear(newCode)
	if _, err = io.ReadFull(input, newCode); err != nil {
		c.Close()
		return errFixture
	}
	seed, err := cryptox.DecodeRecoveryCode(string(newCode))
	clear(seed)
	if err != nil {
		c.Close()
		return errFixture
	}
	if _, err = io.WriteString(c, "NEW_CODE_HELD\n"); err != nil {
		c.Close()
		return errFixture
	}
	c.Close()
	// 下一instrumentation真实force-stop后，只有本host进程保留显示过的完整新码。
	c, err = send('2', newCode)
	if err != nil {
		return errFixture
	}
	ack, err := bufio.NewReader(io.LimitReader(c, 64)).ReadBytes('\n')
	c.Close()
	if err != nil || string(ack) != "REGISTRATION_PENDING\n" {
		clear(ack)
		return errFixture
	}
	clear(ack)
	clear(newCode)
	fmt.Println("native original transition restored after process stop; cert4 accepted-not-applied acknowledged")
	c, err = send('3', nil)
	if err != nil {
		return errFixture
	}
	ack, err = bufio.NewReader(io.LimitReader(c, 64)).ReadBytes('\n')
	c.Close()
	if err != nil || string(ack) != "RECOVERED_TRUSTED\n" {
		clear(ack)
		return errFixture
	}
	clear(ack)
	fmt.Println("native original cert4 enrollment applied after second process stop; no code retained")
	return nil
}
