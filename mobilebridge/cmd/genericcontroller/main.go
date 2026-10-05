// 仅独立合成Android cert3夹具；短码只在本机内存/socket，不进入HTTP/参数/日志/磁盘。
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
	"github.com/harmonia-vault/core-go/pairing"
)

var errFixture = errors.New("synthetic generic controller failed")

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "synthetic generic controller failed")
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
	ctx, deadline := context.WithTimeout(ctx, 150*time.Second)
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
	email := "native-generic-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "@example.invalid"
	password := "synthetic-cross-password-only"
	registration, err := w.Register(ctx, email, password)
	if err != nil {
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
	var proof mobileworkflow.EmailVerification
	found := false
	for _, mail := range emails {
		if mail.To == email {
			for _, line := range strings.Split(mail.Text, "\n") {
				if code, ok := strings.CutPrefix(line, "验证码："); ok && len(code) == 8 {
					proof = mobileworkflow.EmailVerification{AccountID: registration.AccountID, AccountGeneration: registration.AccountGeneration, Code: code}
					found = true
				}
			}
		}
	}
	if !found || w.VerifyEmail(ctx, proof) != nil || w.Login(ctx, email, password) != nil {
		return errFixture
	}
	recoveryCode, err := w.BeginInitialization(ctx, "合成X", "native-generic-init")
	if err != nil {
		return errFixture
	}
	view, err := w.CompleteInitialization(ctx, recoveryCode)
	recoveryCode = ""
	if err != nil || len(view.Environments) != 1 {
		return errFixture
	}
	x := view.Environments[0].ID
	view, err = w.CreateEnvironment(ctx, "合成Y", "native-generic-y")
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
	if _, err = w.SetVariable(ctx, x, "SYNTHETIC_X_ONLY", "synthetic-x-denied", "native-generic-x-value"); err != nil {
		return errFixture
	}
	code, err := pairing.GenerateShortCode()
	if err != nil {
		return errFixture
	}
	defer clear(code)
	randomID := make([]byte, 16)
	if _, err = rand.Read(randomID); err != nil {
		return errFixture
	}
	id := "pair-b-" + hex.EncodeToString(randomID)
	public, err := json.Marshal(map[string]string{"email": email, "approver": view.DeviceID, "x": x, "y": y, "pairingId": id})
	if err != nil || len(public) > 2048 {
		return errFixture
	}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)), 10*time.Second)
	if err != nil {
		return errFixture
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(130 * time.Second))
	var frame bytes.Buffer
	frame.WriteString("HARMEN03")
	binary.Write(&frame, binary.BigEndian, uint16(len(public)))
	frame.Write(public)
	frame.Write(code)
	if _, err = connection.Write(frame.Bytes()); err != nil {
		clear(frame.Bytes())
		return errFixture
	}
	clear(frame.Bytes())
	fmt.Println("synthetic root A initialized X/Y; local cert3 B enrollment intent relayed")
	selection := []mobileworkflow.ApprovalSelection{{EnvironmentID: y, Role: "admin", ExpiresAt: "0"}}
	var approved mobileworkflow.ApprovalResult
	for {
		approved, err = w.ApprovePairingV5(ctx, mobileworkflow.ApprovalInput{PairingID: id, ShortCode: code, Selections: selection})
		if err == nil {
			break
		}
		if approved.PairingID != "" || ctx.Err() != nil {
			return errFixture
		}
		select {
		case <-ctx.Done():
			return errFixture
		case <-time.After(100 * time.Millisecond):
		}
	}
	if approved.State != "approved" && approved.State != "complete" {
		return errFixture
	}
	clear(code)
	ack, err := bufio.NewReader(io.LimitReader(connection, 32)).ReadBytes('\n')
	defer clear(ack)
	if err != nil || string(ack) != "CANDIDATE_COMPLETED\n" {
		return errFixture
	}
	result, err := w.RetryApprovalV5(ctx, id)
	if err != nil || result.State != "complete" || result.Sequence == 0 {
		return errFixture
	}
	if _, err = io.WriteString(connection, "ROOT_COMPLETE\n"); err != nil {
		return errFixture
	}
	fmt.Println("root A verified B cert3 double-signature completion; Y-only admin, X excluded")
	return nil
}
