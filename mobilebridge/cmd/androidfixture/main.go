// 仅本机合成 Android 验收入口：临时 SQLite、捕获 .invalid 邮件、显式临时 CA 和响应丢失。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "synthetic Android fixture failed")
		os.Exit(1)
	}
}
func run() error {
	workspace := flag.String("workspace", "", "Harmonia workspace source root")
	output := flag.String("output", "", "ignored fixture public CA directory")
	port := flag.Int("port", 4443, "loopback TLS port")
	flag.Parse()
	if *workspace == "" || *output == "" || *port < 1024 || *port > 65535 {
		return fmt.Errorf("invalid fixture config")
	}
	cmd := exec.Command("node", "--import", "tsx", "tests/synthetic-server.ts", "--capture-email")
	cmd.Dir = filepath.Join(*workspace, "server")
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return e
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		return e
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
	}()
	reader := bufio.NewReader(stdout)
	line, e := reader.ReadBytes('\n')
	if e != nil {
		return e
	}
	var ready struct {
		Endpoint string `json:"endpoint"`
	}
	if json.Unmarshal(line, &ready) != nil {
		return fmt.Errorf("invalid ready")
	}
	clear(line)
	backend, e := url.Parse(ready.Endpoint)
	if e != nil || backend.Scheme != "http" || backend.Hostname() != "127.0.0.1" {
		return fmt.Errorf("invalid backend")
	}
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Harmonia synthetic Android test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return e
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Harmonia loopback fixture"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("10.0.2.2"), net.ParseIP("127.0.0.1")}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if e != nil {
		return e
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if e = os.MkdirAll(*output, 0700); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(*output, "ca.pem"), caPEM, 0600); e != nil {
		return e
	}
	var lose atomic.Value
	lose.Store("")
	var submitted atomic.Uint64
	var approvals atomic.Uint64
	var approvalsV3 atomic.Uint64
	proxy := httputil.NewSingleHostReverseProxy(backend)
	proxy.ModifyResponse = func(r *http.Response) error {
		if r.Request.Method != "POST" || r.StatusCode != 200 {
			return nil
		}
		kind := ""
		p := r.Request.URL.Path
		if strings.HasSuffix(p, "/complete") && strings.Contains(p, "/vault-initializations/") {
			kind = "init"
		} else if strings.Contains(p, "/pairings-v2/") && strings.HasSuffix(p, "/approve") {
			kind = "approval"
			approvals.Add(1)
		} else if strings.Contains(p, "/pairings-v3/") && strings.HasSuffix(p, "/approve") {
			kind = "approvalV3"
			approvalsV3.Add(1)
		} else if strings.HasSuffix(p, "/device-revocations/complete") {
			kind = "revocation"
		} else if strings.HasSuffix(p, "/mutations") {
			kind = "mutation"
			submitted.Add(1)
		} else if strings.HasSuffix(p, "/environment-changes") {
			kind = "environment"
		}
		if kind != "" && lose.CompareAndSwap(kind, "") {
			_ = r.Body.Close()
			body := []byte(`{"error":"synthetic_lost_response"}`)
			r.StatusCode = 502
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			r.Header.Set("Content-Length", fmt.Sprint(len(body)))
		}
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/test/control", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Lose string `json:"lose"`
		}
		d := json.NewDecoder(io.LimitReader(r.Body, 128))
		d.DisallowUnknownFields()
		if d.Decode(&body) != nil || (body.Lose != "init" && body.Lose != "mutation" && body.Lose != "environment" && body.Lose != "revocation" && body.Lose != "approval" && body.Lose != "approvalV3") {
			http.Error(w, "invalid", 400)
			return
		}
		lose.Store(body.Lose)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/test/counters", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]uint64{"mutations": submitted.Load(), "approvals": approvals.Load(), "approvalsV3": approvalsV3.Load()})
	})
	mux.Handle("/", proxy)
	server := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", *port), Handler: mux, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}}}
	listener, e := net.Listen("tcp", server.Addr)
	if e != nil {
		return e
	}
	defer listener.Close()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		<-signals
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	fmt.Println("synthetic Android HTTPS fixture ready")
	e = server.Serve(tls.NewListener(listener, server.TLSConfig))
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
