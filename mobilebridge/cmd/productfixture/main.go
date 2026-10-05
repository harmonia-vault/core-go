// 只用于本机合成Flutter产品链：真实空实例、临时TLS和固定公开计数，不种入可信身份。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
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
	if run() != nil {
		fmt.Fprintln(os.Stderr, "synthetic product fixture failed")
		os.Exit(1)
	}
}

func decodeStrict(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("synthetic wire invalid")
	}
	return nil
}

func readyPort(body []byte) (int, error) {
	var record struct {
		Port        int    `json:"port"`
		MailboxPath string `json:"mailboxPath"`
	}
	if len(body) > 2048 || decodeStrict(body, &record) != nil || record.Port < 1024 || record.Port > 65535 || record.MailboxPath != "/test/emails" {
		return 0, errors.New("synthetic empty-server ready invalid")
	}
	return record.Port, nil
}

func verifyEmptyInstance(body []byte) error {
	var record struct {
		Product  string `json:"product"`
		Status   string `json:"status"`
		Protocol struct {
			SupportedMajors []int    `json:"supportedMajors"`
			Capabilities    []string `json:"capabilities"`
		} `json:"protocol"`
		InitialRegistrationAvailable *bool `json:"initialRegistrationAvailable"`
		AllowRegistration            *bool `json:"allowRegistration"`
		EmailVerificationRequired    *bool `json:"emailVerificationRequired"`
	}
	if len(body) > 4096 || decodeStrict(body, &record) != nil || record.Product != "harmonia" || record.Status != "experimental" || len(record.Protocol.SupportedMajors) != 1 || record.Protocol.SupportedMajors[0] != 1 || len(record.Protocol.Capabilities) != 2 || record.Protocol.Capabilities[0] != "registration-policy-v1" || record.Protocol.Capabilities[1] != "email-proof-v1" || record.InitialRegistrationAvailable == nil || !*record.InitialRegistrationAvailable || record.AllowRegistration == nil || *record.AllowRegistration || record.EmailVerificationRequired == nil || !*record.EmailVerificationRequired {
		return errors.New("synthetic initial-registration metadata invalid")
	}
	return nil
}

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
func keyID(key *ecdsa.PublicKey) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return bytes.Clone(digest[:20]), nil
}
func ephemeralTLS(now time.Time) (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caSerial, err := serial()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafSerial, err := serial()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caID, err := keyID(&caKey.PublicKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafID, err := keyID(&leafKey.PublicKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	ca := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "Harmonia synthetic empty-instance CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: caID, AuthorityKeyId: caID}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: "Harmonia product loopback"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, SubjectKeyId: leafID, AuthorityKeyId: caID, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("10.0.2.2"), net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	// 两个private signer只活在此进程，不生成private PEM或磁盘钥匙。
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}

type counters struct {
	Inspect                atomic.Uint64
	RegistrationAttempt    atomic.Uint64
	RegistrationAccepted   atomic.Uint64
	EmailProofAttempt      atomic.Uint64
	EmailProofAccepted     atomic.Uint64
	LoginAttempt           atomic.Uint64
	LoginAccepted          atomic.Uint64
	InitializationAccepted atomic.Uint64
	BootAccepted           atomic.Uint64
	PullAccepted           atomic.Uint64
	MutationAttempt        atomic.Uint64
	MutationAccepted       atomic.Uint64
	EnvironmentAttempt     atomic.Uint64
	EnvironmentAccepted    atomic.Uint64
	ApprovalV5Attempt      atomic.Uint64
	ApprovalV5Accepted     atomic.Uint64
}

func (c *counters) public() map[string]uint64 {
	return map[string]uint64{"instanceInfo": c.Inspect.Load(), "registerAttempts": c.RegistrationAttempt.Load(), "registerAccepted": c.RegistrationAccepted.Load(), "emailProofAttempts": c.EmailProofAttempt.Load(), "emailProofAccepted": c.EmailProofAccepted.Load(), "loginAttempts": c.LoginAttempt.Load(), "loginAccepted": c.LoginAccepted.Load(), "initializationAccepted": c.InitializationAccepted.Load(), "bootAccepted": c.BootAccepted.Load(), "pullAccepted": c.PullAccepted.Load(), "mutationAttempts": c.MutationAttempt.Load(), "mutationAccepted": c.MutationAccepted.Load(), "environmentAttempts": c.EnvironmentAttempt.Load(), "environmentAccepted": c.EnvironmentAccepted.Load(), "approvalV5Attempts": c.ApprovalV5Attempt.Load(), "approvalV5Accepted": c.ApprovalV5Accepted.Load()}
}
func (c *counters) response(r *http.Response, lose *atomic.Value) error {
	path := r.Request.URL.Path
	post := r.Request.Method == "POST"
	accepted := r.StatusCode == 200
	kind := ""
	switch {
	case !post && r.Request.Method == "GET" && path == "/instance-info":
		c.Inspect.Add(1)
	case post && path == "/v1/register":
		c.RegistrationAttempt.Add(1)
		if accepted {
			c.RegistrationAccepted.Add(1)
		}
	case post && path == "/v1/login":
		c.LoginAttempt.Add(1)
		if accepted {
			c.LoginAccepted.Add(1)
		}
	case post && strings.Contains(path, "/email-verification/") && strings.HasSuffix(path, "/complete"):
		c.EmailProofAttempt.Add(1)
		if accepted {
			c.EmailProofAccepted.Add(1)
		}
	case post && strings.Contains(path, "/vault-initializations/") && strings.HasSuffix(path, "/complete"):
		if accepted {
			c.InitializationAccepted.Add(1)
		}
	case post && strings.HasSuffix(path, "/boot-sessions"):
		if accepted {
			c.BootAccepted.Add(1)
		}
	case !post && r.Request.Method == "GET" && strings.HasSuffix(path, "/pull"):
		if accepted {
			c.PullAccepted.Add(1)
		}
	case post && strings.HasSuffix(path, "/mutations"):
		c.MutationAttempt.Add(1)
		if accepted {
			c.MutationAccepted.Add(1)
			kind = "mutation"
		}
	case post && strings.HasSuffix(path, "/environment-changes-v4"):
		c.EnvironmentAttempt.Add(1)
		if accepted {
			c.EnvironmentAccepted.Add(1)
			kind = "environment"
		}
	case post && strings.Contains(path, "/pairings-v5/") && strings.HasSuffix(path, "/approve"):
		c.ApprovalV5Attempt.Add(1)
		if accepted {
			c.ApprovalV5Accepted.Add(1)
			kind = "approvalV5"
		}
	}
	if kind != "" && lose.CompareAndSwap(kind, "") {
		_ = r.Body.Close()
		body := []byte(`{"error":"synthetic_lost_response"}`)
		r.StatusCode = http.StatusBadGateway
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Length", fmt.Sprint(len(body)))
	}
	return nil
}
func testProjection(c *counters, lose *atomic.Value, proxy http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/test/counters", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" || r.URL.RawQuery != "" || r.URL.ForceQuery {
			http.Error(w, "invalid", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c.public())
	})
	mux.HandleFunc("/test/control", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var input struct {
			Lose string `json:"lose"`
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 129))
		if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.ForceQuery || err != nil || len(body) > 128 || decodeStrict(body, &input) != nil || (input.Lose != "mutation" && input.Lose != "environment" && input.Lose != "approvalV5") {
			http.Error(w, "invalid", 400)
			return
		}
		lose.Store(input.Lose)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	mux.Handle("/", proxy)
	return mux
}

func run() error {
	workspace := flag.String("workspace", "", "fixed public source workspace")
	output := flag.String("output", "", "new ignored public fixture config directory")
	port := flag.Int("port", 4443, "loopback TLS port")
	flag.Parse()
	if *workspace == "" || *output == "" || !filepath.IsAbs(*workspace) || !filepath.IsAbs(*output) || filepath.Clean(*workspace) != *workspace || filepath.Clean(*output) != *output || *port < 1024 || *port > 65535 || flag.NArg() != 0 {
		return errors.New("fixture config invalid")
	}
	if _, err := os.Lstat(*output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixture output must be new")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		return err
	}
	cmd := exec.Command(node, "--import", "tsx", "tests/synthetic-registration-server.ts", "--capture-email", "--require-email-verification")
	cmd.Dir = filepath.Join(*workspace, "server")
	// 子进程不继承宿主邮件/云端/用户凭据环境，只给固定本机运行路径。
	cmd.Env = []string{"PATH=" + filepath.Dir(node) + ":/usr/bin:/bin", "NODE_ENV=test"}
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	type startup struct {
		port int
		err  error
	}
	ready := make(chan startup, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 2048), 2048)
		if !scanner.Scan() {
			ready <- startup{err: errors.New("empty fixture startup failed")}
			return
		}
		p, e := readyPort(scanner.Bytes())
		ready <- startup{port: p, err: e}
		for scanner.Scan() {
		}
	}()
	var backendPort int
	select {
	case value := <-ready:
		if value.err != nil {
			return value.err
		}
		backendPort = value.port
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(15 * time.Second):
		return errors.New("empty fixture startup timed out")
	}
	backend, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", backendPort))
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, "GET", backend.String()+"/instance-info", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" || verifyEmptyInstance(body) != nil {
		return errors.New("fresh fixture instance check failed")
	}
	certificate, ca, err := ephemeralTLS(time.Now())
	if err != nil {
		return err
	}
	if err = os.MkdirAll(*output, 0700); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(*output, "ca.pem"), ca, 0600); err != nil {
		return err
	}
	config, _ := json.Marshal(map[string]string{"endpoint": fmt.Sprintf("https://10.0.2.2:%d", *port), "caPem": string(ca)})
	if err = os.WriteFile(filepath.Join(*output, "product-fixture.json"), config, 0600); err != nil {
		return err
	}
	var counts counters
	var discovery publicDiscovery
	var lose atomic.Value
	lose.Store("")
	proxy := httputil.NewSingleHostReverseProxy(backend)
	proxy.Transport = transport
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	proxy.ModifyResponse = func(r *http.Response) error {
		discovery.response(r)
		return counts.response(r, &lose)
	}
	// 固定错误类别，禁止反向代理默认打印request/URL/服务响应body。
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		http.Error(w, "synthetic_upstream_unavailable", 502)
	}
	server := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", *port), Handler: withDiscovery(&discovery, testProjection(&counts, &lose, proxy)), ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Println("synthetic empty-instance HTTPS fixture ready")
	if err = server.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
