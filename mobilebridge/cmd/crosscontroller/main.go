// crosscontroller 仅用于本机合成Android→CLI验收；所有CLI输出由匿名管道消费，绝不回显。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/harmonia-vault/core-go/pairing"
)

const prefixID = "配对申请："
const prefixCode = "请在管理手机输入本机短码："
const pipeMagic = "HARMPR01"

var publicID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var errFixture = errors.New("synthetic cross-end controller rejected input or operation")

type intent struct {
	id, environment string
	expiry          uint64
	code            []byte
}

func (i *intent) close()        { clear(i.code); i.code = nil }
func (i intent) String() string { return "native pairing test intent (secret omitted)" }
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "synthetic cross-end controller failed")
		os.Exit(1)
	}
}
func run() (resultErr error) {
	cli := flag.String("cli", "", "explicit freshly compiled harmonia executable")
	endpoint := flag.String("endpoint", "", "synthetic host loopback HTTPS endpoint")
	ca := flag.String("ca-file", "", "explicit public synthetic CA PEM")
	email := flag.String("email", "", "synthetic .invalid email")
	approver := flag.String("approver", "", "native manager public device ID")
	environment := flag.String("environment", "", "single explicit environment ID (rw only)")
	port := flag.Int("port", 0, "adb-forward allocated loopback TCP port")
	expiry := flag.Uint64("expiry", 0, "explicit finite canonical Unix seconds")
	nativeReady := flag.Bool("native-ready", false, "read bounded public fixture metadata from local Android test socket")
	expectRejected := flag.Bool("expect-rejected", false, "expect native save gate to prevent approval POST; no enrollment claim")
	transportOnly := flag.Bool("socket-test", false, "only verify local test socket transport, no enrollment claim")
	flag.Parse()
	if *port < 1024 || *port > 65535 {
		return errFixture
	}
	if *nativeReady {
		fmt.Println("reading local native public metadata")
		ready, e := readReady(*port)
		if e != nil {
			return e
		}
		*email = ready.Email
		*approver = ready.Approver
		*environment = ready.Environment
		*expiry = ready.Expiry
		fmt.Println("local native public metadata validated")
	}
	if !publicID.MatchString(*environment) || *expiry <= uint64(time.Now().Unix()) || *expiry > uint64(time.Now().Add(24*time.Hour).Unix()) {
		return errFixture
	}
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalCtx, 140*time.Second)
	defer cancel()
	if *transportOnly {
		code, err := pairing.GenerateShortCode()
		if err != nil {
			return errFixture
		}
		defer clear(code)
		message := intent{id: "pair-native-socket-test", environment: *environment, expiry: *expiry, code: code}
		if _, err = relay(ctx, *port, message); err != nil {
			return errFixture
		}
		fmt.Println("local native test socket passed; enrollment not exercised")
		return nil
	}
	parsed, err := url.Parse(*endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "127.0.0.1" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || *ca == "" || !strings.HasSuffix(*email, ".invalid") || !publicID.MatchString(*approver) || !filepath.IsAbs(*cli) {
		return errFixture
	}
	fmt.Println("synthetic cross-end configuration validated")
	password, err := bufio.NewReader(io.LimitReader(os.Stdin, 16386)).ReadBytes('\n')
	if err != nil && err != io.EOF {
		return errFixture
	}
	defer clear(password)
	password = bytes.TrimSuffix(bytes.TrimSuffix(password, []byte("\n")), []byte("\r"))
	if len(password) == 0 || len(password) > 16384 || bytes.ContainsAny(password, "\x00\r\n") {
		return errFixture
	}
	fmt.Println("synthetic stdin credential consumed")
	temporaryRoot, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return errFixture
	}
	directory, err := os.MkdirTemp(temporaryRoot, "harmonia-cross-cli-")
	if err != nil {
		return errFixture
	}
	// 此目录只由本次测试创建；不打开任何已有CLI槽或宿主环境。
	defer func() {
		_ = quietCLI(ctx, *cli, nil, "logout", "--local-directory", directory)
		if os.RemoveAll(directory) != nil {
			resultErr = errFixture
		}
	}()
	if err = quietCLI(ctx, *cli, append(bytes.Clone(password), '\n'), "login", "--local-directory", directory, "--server", *endpoint, "--email", *email, "--ca-file", *ca, "--password-stdin"); err != nil {
		return errFixture
	}
	fmt.Println("compiled CLI synthetic login passed")
	command := exec.CommandContext(ctx, *cli, "pair", "--local-directory", directory, "--approver", *approver, "--ca-file", *ca, "--certificate-version", "2")
	reader, err := command.StdoutPipe()
	if err != nil {
		return errFixture
	}
	var pairDiagnostic bytes.Buffer
	command.Stderr = &pairDiagnostic
	defer func() { clear(pairDiagnostic.Bytes()) }()
	if err = command.Start(); err != nil {
		return errFixture
	}
	sent := false
	stageNotified := false
	defer func() {
		if sent && !stageNotified {
			_ = notifyStage(*port, false)
		}
	}()
	nativeRejected := false
	scanErr := consumeCLI(reader, func(id string, code []byte) error {
		if sent {
			return errFixture
		}
		sent = true
		state, err := relay(ctx, *port, intent{id: id, environment: *environment, expiry: *expiry, code: code})
		if state == "REJECTED" {
			nativeRejected = true
			_ = command.Process.Kill()
			return errFixture
		}
		return err
	})
	if scanErr != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if waitErr != nil {
		for _, category := range []string{"expired", "confirmation", "确认", "签名", "certificate", "x509", "400", "401", "403", "409", "context", "上下文", "timeout", "deadline", "message"} {
			if bytes.Contains(pairDiagnostic.Bytes(), []byte(category)) {
				fmt.Println("synthetic CLI pairing rejected category:", category)
			}
		}
	}
	if *expectRejected {
		if !nativeRejected || !sent {
			return errFixture
		}
		if err = notifyStage(*port, true); err != nil {
			return err
		}
		stageNotified = true
		fmt.Println("native pre-POST save gate passed; candidate not enrolled")
		return nil
	}
	if nativeRejected || scanErr != nil || waitErr != nil || !sent {
		return errFixture
	}
	fmt.Println("compiled CLI v2 pairing process passed")
	if err = verifyDaemon(ctx, *cli, directory, *ca, *environment); err != nil {
		return err
	}
	if err = notifyStage(*port, true); err != nil {
		return err
	}
	stageNotified = true
	fmt.Println("compiled CLI v2 dual-signature completion, device-key boot, verified pull and isolated export passed")
	return nil
}
func quietCLI(ctx context.Context, path string, input []byte, args ...string) error {
	defer clear(input)
	command := exec.CommandContext(ctx, path, args...)
	command.Stdout = io.Discard
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	defer func() { clear(diagnostic.Bytes()) }()
	if len(input) > 0 {
		command.Stdin = bytes.NewReader(input)
	}
	if command.Run() != nil {
		text := diagnostic.Bytes()
		for _, stage := range []string{"certificate", "unauthorized", "permission", "占用", "锁", "password", "directory", "x509", "email", "invalid"} {
			if bytes.Contains(text, []byte(stage)) {
				fmt.Println("synthetic CLI rejected category:", stage)
			}
		}
		clear(text)
		return errFixture
	}
	return nil
}

// ReadSlice避免把短码变成不可清理字符串。所有行（包括未知输出）消费后清理，不写日志/文件。
func consumeCLI(source io.Reader, send func(string, []byte) error) error {
	reader := bufio.NewReaderSize(source, 4096)
	id := ""
	sent := false
	for {
		line, err := reader.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			clear(line)
			return errFixture
		}
		value := bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		if bytes.HasPrefix(value, []byte(prefixID)) {
			candidate := value[len([]byte(prefixID)):]
			if id != "" || !publicID.Match(candidate) || len(candidate) > 64 {
				clear(line)
				return errFixture
			}
			id = string(candidate)
		} else if bytes.HasPrefix(value, []byte(prefixCode)) {
			code := value[len([]byte(prefixCode)):]
			if sent || id == "" || len(code) != 8 {
				clear(line)
				return errFixture
			}
			for _, c := range code {
				if c < '0' || c > '9' {
					clear(line)
					return errFixture
				}
			}
			copyCode := bytes.Clone(code)
			sendErr := send(id, copyCode)
			clear(copyCode)
			clear(line)
			if sendErr != nil {
				return errFixture
			}
			sent = true
		}
		clear(line)
		if err == io.EOF {
			if !sent {
				return errFixture
			}
			return nil
		}
		if err != nil {
			return errFixture
		}
	}
}
func relay(ctx context.Context, port int, message intent) (string, error) {
	if !publicID.MatchString(message.id) || len(message.id) > 64 || !publicID.MatchString(message.environment) || len(message.environment) > 128 || len(message.code) != 8 {
		return "", errFixture
	}
	for _, c := range message.code {
		if c < '0' || c > '9' {
			return "", errFixture
		}
	}
	var packet bytes.Buffer
	packet.WriteString(pipeMagic)
	_ = binary.Write(&packet, binary.BigEndian, uint16(len(message.id)))
	packet.WriteString(message.id)
	_ = binary.Write(&packet, binary.BigEndian, uint16(len(message.environment)))
	packet.WriteString(message.environment)
	_ = binary.Write(&packet, binary.BigEndian, message.expiry)
	packet.WriteByte(2)
	packet.Write(message.code)
	defer clear(packet.Bytes())
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return "", errFixture
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(125 * time.Second))
	if _, err = io.Copy(connection, bytes.NewReader(packet.Bytes())); err != nil {
		return "", errFixture
	}
	reply, err := bufio.NewReader(io.LimitReader(connection, 33)).ReadBytes('\n')
	defer clear(reply)
	if err != nil {
		return "", errFixture
	}
	state := strings.TrimSuffix(string(reply), "\n")
	switch state {
	case "RECEIVED", "APPROVED", "UNKNOWN", "COMPLETE", "REJECTED":
		return state, nil
	default:
		return "", errFixture
	}
}

// 元数据全部公开且只来自本轮合成Android测试。短码不在元数据JSON中。
type nativeMetadata struct {
	Email       string `json:"email"`
	Approver    string `json:"approver"`
	Environment string `json:"environment"`
	Expiry      uint64 `json:"expiry"`
}

func readReady(port int) (nativeMetadata, error) {
	var m nativeMetadata
	c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if e != nil {
		return m, errFixture
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, e = io.WriteString(c, "HARMQR01"); e != nil {
		return m, errFixture
	}
	raw, e := bufio.NewReader(io.LimitReader(c, 2049)).ReadBytes('\n')
	defer clear(raw)
	if e != nil || len(raw) > 2048 {
		return m, errFixture
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return m, errFixture
	}
	return m, nil
}
func notifyStage(port int, success bool) error {
	c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if e != nil {
		return errFixture
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	frame := []byte("HARMDN01")
	if success {
		frame = append(frame, 1)
	} else {
		frame = append(frame, 0)
	}
	if _, e = c.Write(frame); e != nil {
		return errFixture
	}
	raw, e := bufio.NewReader(io.LimitReader(c, 4)).ReadBytes('\n')
	if e != nil || string(raw) != "OK\n" {
		return errFixture
	}
	return nil
}
func captureCLI(ctx context.Context, path string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, path, args...)
	c.Stderr = io.Discard
	var out bytes.Buffer
	c.Stdout = &out
	if c.Run() != nil {
		clear(out.Bytes())
		return nil, errFixture
	}
	if out.Len() > 32768 {
		clear(out.Bytes())
		return nil, errFixture
	}
	return out.Bytes(), nil
}
func verifyDaemon(ctx context.Context, path, directory, ca, environment string) error {
	// 只写本次新建目录下的独立fragment，不source、不安装服务、不修改宿主环境。
	d := exec.CommandContext(ctx, path, "daemon", "--local-directory", directory, "--ca-file", ca, "--platform-fragment", filepath.Join(directory, "environment.sh"), "--interval", "100ms", "--sync-interval", "1s")
	d.Stdout = io.Discard
	var diagnostic boundedDiagnostic
	d.Stderr = &diagnostic
	fmt.Println("starting isolated compiled CLI daemon")
	if d.Start() != nil {
		return errFixture
	}
	done := make(chan struct{})
	go func() { _ = d.Wait(); close(done) }()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = quietCLI(cleanupCtx, path, nil, "logout", "--local-directory", directory)
		_ = d.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = d.Process.Kill()
			<-done
		}
		diagnostic.clear()
	}()
	deadline := time.Now().Add(15 * time.Second)
	var status struct {
		Sequence          uint64 `json:"sequence"`
		AccountGeneration uint64 `json:"accountGeneration"`
		Environments      int    `json:"environments"`
	}
	for {
		raw, e := captureCLI(ctx, path, "status", "--local-directory", directory)
		statusAvailable := e == nil && json.Unmarshal(raw, &status) == nil
		valid := statusAvailable && status.Sequence > 0 && status.AccountGeneration > 0 && status.Environments == 1
		clear(raw)
		if valid {
			fmt.Println("compiled daemon verified pull passed")
			break
		}
		if time.Now().After(deadline) {

			fmt.Println("synthetic daemon status available:", statusAvailable)
			select {
			case <-done:
				fmt.Println("synthetic daemon exited before readiness")
			default:
			}
			for _, category := range diagnostic.categories() {
				fmt.Println("synthetic daemon rejected category:", category)
			}
			if statusAvailable {
				fmt.Println("synthetic daemon public status fields:", status.Sequence, status.AccountGeneration, status.Environments)
			}
			return errFixture
		}
		select {
		case <-ctx.Done():
			return errFixture
		case <-time.After(100 * time.Millisecond):
		}
	}
	if quietCLI(ctx, path, nil, "activate", "--local-directory", directory, "--environment", environment, "--priority", "10") != nil {
		return errFixture
	}
	fmt.Println("compiled environment activation passed")
	raw, e := captureCLI(ctx, path, "export", "--local-directory", directory)
	defer clear(raw)
	if e != nil || !bytes.Contains(raw, []byte("SYNTHETIC_CROSS")) || !bytes.Contains(raw, []byte("synthetic-cross-value")) {
		return errFixture
	}
	fmt.Println("compiled synthetic export passed")
	if quietCLI(ctx, path, []byte("synthetic-cli-write"), "put", "--local-directory", directory, "--environment", environment, "--name", "SYNTHETIC_CLI", "--request-id", "cross-cli-put", "--value-stdin") != nil {
		return errFixture
	}
	raw, e = captureCLI(ctx, path, "export", "--local-directory", directory)
	defer clear(raw)
	if e != nil || !bytes.Contains(raw, []byte("synthetic-cli-write")) {
		return errFixture
	}
	return nil
}
