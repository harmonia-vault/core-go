package localipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAccountRequestStrictWhitelist(t *testing.T) {
	credential := bytes.Repeat([]byte{7}, 32)
	good := []AccountRequest{
		{Action: "login", Endpoint: "https://synthetic.invalid", Email: "test@example.invalid", Credential: credential},
		{Action: "pair", ApproverDeviceID: "manager", CertificateVersion: "5"},
		{Action: "pair-status", PairingID: "pair-1"}, {Action: "pair-cancel", PairingID: "pair-1"},
	}
	for _, r := range good {
		if e := validateAccountRequest(r); e != nil {
			t.Fatalf("合法消息拒绝：%s", r.Action)
		}
	}
	bad := []AccountRequest{
		{Action: "login", Endpoint: "http://synthetic.invalid", Email: "test@example.invalid", Credential: credential},
		{Action: "login", Endpoint: "https://user:password@synthetic.invalid", Email: "test@example.invalid", Credential: credential},
		{Action: "login", Endpoint: "https://synthetic.invalid/?token=synthetic", Email: "test@example.invalid", Credential: credential},
		{Action: "login", Endpoint: "https://synthetic.invalid", Email: "test@example.invalid", Credential: credential[:31]},
		{Action: "pair", ApproverDeviceID: "manager", CertificateVersion: "1"},
		{Action: "pair-status", PairingID: "pair-1", Credential: credential},
		{Action: "trust"}, {Action: "pair-cancel", PairingID: "../vault"},
	}
	for i, r := range bad {
		if !errors.Is(validateAccountRequest(r), ErrProtocol) {
			t.Fatalf("非法消息%d被接受", i)
		}
	}
}
func TestAccountOuterRequestCannotMixLocalCloudFields(t *testing.T) {
	account := &AccountRequest{Action: "pair-status", PairingID: "pair-1"}
	good := Request{Version: Version, Command: "account", Account: account}
	if validateRequest(good) != nil {
		t.Fatal("账号白名单被拒")
	}
	variants := []Request{good, good, good, good, good, good}
	value := "synthetic-value"
	priority := 1
	variants[0].Value = &value
	variants[1].EnvironmentID = "env"
	variants[2].RequestID = "write"
	variants[3].Selected = map[string]string{"SYNTHETIC": value}
	variants[4].Priority = &priority
	variants[5].Command = "status"
	for i, r := range variants {
		if validateRequest(r) == nil {
			t.Fatalf("混用字段%d被接受", i)
		}
	}
	data := []byte(`{"version":1,"command":"account","account":{"action":"pair-status","pairingId":"pair-1","trust":{"accepted":true}}}`)
	var r Request
	var frame bytes.Buffer
	if err := writeFrame(&frame, json.RawMessage(data), maxRequestBytes); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(readFrame(&frame, &r, maxRequestBytes), ErrProtocol) {
		t.Fatal("未知信任字段被接受")
	}
}
func TestAccountResultCannotReportFalseCompletionOrLeakError(t *testing.T) {
	account := &AccountRequest{Action: "pair-status", PairingID: "pair-1"}
	request := Request{Version: Version, Command: "account", Account: account}
	server := &Server{config: Config{Account: func(context.Context, AccountRequest) (AccountState, error) {
		return AccountState{Phase: "accepted", PairingID: "pair-1", Applied: true}, nil
	}}}
	if got := server.dispatchAccount(context.Background(), request); got.OK || got.Account != nil {
		t.Fatal("未接受却报告完成")
	}
	server.config.Account = func(context.Context, AccountRequest) (AccountState, error) {
		return AccountState{}, errors.New("SYNTHETIC-SECRET-ERROR")
	}
	got := server.dispatchAccount(context.Background(), request)
	encoded, _ := json.Marshal(got)
	if got.Code != "account_failed" || strings.Contains(string(encoded), "SYNTHETIC-SECRET") {
		t.Fatal("错误不是固定白名单")
	}
	server.config.Account = func(context.Context, AccountRequest) (AccountState, error) {
		return AccountState{Phase: "accepted", PairingID: "pair-1", Accepted: true, Applied: false}, nil
	}
	if got = server.dispatchAccount(context.Background(), request); !got.OK || got.Account == nil || got.Account.Applied {
		t.Fatal("接受但未下发状态丢失")
	}
}

func TestAccountTransportCannotUseLegacyEndpoint(t *testing.T) {
	_, err := Call(context.Background(), Endpoint{Directory: "/unused", UserID: "0"}, Request{Command: "account", Account: &AccountRequest{Action: "pair-status", PairingID: "pair-1"}})
	if !errors.Is(err, ErrIdentity) {
		t.Fatal("账号消息绕过保护配置身份门槛")
	}
}
