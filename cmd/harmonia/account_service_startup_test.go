package main

import (
	"context"
	"errors"
	"testing"
)

func TestAccountServiceDefersTrustAndInitializationUntilDispatcher(t *testing.T) {
	const path = `C:\Program Files\Harmonia\HarmoniaUser-41e81daa5894\service.json`
	initialized := false
	connected := false
	var deferred func(context.Context, func()) error
	initialize := func(ctx context.Context, gotPath, name string, ready func()) error {
		if !connected || gotPath != path || name != "HarmoniaUser-41e81daa5894" {
			t.Fatal("initialization before routed dispatcher connection")
		}
		initialized = true
		return accountStartupError(accountStartupOwnIdentity, errors.New("private underlying detail"))
	}
	dispatch := func(ctx context.Context, name string, run func(context.Context, func()) error) error {
		if initialized || name != "HarmoniaUser-41e81daa5894" {
			t.Fatal("untrusted path used for initialization before dispatcher")
		}
		connected = true
		deferred = run
		return nil
	}
	if err := enterAccountService(context.Background(), path, dispatch, initialize); err != nil || initialized || deferred == nil {
		t.Fatal("entry did not defer initialization")
	}
	ready := false
	err := deferred(context.Background(), func() { ready = true })
	if !initialized || ready || ownerServiceFailureCode(err) != accountStartupOwnIdentity || err.Error() != "windows_account_service_startup_rejected" {
		t.Fatal("trust rejection became ready or exposed its raw error")
	}
	initialized = false
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if deferred(cancelled, func() {}) == nil || initialized {
		t.Fatal("cancelled startup initialized state")
	}
	connected = false
	if enterAccountService(context.Background(), path+":stream", dispatch, initialize) == nil || connected {
		t.Fatal("invalid routing path reached dispatcher")
	}
}

func TestAccountServiceFailureCodesAreFinite(t *testing.T) {
	for _, code := range []uint32{accountStartupConfiguration, accountStartupOwnIdentity, accountStartupServiceSID, accountStartupCA} {
		err := errors.Join(accountStartupError(code, errors.New("not for logging")), errors.New("close failed"))
		if ownerServiceFailureCode(err) != code {
			t.Fatal("startup stage lost through resource cleanup")
		}
	}
	if ownerServiceFailureCode(accountStartupError(0xffffffff, errors.New("unrecognized"))) != 1 || ownerServiceFailureCode(errors.New("other")) != 1 {
		t.Fatal("unbounded service-specific code")
	}
}
