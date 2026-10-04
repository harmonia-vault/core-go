package main

import (
	"context"
	"errors"

	"github.com/harmonia-vault/core-go/windowsaccount"
)

// Codes are deliberately fixed and contain no underlying error text or input.
const (
	accountStartupConfiguration uint32 = 0x4801
	accountStartupOwnIdentity   uint32 = 0x4802
	accountStartupServiceSID    uint32 = 0x4803
	accountStartupCA            uint32 = 0x4804
)

type accountStartupFailure struct {
	code  uint32
	cause error
}

func (e *accountStartupFailure) Error() string { return "windows_account_service_startup_rejected" }
func (e *accountStartupFailure) Unwrap() error { return e.cause }
func accountStartupError(code uint32, err error) error {
	if err == nil {
		return nil
	}
	return &accountStartupFailure{code: code, cause: err}
}
func ownerServiceFailureCode(err error) uint32 {
	var failure *accountStartupFailure
	if errors.As(err, &failure) {
		switch failure.code {
		case accountStartupConfiguration:
			if code, ok := windowsaccount.ConfigurationFailureCode(failure.cause); ok {
				return code
			}
			return failure.code
		case accountStartupOwnIdentity, accountStartupServiceSID, accountStartupCA:
			return failure.code
		}
	}
	return 1
}

type accountServiceDispatcher func(context.Context, string, func(context.Context, func()) error) error
type accountServiceInitializer func(context.Context, string, string, func()) error

// No configuration, token, key, IPC or network operation precedes dispatcher
// connection. Only a strict fixed-layout string is used to route that connection.
func enterAccountService(ctx context.Context, config string, dispatch accountServiceDispatcher, initialize accountServiceInitializer) error {
	name, err := windowsaccount.DispatcherName(config)
	if err != nil {
		return accountStartupError(accountStartupConfiguration, err)
	}
	return dispatch(ctx, name, func(serviceCtx context.Context, ready func()) error {
		if err := serviceCtx.Err(); err != nil {
			return err
		}
		return initialize(serviceCtx, config, name, ready)
	})
}
