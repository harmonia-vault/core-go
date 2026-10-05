package mobilebridge

import (
	"errors"
	"github.com/harmonia-vault/core-go/syncclient"
)

// Only fixed protocol codes cross the native/UI boundary, never server text.
func emailCodeFailure(err error) string {
	var fault *syncclient.RequestError
	if !errors.As(err, &fault) {
		return ""
	}
	switch fault.Code {
	case "registration_expired":
		return "REGISTRATION_EXPIRED"
	case "email_code_invalid":
		return "EMAIL_CODE_INVALID"
	case "email_code_expired":
		return "EMAIL_CODE_EXPIRED"
	case "email_code_attempts_exhausted":
		return "EMAIL_CODE_EXHAUSTED"
	}
	return ""
}
