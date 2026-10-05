package mobileworkflow

import "errors"

var ErrRecoveryRestricted = errors.New("recovery context is restricted; it does not enroll or authorize this device")
var ErrRecoveryPending = errors.New("recovery rotation outcome pending; query the original operation")
var ErrRecoveryExpired = errors.New("original recovery session or rotation challenge expired; no implicit replacement")
var ErrRecoveryEvidence = errors.New("recovery historical issuer evidence is unavailable or invalid")
