package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/localstate"
	"net/http"
	"regexp"
	"time"
)

var ErrEnrollmentPending = errors.New("enrollment result uncertain; query the same pairing before retrying")
var enrollmentID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type EnrollmentConfig struct {
	Endpoint            string
	HTTPClient          *http.Client
	AccountID           string
	AccountGeneration   uint64
	DeviceID            string
	LoginToken          string
	SigningKey          ed25519.PrivateKey
	ReceivingPrivateKey []byte
	Engine              *localstate.Engine
	Now                 func() time.Time
}
type deniedEnrollmentVerifier struct{}

func (deniedEnrollmentVerifier) VerifyPull(context.Context, Pull, localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	return localstate.CloudSnapshot{}, errors.New("unapproved device cannot synchronize")
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
