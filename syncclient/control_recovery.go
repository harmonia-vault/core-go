package syncclient

import (
	"github.com/harmonia-vault/core-go/cryptox"
)

type VerifiedControlEvidence interface {
	VerifyHistoricalGrant(cryptox.SignedGrantWire) error
	VerifyTarget(cryptox.SignedGrantWire, string, string, string) error
	IssuerBindings() []cryptox.IssuerBinding
}
