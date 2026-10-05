package syncclient

import (
	"context"
	"github.com/harmonia-vault/core-go/cryptox"
	"net/url"
)

type verifiedAuthorityGraph interface {
	VerifyHistoricalGrant(cryptox.SignedGrantWire) error
	VerifyTarget(cryptox.SignedGrantWire, string, string, string) error
	IssuerBindings() []cryptox.IssuerBinding
	Authority(string) (cryptox.SignedGrantWire, bool)
	VerifyEnvironmentOriginEvent(cryptox.SignedEnvironmentChange, cryptox.SignedEnvironmentOrigin, cryptox.SignedGrantWire) error
}

func (c *Client) requestPull(ctx context.Context, u *url.URL, out *Pull) error {
	return c.requestDAGPull(ctx, u, out)
}
func (v *PinnedVerifier) cachedLedger(data []byte) (*cachedSourceLedger, error) {
	return v.cachedDAGLedger(data)
}
