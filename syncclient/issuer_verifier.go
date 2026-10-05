package syncclient

import "github.com/harmonia-vault/core-go/cryptox"

func (v *PinnedVerifier) IssuerBindings() []cryptox.IssuerBinding {
	if v.issuerOriginProof != nil {
		return v.issuerOriginProof.IssuerBindings()
	}
	return nil
}
