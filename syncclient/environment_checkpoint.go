package syncclient

import (
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// VerifyEnvironmentChangeCheckpoint confirms one original transaction against
// an already verified, protected cloud snapshot. It is not a trust or signature
// verifier and must never be used to accept an unverified server checkpoint.
func VerifyEnvironmentChangeCheckpoint(checkpoint localstate.CloudSnapshot, signed cryptox.SignedEnvironmentChange, acceptedSequence uint64) error {
	c := signed.Change
	if checkpoint.AccountID != c.AccountID || strconv.FormatUint(checkpoint.AccountGeneration, 10) != c.AccountGeneration {
		return ErrAcceptedNotApplied
	}
	wire, err := c.SigningBytes()
	if err != nil {
		return err
	}
	expected, err := strconv.ParseUint(c.ExpectedSequence, 10, 64)
	if err != nil {
		return err
	}
	const maximum = uint64(9007199254740991)
	if expected >= maximum || uint64(len(c.Mutations)) > maximum-expected-1 {
		return ErrAcceptedNotApplied
	}
	head := expected + 1
	tail := head + uint64(len(c.Mutations))
	seen, ok := checkpoint.EnvironmentCheckpoints[c.DeviceID+"/"+c.IdempotencyKey]
	if acceptedSequence != tail || checkpoint.Sequence < tail || !ok || seen.Sequence != head || seen.Fingerprint != digest(wire) {
		return ErrAcceptedNotApplied
	}
	sequences := map[uint64]bool{}
	for _, signedMutation := range c.Mutations {
		m := signedMutation.Mutation
		b, err := m.SigningBytes()
		if err != nil {
			return err
		}
		point, exists := checkpoint.SeenMutations[m.DeviceID+"/"+m.IdempotencyKey]
		if !exists || point.Sequence <= head || point.Sequence > tail || sequences[point.Sequence] || point.Fingerprint != digest(b) {
			return ErrAcceptedNotApplied
		}
		sequences[point.Sequence] = true
	}
	return nil
}
