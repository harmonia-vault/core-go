//go:build !harmonia_boringssl || !cgo || (!darwin && !linux)

package pairing

func NativeAvailable() bool { return false }
func newNative(role string, myName, peerName, code []byte) (nativeState, []byte, error) {
	return nil, nil, ErrUnavailable
}
