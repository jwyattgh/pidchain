// Package pidchain returns kernel-attested process ancestry and a stable
// fingerprint over the ancestors' code-signing identities. Use Fingerprint
// for runtime authentication; use Chain for diagnostics and UI.
package pidchain

import (
	"github.com/jwyattgh/pidchain/internal/walker"
)

// Error sentinels re-exported from internal/walker so consumers can write
// errors.Is(err, pidchain.ErrProcessDead).
var (
	ErrPlatformUnsupported = walker.ErrPlatformUnsupported
	ErrProcessDead         = walker.ErrProcessDead
	ErrMaxDepthExceeded    = walker.ErrMaxDepthExceeded
)

// Fingerprint returns a lowercase hex SHA256 over the code-signing
// identity of every ancestor of pid. Deterministic: identical ancestry
// produces an identical fingerprint. Any change to any ancestor's signing
// identity produces a different fingerprint.
//
// Runtime authentication uses this function. Pass in the peer PID the
// kernel reported, compare the result against a stored fingerprint.
//
// On ErrMaxDepthExceeded the returned string is the fingerprint of the
// 32-entry partial chain; the consumer decides whether to accept it.
func Fingerprint(pid int) (string, error) {
	chain, err := walker.Walk(pid)
	return chain.Fingerprint, err
}

// Chain returns the walked ancestry as structured data. Intended for
// diagnostics, setup-time UI, and pairing prompts. Not for runtime
// authentication — use Fingerprint.
//
// On ErrMaxDepthExceeded the returned chain holds the 32 successfully
// walked entries plus their fingerprint.
func Chain(pid int) (walker.ProcessChain, error) {
	return walker.Walk(pid)
}
