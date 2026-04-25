// Package pidchain returns kernel-attested process ancestry and a stable
// fingerprint over the ancestors' code-signing identities. Use Fingerprint
// for runtime authentication; use Chain for diagnostics and UI.
package pidchain

import "github.com/jwyattgh/pidchain/internal/walker"

// Error sentinels re-exported from internal/walker so consumers can write
// errors.Is(err, pidchain.ErrProcessDead).
var (
	ErrPlatformUnsupported = walker.ErrPlatformUnsupported
	ErrProcessDead         = walker.ErrProcessDead
)

// ProcessInfo is one ancestor's kernel-attested identity.
type ProcessInfo = walker.ProcessInfo

// ProcessChain is the walked ancestry plus the SHA256 fingerprint over
// every entry's code-signing identity.
type ProcessChain = walker.ProcessChain

// Fingerprint returns a lowercase hex SHA256 over the code-signing
// identity of every ancestor of pid. Deterministic: identical ancestry
// produces an identical fingerprint. Any change to any ancestor's signing
// identity produces a different fingerprint.
func Fingerprint(pid int) (string, error) {
	chain, err := walker.Walk(pid)
	return chain.Fingerprint, err
}

// Chain returns the walked ancestry as structured data. Intended for
// diagnostics, setup-time UI, and pairing prompts. Not for runtime
// authentication — use Fingerprint.
func Chain(pid int) (ProcessChain, error) {
	return walker.Walk(pid)
}
