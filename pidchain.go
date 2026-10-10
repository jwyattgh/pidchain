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
// identity of every ancestor of pid, starting at pid itself.
// Deterministic: identical ancestry produces an identical fingerprint.
// Any change to any ancestor's signing identity produces a different
// fingerprint.
//
// # Choosing pid
//
// Two call sites use different pid arguments. The choice depends on
// whose identity is at index zero of the chain.
//
// Server-side (the verifier): pass the peer PID obtained from the
// kernel — cmd.Process.Pid for a child spawned over stdio,
// LOCAL_PEERPID or GetNamedPipeClientProcessId for socket transports.
// The chain walks from the peer up through its ancestors.
//
// Spawned-binary, self-attesting (a process committing its own
// identity alongside its launcher's — for example a probe or a
// stdio-to-HTTP bridge): pass os.Getpid(), NOT os.Getppid(). The
// chain must start at the spawned binary itself so that its own
// code-signing identity is entry zero and contributes to the hash.
// Passing os.Getppid() roots the chain at the launcher and excludes
// the spawned binary entirely from the hash input, defeating
// SECURITY.md's "tampering with the binary on disk" detection for
// that binary.
func Fingerprint(pid int) (string, error) {
	chain, err := walker.Walk(pid)
	return chain.Fingerprint, err
}

// Chain returns the walked ancestry as structured data. Intended for
// diagnostics, setup-time UI, and pairing prompts. Not for runtime
// authentication — use Fingerprint. See Fingerprint for the
// pid-argument convention.
func Chain(pid int) (ProcessChain, error) {
	return walker.Walk(pid)
}
