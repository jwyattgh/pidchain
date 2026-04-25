package walker

import "errors"

// ProcessInfo is one ancestor's kernel-attested identity.
type ProcessInfo struct {
	PID              int
	ParentPID        int
	BinaryPath       string
	TeamID           string
	BundleIdentifier string
	AuthorityLeaf    string
}

// ProcessChain is the walked ancestry plus the SHA256 fingerprint over
// every entry's code-signing identity. Walker populates both fields in a
// single pass; pidchain.Fingerprint and pidchain.Chain each project one.
type ProcessChain struct {
	Entries     []ProcessInfo
	Fingerprint string
}

// Error sentinels. Messages use the "pidchain:" prefix because these are
// what consumers see — pidchain re-exports these directly.
var (
	ErrPlatformUnsupported = errors.New("pidchain: platform not supported")
	ErrProcessDead         = errors.New("pidchain: process not found")
	ErrMaxDepthExceeded    = errors.New("pidchain: walk exceeded max depth")
)
