package pidchain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/jwyattgh/pidchain/internal/canonical"
	"github.com/jwyattgh/pidchain/internal/walker"
)

// Exported error sentinels. These are the only errors callers need to
// distinguish; OS-level errors are translated to one of these inside the
// walker.
var (
	ErrPlatformUnsupported = errors.New("pidchain: platform not supported")
	ErrProcessDead         = errors.New("pidchain: process not found")
	ErrMaxDepthExceeded    = errors.New("pidchain: walk exceeded max depth")
)

// ProcessChain is the ordered sequence of ancestors. Index 0 is the PID
// passed to Chain; index 1 is its parent; and so on to the terminator.
type ProcessChain []ProcessInfo

// ProcessInfo is a single ancestor's kernel-attested identity.
type ProcessInfo struct {
	PID              int    // the PID this entry describes
	ParentPID        int    // parent of PID at walk time
	BinaryPath       string // absolute executable path, kernel-attested
	TeamID           string // platform-specific publisher identifier
	BundleIdentifier string // platform-specific application identifier
	AuthorityLeaf    string // platform-specific signing-authority label
}

// Fingerprint returns a lowercase hex-encoded SHA256 identifying the full
// process ancestry rooted at pid. Deterministic: identical ancestry
// produces an identical fingerprint. Any change to any ancestor's
// code-signing identity produces a different fingerprint.
//
// Runtime authentication uses this function. Pass in the peer PID the
// kernel reported, compare the result against a stored fingerprint.
//
// On ErrMaxDepthExceeded the returned string is still the fingerprint of
// the 32-entry partial chain; the consumer decides whether to accept it.
func Fingerprint(pid int) (string, error) {
	chain, err := Chain(pid)
	if err != nil && !errors.Is(err, ErrMaxDepthExceeded) {
		return "", err
	}

	ancestors := make([]canonical.Ancestor, len(chain))
	for i, p := range chain {
		ancestors[i] = canonical.Ancestor{
			TeamID:           p.TeamID,
			BundleIdentifier: p.BundleIdentifier,
			AuthorityLeaf:    p.AuthorityLeaf,
		}
	}
	bytes, cerr := canonical.Bytes(ancestors)
	if cerr != nil {
		return "", cerr
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), err
}

// Chain returns the walked process ancestry as structured data. Intended
// for diagnostics, setup-time UI, and pairing prompts that show a human
// "a process signed by X wants to connect."
//
// Not for runtime authentication. The fingerprint already commits to the
// chain; re-inspecting the chain on every call duplicates work the hash
// comparison already did. Use Fingerprint for auth, Chain for display.
//
// On ErrMaxDepthExceeded the returned chain holds the 32 successfully
// walked entries.
func Chain(pid int) (ProcessChain, error) {
	entries, err := walker.Walk(pid)
	if err != nil && !errors.Is(err, walker.ErrMaxDepthExceeded) {
		return nil, translateWalkerErr(err)
	}

	chain := make(ProcessChain, len(entries))
	for i, e := range entries {
		chain[i] = ProcessInfo{
			PID:              e.PID,
			ParentPID:        e.ParentPID,
			BinaryPath:       e.BinaryPath,
			TeamID:           e.TeamID,
			BundleIdentifier: e.BundleIdentifier,
			AuthorityLeaf:    e.AuthorityLeaf,
		}
	}
	if errors.Is(err, walker.ErrMaxDepthExceeded) {
		return chain, ErrMaxDepthExceeded
	}
	return chain, nil
}

func translateWalkerErr(err error) error {
	switch {
	case errors.Is(err, walker.ErrPlatformUnsupported):
		return ErrPlatformUnsupported
	case errors.Is(err, walker.ErrProcessDead):
		return ErrProcessDead
	default:
		return err
	}
}
