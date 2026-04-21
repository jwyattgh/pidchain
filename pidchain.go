package pidchain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

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

// build does one kernel walk and returns both the chain and its
// fingerprint. Fingerprint and Chain are thin wrappers that each expose
// one of the two values. Sharing this code path makes divergence between
// the two public functions structurally impossible.
func build(pid int) (ProcessChain, string, error) {
	entries, walkErr := walker.Walk(pid)
	if walkErr != nil && !errors.Is(walkErr, walker.ErrMaxDepthExceeded) {
		return nil, "", translateWalkerErr(walkErr)
	}

	chain := make(ProcessChain, len(entries))
	h := sha256.New()
	for i, e := range entries {
		chain[i] = ProcessInfo{
			PID:              e.PID,
			ParentPID:        e.ParentPID,
			BinaryPath:       e.BinaryPath,
			TeamID:           e.TeamID,
			BundleIdentifier: e.BundleIdentifier,
			AuthorityLeaf:    e.AuthorityLeaf,
		}
		h.Write([]byte(e.TeamID))
		h.Write([]byte(e.BundleIdentifier))
		h.Write([]byte(e.AuthorityLeaf))
	}
	fp := hex.EncodeToString(h.Sum(nil))

	if errors.Is(walkErr, walker.ErrMaxDepthExceeded) {
		return chain, fp, ErrMaxDepthExceeded
	}
	return chain, fp, nil
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
	_, fp, err := build(pid)
	if err != nil && !errors.Is(err, ErrMaxDepthExceeded) {
		return "", err
	}
	return fp, err
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
	chain, _, err := build(pid)
	if err != nil && !errors.Is(err, ErrMaxDepthExceeded) {
		return nil, err
	}
	return chain, err
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