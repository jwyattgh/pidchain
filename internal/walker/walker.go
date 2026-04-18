// Package walker walks a process's ancestry and collects per-ancestor
// codesign identity. The Walk function and Entry type are platform-neutral;
// the per-OS Platform implementation lives in walker_<goos>.go.
package walker

import "errors"

// MaxDepth caps the chain length to bound runtime on pathological trees and
// to bound the canonical-bytes size that downstream code hashes.
const MaxDepth = 32

// Internal sentinels. The root pidchain package translates these to its
// public sentinels; consumers never see walker errors directly.
var (
	ErrPlatformUnsupported = errors.New("walker: platform not supported")
	ErrProcessDead         = errors.New("walker: process not found")
	ErrMaxDepthExceeded    = errors.New("walker: walk exceeded max depth")
)

// Entry is one ancestor's kernel-attested identity plus its codesign data.
type Entry struct {
	PID              int
	ParentPID        int
	BinaryPath       string
	TeamID           string
	BundleIdentifier string
	AuthorityLeaf    string
}

// Platform is the per-OS primitive surface used by Walk. Lookup returns the
// kernel-attested parent PID and binary path for pid; Codesign returns the
// three signing fields for the binary at path. Codesign returns empty
// strings on any failure (unsigned binary, API error, access denied) — not
// an error, because partial signing data is still data we want in the chain.
type Platform interface {
	Lookup(pid int) (parentPID int, binaryPath string, err error)
	Codesign(path string) (teamID, bundleIdentifier, authorityLeaf string)
}

// New is set in each walker_<goos>.go init() to the active platform
// implementation. Tests may swap it for a fake.
var New func() Platform

// Walk runs the walker from startPID toward the kernel terminator.
//
// Returns:
//   - (nil, ErrPlatformUnsupported) if the active platform is unsupported.
//   - (nil, ErrProcessDead) if startPID itself cannot be looked up.
//   - (chain, ErrMaxDepthExceeded) if the walk hits MaxDepth before
//     terminating; the chain holds MaxDepth entries.
//   - (chain, nil) otherwise. A mid-walk lookup failure (ancestor exited,
//     kernel terminator reached) stops the walk and returns the partial
//     chain without an error.
func Walk(startPID int) ([]Entry, error) {
	p := New()
	chain := make([]Entry, 0, 8)
	current := startPID

	for len(chain) < MaxDepth {
		ppid, path, err := p.Lookup(current)
		if err != nil {
			if len(chain) == 0 {
				if errors.Is(err, ErrPlatformUnsupported) {
					return nil, ErrPlatformUnsupported
				}
				return nil, ErrProcessDead
			}
			// Mid-walk lookup failure (kernel terminator, dead ancestor):
			// stop and return what we have. Not an error.
			return chain, nil
		}

		teamID, bundleID, authority := p.Codesign(path)
		chain = append(chain, Entry{
			PID:              current,
			ParentPID:        ppid,
			BinaryPath:       path,
			TeamID:           teamID,
			BundleIdentifier: bundleID,
			AuthorityLeaf:    authority,
		})

		if ppid == 0 || current == 1 {
			return chain, nil
		}
		current = ppid
	}

	return chain, ErrMaxDepthExceeded
}
