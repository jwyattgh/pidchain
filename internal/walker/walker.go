// Package walker walks a process's ancestry and collects per-ancestor
// codesign identity. The Walk function is platform-neutral; the per-OS
// Platform implementation lives in walker_<goos>.go.
package walker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// MaxDepth caps the chain length to bound runtime on pathological trees and
// to bound the canonical-bytes size that downstream code hashes.
const MaxDepth = 32

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

// Walk runs the walker from startPID toward the kernel terminator and
// returns the chain together with a SHA256 fingerprint over every entry's
// code-signing identity (TeamID + BundleIdentifier + AuthorityLeaf, in walk
// order, hex-encoded lowercase).
//
// Returns:
//   - (zero, ErrPlatformUnsupported) if the active platform is unsupported.
//   - (zero, ErrProcessDead) if startPID itself cannot be looked up.
//   - (chain, ErrMaxDepthExceeded) if the walk hits MaxDepth before
//     terminating; the chain holds MaxDepth entries and a fingerprint over
//     them.
//   - (chain, nil) otherwise. A mid-walk lookup failure (ancestor exited,
//     kernel terminator reached) stops the walk and returns the partial
//     chain, with its fingerprint, without an error.
func Walk(startPID int) (ProcessChain, error) {
	p := New()
	result := ProcessChain{Entries: make([]ProcessInfo, 0, 8)}
	h := sha256.New()
	current := startPID

	for len(result.Entries) < MaxDepth {
		ppid, path, err := p.Lookup(current)
		if err != nil {
			if len(result.Entries) == 0 {
				if errors.Is(err, ErrPlatformUnsupported) {
					return ProcessChain{}, ErrPlatformUnsupported
				}
				return ProcessChain{}, ErrProcessDead
			}
			// Mid-walk lookup failure (kernel terminator, dead ancestor):
			// stop and return what we have. Not an error.
			result.Fingerprint = hex.EncodeToString(h.Sum(nil))
			return result, nil
		}

		teamID, bundleID, authority := p.Codesign(path)
		result.Entries = append(result.Entries, ProcessInfo{
			PID:              current,
			ParentPID:        ppid,
			BinaryPath:       path,
			TeamID:           teamID,
			BundleIdentifier: bundleID,
			AuthorityLeaf:    authority,
		})
		h.Write([]byte(teamID))
		h.Write([]byte(bundleID))
		h.Write([]byte(authority))

		if ppid == 0 || current == 1 {
			result.Fingerprint = hex.EncodeToString(h.Sum(nil))
			return result, nil
		}
		current = ppid
	}

	result.Fingerprint = hex.EncodeToString(h.Sum(nil))
	return result, ErrMaxDepthExceeded
}
