// Package walker walks a process's ancestry and collects per-ancestor
// codesign identity. The Walk function is platform-neutral; the per-OS
// Platform implementation lives in walker_<goos>.go.
package walker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Platform is the per-OS primitive surface used by Walk.
//
// Lookup returns the kernel-attested parent PID and binary path for pid.
// Codesign takes a ProcessInfo with PID, ParentPID, and BinaryPath already
// filled in, populates the three signing fields from the binary at the
// given BinaryPath, and returns the completed struct. Codesign returns the
// info unchanged on any failure (unsigned binary, API error, access
// denied) — partial signing data is still data we want in the chain.
type Platform interface {
	Lookup(pid int) (parentPID int, binaryPath string, err error)
	Codesign(info ProcessInfo) ProcessInfo
}

// New is set in each walker_<goos>.go init() to the active platform
// implementation. Tests may swap it for a fake.
var New func() Platform

// Walk runs the walker from startPID toward the kernel terminator and
// returns the chain together with a SHA256 fingerprint over every entry's
// code-signing identity.
//
// Returns:
//   - (zero, ErrPlatformUnsupported) if the active platform is unsupported.
//   - (zero, ErrProcessDead) if startPID itself cannot be looked up.
//   - (chain, nil) on success. A mid-walk lookup failure (kernel terminator
//     reached, ancestor exited) stops the walk and returns the partial
//     chain without an error.
func Walk(startPID int) (ProcessChain, error) {
	p := New()                // platform: the active per-OS implementation
	var entries []ProcessInfo // ordered list of ancestors, queried PID first
	current := startPID

	for {
		ppid, path, err := p.Lookup(current)
		if err != nil {
			if len(entries) == 0 {
				return ProcessChain{}, classifyStartupErr(err)
			}
			return finalize(entries), nil
		}

		entries = append(entries, p.Codesign(ProcessInfo{
			PID:        current,
			ParentPID:  ppid,
			BinaryPath: path,
		}))

		if isKernelTerminator(ppid, current) {
			break
		}
		current = ppid
	}

	return finalize(entries), nil
}

// classifyStartupErr maps a Lookup error received before any entry was
// added (i.e., the start PID itself failed) to the appropriate public
// sentinel. errors.Is is used so wrapped errors continue to classify
// correctly if a future platform implementation wraps with %w.
func classifyStartupErr(err error) error {
	if errors.Is(err, ErrPlatformUnsupported) {
		return ErrPlatformUnsupported
	}
	return ErrProcessDead
}

// finalize attaches the fingerprint to a populated entry list and returns
// the completed chain. Used for both normal termination (kernel terminator
// reached) and mid-walk truncation (Lookup failed after at least one
// entry was collected).
func finalize(entries []ProcessInfo) ProcessChain {
	return ProcessChain{
		Entries:     entries,
		Fingerprint: computeFingerprint(entries),
	}
}

// isKernelTerminator returns true when the walk has reached the top of the
// process tree. PPID 0 is the kernel's "no parent above me" signal; PID 1
// is init/launchd/systemd, the topmost user-visible process.
func isKernelTerminator(ppid, current int) bool {
	return ppid == 0 || current == 1
}

// computeFingerprint produces the lowercase hex SHA256 over every entry's
// TeamID + BundleIdentifier + AuthorityLeaf, in walk order.
func computeFingerprint(entries []ProcessInfo) string {
	h := sha256.New() // hash accumulator; .Sum(nil) at the end yields the digest
	for _, e := range entries {
		h.Write([]byte(e.TeamID))
		h.Write([]byte(e.BundleIdentifier))
		h.Write([]byte(e.AuthorityLeaf))
	}
	return hex.EncodeToString(h.Sum(nil))
}
