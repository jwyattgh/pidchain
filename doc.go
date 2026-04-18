// Package pidchain produces SHA256 fingerprints identifying local process
// callers, for same-host authentication without stored credentials.
//
// The consumer obtains a peer PID from the kernel (SO_PEERCRED on Linux,
// LOCAL_PEERPID on macOS, GetNamedPipeClientProcessId on Windows, or an
// equivalent peer-credential syscall) and calls Fingerprint with it. The
// returned string identifies the caller's full process ancestry; identical
// ancestry produces an identical fingerprint. Callers store the fingerprint
// as the verification value in their own authentication record. On every
// inbound call, the consumer re-derives the fingerprint from kernel state
// and compares it against the stored value.
//
// Identity comes from a fresh kernel query per call. Nothing secret is
// stored on the client, nothing is transmitted by the client. The credential
// cannot be stolen because the credential does not exist at rest. This
// addresses the cleartext-credential pattern described by CWE-312, CWE-313,
// CWE-522, CWE-256, and CWE-922.
//
// Scope is deliberately narrow. pidchain works for same-host callers where
// the consumer can obtain a peer PID from the kernel. For remote callers,
// use mTLS, OAuth, or another transport-layer mechanism.
//
// Both Fingerprint and Chain do a fresh kernel walk on every call. The
// package holds no state and is safe for concurrent use from multiple
// goroutines.
package pidchain
