// Package pidchain produces SHA256 fingerprints identifying local process
// callers, for same-host IPC authentication without stored credentials.
//
// The consumer obtains a peer PID from the kernel and calls Fingerprint
// with it. The returned string identifies the caller's full process
// ancestry; identical ancestry produces an identical fingerprint.
// Callers store the fingerprint as the verification value in their own
// authentication record. On every inbound call, the consumer re-derives
// the fingerprint from kernel state and compares it against the stored
// value.
//
// Identity comes from a fresh kernel query per call. Nothing secret is
// stored on the client, nothing is transmitted by the client. The
// credential cannot be stolen because the credential does not exist at
// rest. This addresses the cleartext-credential pattern described by
// CWE-312, CWE-313, CWE-522, CWE-256, and CWE-922.
//
// # Supported platforms and IPC
//
// pidchain supports macOS and Windows. Linux and other platforms compile
// but return ErrPlatformUnsupported at runtime.
//
// On a supported platform, pidchain applies wherever the kernel can
// identify the process on the other end of a connection:
//
//   - stdio pipes between a parent process and a child it spawned; the
//     consumer is the parent and already knows the child PID.
//   - Unix domain sockets, queried via LOCAL_PEERPID on macOS.
//   - Windows named pipes, queried via GetNamedPipeClientProcessId.
//
// pidchain does not apply to TCP loopback, HTTP over localhost, or any
// other transport where the kernel does not identify the peer by PID.
// For those connections, and for any remote caller, use mTLS or another
// transport-layer mechanism.
//
// # Concurrency
//
// Both Fingerprint and Chain do a fresh kernel walk on every call. The
// package holds no state and is safe for concurrent use from multiple
// goroutines.
package pidchain
