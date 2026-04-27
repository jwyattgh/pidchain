# pidchain

Same-host IPC authentication without stored credentials.

## The problem

Local app-to-app authentication typically stores a bearer token — a secret the client keeps in a config file or a keychain entry and transmits to prove identity. Any process running as the same user can read that file and impersonate the client. This is the stored-credential pattern described by CWE-312, CWE-313, CWE-522, CWE-256, and CWE-922: the credential is stealable because it exists at rest.

Encrypting the file does not fix it; the decryption key has the same storage problem. The only fix is removing the stored credential entirely.

## What pidchain does

The kernel already knows which process is on the other end of a local IPC connection. pidchain walks that process's ancestry, extracts each ancestor's code-signing identity (team ID, bundle/subject identifier, signing authority), and hashes the result into a SHA256 fingerprint.

Consumers store the fingerprint as the verification value in their own ACL, keyed by a caller name they assigned at pairing time. On every call, the consumer asks the kernel for the peer PID, re-derives the fingerprint from scratch, and compares.

Two properties make this stronger than a stored token:

1. **No secret at rest on the client.** The "credential" is reconstructed from kernel state on every call. There is nothing in a config file, nothing in a keychain entry, nothing persistently in process memory. A process that reads everything the client has access to gains no credential to replay.
2. **No secret transmitted by the client.** The client doesn't send a fingerprint or any other identifier. The consumer derives the fingerprint independently from the kernel-reported peer PID. A network tap or man-in-the-middle on the IPC channel sees nothing identity-relevant.

A compromised same-user process cannot fake a fingerprint because it cannot make the kernel lie about its own process ancestry or its on-disk binary's code signature.

## Usage

```go
import "github.com/jwyattgh/pidchain"

// Server side, after obtaining the peer PID from the kernel — e.g.
// directly from cmd.Process.Pid for a child spawned over stdio.
fp, err := pidchain.Fingerprint(peerPID)
if err != nil {
    // ErrProcessDead, ErrPlatformUnsupported
}

// pseudocode — your ACL implementation:
switch acl.Lookup(callerName) {
case NotPaired:
    // First contact. Run your pairing flow, store (callerName, fp).
case Paired(stored) where stored == fp:
    // Authenticated. Apply this caller's permissions.
case Paired(stored) where stored != fp:
    // SECURITY EVENT: known caller, unexpected ancestry. Investigate
    // before re-pairing.
}
```

For diagnostic output (pairing prompts, debugging), `pidchain.Chain(pid)` returns the structured ancestor list the fingerprint was computed over.

## How we test it

The integration test (`pidchain_stdio_integration_test.go`) exercises the canonical MCP-style stdio bridge pattern: a probe binary at `testdata/integration/probe/` is built into a temp directory, launched via `exec.Command`, and calls `pidchain.Chain(os.Getppid())` to fingerprint the test process that spawned it. Three runs verify that the fingerprint is deterministic across invocations and that the on-disk codesign path actually fires (at least one ancestor has a non-empty BundleIdentifier).

The library accepts any PID. If you obtain a peer PID through another kernel-attested mechanism — `LOCAL_PEERPID` over a Unix domain socket, `GetNamedPipeClientProcessId` over a Windows named pipe, or some other transport — pidchain will return a fingerprint just fine. We don't ship integration tests for those paths; if you use them, validate against your own test fixtures.

## Platforms

| Platform | Status |
| --- | --- |
| macOS | supported — libproc + Security.framework via CGo |
| Windows | supported — Toolhelp32 + Crypt API via CGo |
| Linux and other | compiles; returns `ErrPlatformUnsupported` at runtime |

## Install

```
go get github.com/jwyattgh/pidchain
```

Requires Go 1.25+. Builds with CGo enabled on macOS and Windows. CGo is required because pidchain uses the platform's native code-signing APIs (Security.framework on macOS, Crypt API on Windows) directly rather than shelling out to CLI tools.

## API reference

Full API documentation: [pkg.go.dev/github.com/jwyattgh/pidchain](https://pkg.go.dev/github.com/jwyattgh/pidchain).

The public surface is two functions (`Fingerprint`, `Chain`), two types (`ProcessInfo`, `ProcessChain`), and two error sentinels (`ErrPlatformUnsupported`, `ErrProcessDead`). Everything else lives under `internal/` and can change without affecting consumers.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, what's in and out of scope, and how to report a vulnerability.

## License

MIT — see [LICENSE](LICENSE).
