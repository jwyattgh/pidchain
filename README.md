# pidchain

Same-host IPC authentication without stored credentials.

## The problem

Local app-to-app authentication typically stores a bearer token — a secret the client keeps in a config file or a keychain entry and transmits to prove identity. Any process running as the same user can read that file and impersonate the client. This is the stored-credential pattern described by CWE-312, CWE-313, CWE-522, CWE-256, and CWE-922: the credential is stealable because it exists at rest.

Encrypting the file does not fix it; the decryption key has the same storage problem. The only fix is removing the stored credential entirely.

## What pidchain does

The kernel already knows which process is on the other end of a local IPC connection. pidchain walks that process's ancestry, extracts each ancestor's code-signing identity (team ID, bundle/subject identifier, signing authority), and hashes the result into a SHA256 fingerprint.

Consumers store the fingerprint as the verification value in their own ACL, keyed by a caller name they assigned at pairing time. On every call, the consumer asks the kernel for the peer PID, re-derives the fingerprint from scratch, and compares. Nothing secret at rest on the client. Nothing transmitted by the client. A compromised same-user process cannot fake the fingerprint because it cannot make the kernel lie about its own ancestry.

## Usage

```go
import "github.com/jwyattgh/pidchain"

// Server side, after obtaining the peer PID from the kernel — e.g. via
// LOCAL_PEERPID on a Unix domain socket, GetNamedPipeClientProcessId on
// a Windows named pipe, or directly from os.StartProcess for a child
// spawned over stdio.
fp, err := pidchain.Fingerprint(peerPID)
if err != nil {
    // ErrProcessDead, ErrPlatformUnsupported, ErrMaxDepthExceeded
}

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

## When to use it

pidchain applies to IPC where the kernel identifies the peer by PID:

- stdio pipes between a parent and a spawned child.
- Unix domain sockets on macOS.
- Windows named pipes.

It does not apply to TCP loopback, HTTP over localhost, or any remote connection. Use mTLS or a transport-layer mechanism for those.

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

Requires Go 1.25+. Builds with CGo enabled on macOS and Windows.

## API reference

Full API documentation: [pkg.go.dev/github.com/jwyattgh/pidchain](https://pkg.go.dev/github.com/jwyattgh/pidchain).

The public surface is two functions, one type alias, one struct, three error sentinels. Everything else lives under `internal/` and can change without affecting consumers.

## License

TBD.
