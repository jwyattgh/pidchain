# Security Policy

## Reporting a vulnerability

Report security issues privately via GitHub Security Advisories on this repository: <https://github.com/jwyattgh/pidchain/security/advisories/new>.

Do not open a public issue for a suspected vulnerability. Allow up to 7 days for an initial response.

## Supported versions

pidchain is pre-1.0. Only the latest minor release receives security fixes. Once 1.0 ships, this section will be updated with a longer-window policy.

## Threat model

pidchain is designed to defeat the **stored-credential pattern** for same-host IPC authentication described by CWE-312, CWE-313, CWE-522, CWE-256, and CWE-922. The fingerprint is regenerated from kernel-attested process state on every call; nothing secret is stored on or transmitted by the caller.

### In scope

- A same-host attacker running as the same user as the legitimate caller, attempting to impersonate it. pidchain prevents this because the attacker cannot make the kernel lie about its own process ancestry.
- Tampering with the binary on disk between the original pairing and a subsequent call. pidchain detects this because the code-signing identity collected from the modified binary differs, producing a different fingerprint.
- Replacement of an ancestor binary in the chain (e.g. a compromised launcher). Same detection mechanism: the ancestor's signing identity changes, the fingerprint changes.

### Out of scope

- **Remote callers.** pidchain depends on kernel-attested peer-credential primitives that only exist for same-host connections. For remote authentication use mTLS or a transport-layer mechanism.
- **Kernel compromise.** pidchain trusts the kernel's reporting of process ancestry. An attacker with kernel-level capability can forge any system call response, including those pidchain depends on.
- **OS code-signing infrastructure compromise.** pidchain trusts the platform's code-signing verification (Security.framework on macOS, Authenticode/Crypt API on Windows). An attacker who can forge or bypass the OS-level code-signing check can produce a binary that pidchain identifies as legitimate.
- **Same-user privileged process.** A process running as the same user with `ptrace` or `task_for_pid` capability can read and modify the calling process's memory directly. pidchain does not protect against an attacker who already has process-internal access; at that point the credential abstraction is moot.
- **Supply-chain attack on a signed parent.** If a legitimately signed binary in the caller's ancestry is itself compromised at build time (a malicious version published with a valid signature), pidchain has no way to distinguish the malicious build from a legitimate one. This is the same trust model as any code-signing-based identity scheme.

### Not a defense against

- Transport security failures. Use pidchain alongside, not instead of, TLS for any cross-host communication.
- Authorization. pidchain identifies; the consumer's ACL decides what the identified caller is allowed to do.
- Kernel rootkits, compromised OSes, or attackers with administrative privileges on the host.
