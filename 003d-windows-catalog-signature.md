# 003d — Windows Codesign: Catalog-Signature Fallback

## Goal

Extend `pidchain_authenticode` in `internal/walker/walker_windows.go` to handle catalog-signed binaries. Today the function only finds embedded Authenticode signatures; most Windows system binaries (notepad.exe, explorer.exe, svchost.exe, calc.exe, cmd.exe) carry their signatures in separate `.cat` files instead, and Codesign returns empty fields for them.

After this change, Codesign extracts the same three identity strings (TeamID, BundleIdentifier, AuthorityLeaf) from catalog-signed binaries that it extracts from embedded-signed binaries.

## Background

The current `pidchain_authenticode` calls `CryptQueryObject` with `CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED`, which returns failure for any binary without an inline PE signature. Diagnostic output from CI confirmed `notepad.exe` on the GitHub `windows-latest` runner produces diag code 2 (CryptQueryObject failed → no embedded signature).

Catalog signing is the dominant signature format for Windows system binaries since Windows 10. The signature is stored in `C:\Windows\System32\CatRoot\<GUID>\*.cat` files, indexed by SHA1 hash of the signed file's PE-relevant content. The Crypt API exposes catalog signatures through:

- `CryptCATAdminAcquireContext2` — open a handle to the catalog admin.
- `CryptCATAdminCalcHashFromFileHandle2` — compute the file's catalog hash.
- `CryptCATAdminEnumCatalogFromHash` — find the catalog file containing that hash.
- `CryptCATCatalogInfoFromContext` — get the catalog file's path.
- `CryptQueryObject` (re-used) on the catalog file path → standard PKCS#7 signer extraction.

Once the catalog file is found, the same `CryptQueryObject` + `CryptMsgGetParam` + `CertFindCertificateInStore` + `extract_name_string` chain that handles embedded signatures works on the catalog file. The signer extracted from a catalog file is Microsoft (or whichever publisher signed the catalog), which is the same identity that signing the binary inline would have produced.

The link library `wintrust.lib` is required (catalog admin functions live there). It must be added to the `#cgo LDFLAGS` line.

## Files

- CHANGE: `internal/walker/walker_windows.go`
- CHANGE: `internal/walker/walker_windows_test.go`

## Implementation

### `internal/walker/walker_windows.go`

**1. Update the `#cgo LDFLAGS` line.**

Before:
```c
#cgo LDFLAGS: -lcrypt32
```

After:
```c
#cgo LDFLAGS: -lcrypt32 -lwintrust
```

**2. Add `mscat.h` to the includes.**

Add after the existing `#include` lines:
```c
#include <mscat.h>
```

**3. Refactor `pidchain_authenticode` to extract the signer-from-PKCS7 logic into a reusable helper.**

The current function does three things in sequence: open file with CryptQueryObject, get signer info, look up signer cert. The signer-info-from-CryptMsg portion is needed for both embedded and catalog paths. Extract it into a helper:

```c
// extract_signer_from_msg pulls the three identity strings from an
// HCRYPTMSG / HCERTSTORE pair. Used by both the embedded-signature path
// and the catalog-signature path. Returns 0 on success, non-zero on
// failure. On failure the out parameters are NULL.
static int extract_signer_from_msg(HCRYPTMSG msg,
                                   HCERTSTORE certStore,
                                   char** out_team,
                                   char** out_bundle,
                                   char** out_auth) {
    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize) || signerInfoSize == 0) {
        return -1;
    }
    PCMSG_SIGNER_INFO signerInfo = (PCMSG_SIGNER_INFO)malloc(signerInfoSize);
    if (!signerInfo) {
        return -1;
    }
    if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo, &signerInfoSize)) {
        free(signerInfo);
        return -1;
    }

    CERT_INFO certInfo;
    certInfo.Issuer = signerInfo->Issuer;
    certInfo.SerialNumber = signerInfo->SerialNumber;
    PCCERT_CONTEXT signerCert = CertFindCertificateInStore(
        certStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_SUBJECT_CERT, &certInfo, NULL);

    int result = -1;
    if (signerCert) {
        *out_bundle = extract_name_string(signerCert, 0, szOID_COMMON_NAME);
        *out_team = extract_name_string(signerCert, 0, szOID_ORGANIZATION_NAME);
        *out_auth = extract_name_string(signerCert, CERT_NAME_ISSUER_FLAG, szOID_COMMON_NAME);
        CertFreeCertificateContext(signerCert);
        result = 0;
    }

    free(signerInfo);
    return result;
}
```

**4. Add a catalog-lookup helper.**

```c
// find_catalog_file looks up the catalog file containing the signature
// for the binary at path. On success, copies the catalog file path into
// out_catalog (a wchar_t buffer of MAX_PATH wchar_t units) and returns 0.
// Returns non-zero on any failure (no catalog admin handle, hash failed,
// no catalog matches the hash).
static int find_catalog_file(const wchar_t* path, wchar_t* out_catalog) {
    out_catalog[0] = 0;

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    HCATADMIN hCatAdmin = NULL;
    if (!CryptCATAdminAcquireContext2(&hCatAdmin, NULL, BCRYPT_SHA256_ALGORITHM, NULL, 0)) {
        // Fall back to SHA1 catalog admin (older catalogs).
        if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
            CloseHandle(hFile);
            return -1;
        }
    }

    DWORD hashSize = 0;
    CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashSize, NULL, 0);
    if (hashSize == 0) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return -1;
    }
    BYTE* hash = (BYTE*)malloc(hashSize);
    if (!hash) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return -1;
    }
    if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashSize, hash, 0)) {
        free(hash);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return -1;
    }
    CloseHandle(hFile);

    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, NULL);
    if (!hCatInfo) {
        free(hash);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return -1;
    }

    CATALOG_INFO catInfo;
    catInfo.cbStruct = sizeof(catInfo);
    int result = -1;
    if (CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
        wcsncpy(out_catalog, catInfo.wszCatalogFile, MAX_PATH - 1);
        out_catalog[MAX_PATH - 1] = 0;
        result = 0;
    }

    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    free(hash);
    CryptCATAdminReleaseContext(hCatAdmin, 0);
    return result;
}
```

**5. Rewrite `pidchain_authenticode` to try embedded first, then catalog.**

```c
static int pidchain_authenticode(const wchar_t* path,
                                 char** out_team,
                                 char** out_bundle,
                                 char** out_auth) {
    *out_team = NULL;
    *out_bundle = NULL;
    *out_auth = NULL;

    HCERTSTORE certStore = NULL;
    HCRYPTMSG msg = NULL;
    DWORD encoding = 0, contentType = 0, formatType = 0;

    // Try embedded signature first.
    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE, path,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, &encoding, &contentType, &formatType,
        &certStore, &msg, NULL);

    if (ok) {
        int rc = extract_signer_from_msg(msg, certStore, out_team, out_bundle, out_auth);
        CryptMsgClose(msg);
        CertCloseStore(certStore, 0);
        if (rc == 0) return 0;
    }

    // Embedded failed or had no extractable signer. Try catalog.
    wchar_t catalogPath[MAX_PATH];
    if (find_catalog_file(path, catalogPath) != 0) {
        return -1;
    }

    certStore = NULL;
    msg = NULL;
    ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE, catalogPath,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, &encoding, &contentType, &formatType,
        &certStore, &msg, NULL);
    if (!ok) return -1;

    int rc = extract_signer_from_msg(msg, certStore, out_team, out_bundle, out_auth);
    CryptMsgClose(msg);
    CertCloseStore(certStore, 0);
    return rc;
}
```

Note the flag difference on the catalog path: `CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED` (not `_EMBED`) because the catalog file itself *is* a PKCS#7 file, not a PE with an embedded signature.

**6. Update `pidchain_codesign_diag` to reflect the new behavior.**

Add catalog-lookup outcomes to the diagnostic codes:

```c
// pidchain_codesign_diag returns a diagnostic code describing why
// pidchain_authenticode would fail or succeed for the given path. Values:
//   0  = embedded signature found and signer cert extracted
//   1  = file does not exist or cannot be opened
//   2  = no embedded signature; catalog lookup also failed
//   3  = signer info unreadable
//   4  = signer cert not found in store
//   5  = catalog signature found and signer cert extracted (success)
// Used only by tests to distinguish failure modes in CI logs.
static int pidchain_codesign_diag(const wchar_t* path) {
    DWORD attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) return 1;

    HCERTSTORE certStore = NULL;
    HCRYPTMSG msg = NULL;
    DWORD encoding = 0, contentType = 0, formatType = 0;

    // Try embedded first.
    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE, path,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, &encoding, &contentType, &formatType,
        &certStore, &msg, NULL);

    if (ok) {
        char *t = NULL, *b = NULL, *a = NULL;
        int rc = extract_signer_from_msg(msg, certStore, &t, &b, &a);
        if (t) free(t); if (b) free(b); if (a) free(a);
        CryptMsgClose(msg);
        CertCloseStore(certStore, 0);
        if (rc == 0) return 0;
        return 4;  // signer not found in embedded path
    }

    // Try catalog.
    wchar_t catalogPath[MAX_PATH];
    if (find_catalog_file(path, catalogPath) != 0) {
        return 2;  // no embedded, no catalog
    }

    certStore = NULL;
    msg = NULL;
    ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE, catalogPath,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, &encoding, &contentType, &formatType,
        &certStore, &msg, NULL);
    if (!ok) return 3;

    char *t = NULL, *b = NULL, *a = NULL;
    int rc = extract_signer_from_msg(msg, certStore, &t, &b, &a);
    if (t) free(t); if (b) free(b); if (a) free(a);
    CryptMsgClose(msg);
    CertCloseStore(certStore, 0);
    return rc == 0 ? 5 : 4;
}
```

The Go-side `Codesign` and `codesignDiag` wrappers do not change. They call the C functions through the same signatures.

### `internal/walker/walker_windows_test.go`

Update `TestWindowsPlatform_CodesignSystemBinary` to accept both diag code 0 (embedded) and 5 (catalog) as success, and to fail on the unchanged failure codes:

```go
func TestWindowsPlatform_CodesignSystemBinary(t *testing.T) {
	const path = `C:\Windows\System32\notepad.exe`

	if _, err := os.Stat(path); err != nil {
		t.Skipf("notepad.exe not present at %s: %v", path, err)
	}

	diag := codesignDiag(path)

	p := windowsPlatform{}
	info := p.Codesign(ProcessInfo{BinaryPath: path})

	allEmpty := info.TeamID == "" && info.BundleIdentifier == "" && info.AuthorityLeaf == ""

	switch diag {
	case 0, 5:
		if allEmpty {
			t.Fatalf("diag reports success (%d) but Codesign returned empty fields: team=%q bundle=%q auth=%q",
				diag, info.TeamID, info.BundleIdentifier, info.AuthorityLeaf)
		}
	case 1:
		t.Fatalf("file disappeared between os.Stat and CGo call (race): %s", path)
	case 2:
		t.Fatalf("notepad.exe has no embedded Authenticode signature and no catalog match. diag=2")
	case 3:
		t.Fatalf("notepad.exe signer info is unreadable. diag=3")
	case 4:
		t.Fatalf("notepad.exe signer cert not found in store. diag=4")
	default:
		t.Fatalf("unknown diag code: %d", diag)
	}
}
```

`TestWindowsPlatform_CodesignProbeSignedBinary` should now find populated fields on the first iteration (cmd.exe, the first candidate, is catalog-signed) and stop without skipping. No change to the test's logic is required, but the skip path will no longer trigger.

## Success Criteria

1. `go build ./...` succeeds on Windows.
2. `go test ./...` passes on Windows; `TestWindowsPlatform_CodesignSystemBinary` reports diag=5 with non-empty signing fields for notepad.exe.
3. `TestWindowsPlatform_CodesignProbeSignedBinary` no longer skips on the GitHub Windows runner.
4. `Fingerprint(pid)` and `Chain(pid)` on a Windows process whose ancestors include catalog-signed system binaries (svchost.exe, services.exe) now produce non-empty TeamID/BundleIdentifier/AuthorityLeaf fields for those entries.
5. macOS and Linux behavior is unchanged. (The change is in walker_windows.go only.)

## Out of Scope

- Reviewing the Crypt API memory-management correctness in the existing CGo (separate audit).
- Adding tests for binaries outside `C:\Windows\System32\`.
- Switching the embedded-signature path to use `WinVerifyTrust` (the alternative option discussed during review; this DR keeps embedded extraction unchanged).
- Updating `walker_darwin.go` (out of scope for Windows-only fix).

## Go Standards Compliance

This refactor doesn't violate any Go standard. The Go side is unchanged; all changes are in the C portion of the CGo block. The C code follows the same allocation/free patterns the existing function uses.
