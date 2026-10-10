//go:build windows && cgo

package walker

/*
#cgo LDFLAGS: -lcrypt32 -lwintrust

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <wincrypt.h>
#include <mscat.h>
#include <stdlib.h>
#include <string.h>

// w_to_utf8 converts a malloc'd UTF-16 wide string to a malloc'd UTF-8
// C string. Returns NULL on failure or empty input.
static char* w_to_utf8(const wchar_t* w, int wlen) {
    if (w == NULL || wlen <= 0) return NULL;
    int needed = WideCharToMultiByte(CP_UTF8, 0, w, wlen, NULL, 0, NULL, NULL);
    if (needed <= 0) return NULL;
    char* buf = (char*)malloc((size_t)needed + 1);
    if (!buf) return NULL;
    int written = WideCharToMultiByte(CP_UTF8, 0, w, wlen, buf, needed, NULL, NULL);
    if (written <= 0) {
        free(buf);
        return NULL;
    }
    buf[written] = 0;
    return buf;
}

// extract_name_string runs the two-call CertGetNameStringW pattern (size,
// then fill) for the given attribute OID and returns a malloc'd UTF-8 C
// string. Returns NULL if the attribute isn't present.
static char* extract_name_string(PCCERT_CONTEXT cert, DWORD flags, LPCSTR oid) {
    DWORD size = CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, flags, (void*)oid, NULL, 0);
    if (size <= 1) return NULL;
    wchar_t* wbuf = (wchar_t*)malloc(sizeof(wchar_t) * size);
    if (!wbuf) return NULL;
    DWORD got = CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, flags, (void*)oid, wbuf, size);
    if (got <= 1) {
        free(wbuf);
        return NULL;
    }
    char* out = w_to_utf8(wbuf, (int)got - 1);
    free(wbuf);
    return out;
}

// extract_signer_from_msg pulls the three identity strings from an
// HCRYPTMSG / HCERTSTORE pair. Used by both the embedded-signature path
// and the catalog-signature path. Returns 0 on success, non-zero on
// failure. On failure the out parameters are left untouched (the caller
// initializes them to NULL).
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

    // Microsoft API quirk: CryptCATAdminCalcHashFromFileHandle2's size-probe
    // call (NULL buffer) returns FALSE with ERROR_INSUFFICIENT_BUFFER and
    // populates *hashSize. Don't gate on the BOOL return; gate on hashSize.
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

// pidchain_authenticode extracts Subject O, Subject CN, and Issuer CN
// from the Authenticode signature for the binary at path. Tries the
// embedded-PE signature first; on failure (no embedded signature, common
// for Windows system binaries since Windows 10), falls back to the
// Windows catalog database. Returns 0 on success and writes malloc'd C
// strings into the out parameters (any of which may be NULL if missing).
// Returns non-zero on failure (no embedded and no catalog match, API
// error); on failure all three out parameters are NULL. Caller must free
// any non-NULL out string.
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

// pidchain_codesign_diag returns a diagnostic code describing why
// pidchain_authenticode would fail or succeed for the given path. Values:
//   0  = embedded signature found and signer cert extracted
//   1  = file does not exist or cannot be opened
//   2  = no embedded signature; catalog lookup also failed
//   3  = signer info unreadable on the catalog path
//   4  = signer cert not found in store (embedded or catalog)
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
        if (t) free(t);
        if (b) free(b);
        if (a) free(a);
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
    if (t) free(t);
    if (b) free(b);
    if (a) free(a);
    CryptMsgClose(msg);
    CertCloseStore(certStore, 0);
    return rc == 0 ? 5 : 4;
}
*/
import "C"

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	New = func() Platform { return windowsPlatform{} }
}

type windowsPlatform struct{}

// Lookup uses Toolhelp32 + OpenProcess (via golang.org/x/sys/windows, no
// CGo) to resolve a PID's parent and binary path. Returns ErrProcessDead
// on snapshot failure or PID not found. ERROR_ACCESS_DENIED on the
// OpenProcess (SYSTEM-owned ancestors) yields an empty BinaryPath but
// the parent PID is still returned — the walker will continue with an
// empty-codesign entry, which is correct.
func (windowsPlatform) Lookup(pid int) (int, string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, "", ErrProcessDead
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return 0, "", ErrProcessDead
	}
	for {
		if entry.ProcessID == uint32(pid) {
			return int(entry.ParentProcessID), fullImagePath(pid), nil
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			return 0, "", ErrProcessDead
		}
	}
}

// fullImagePath upgrades Toolhelp32's basename-only ExeFile to the full
// path via OpenProcess + QueryFullProcessImageName. Returns "" on access
// failure (SYSTEM-owned ancestors, gone processes) — empty BinaryPath
// is a valid signal that codesign inspection should be skipped.
func fullImagePath(pid int) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

// Codesign populates the three Authenticode fields on info via the Crypt
// API in CGo. Returns info unchanged on any failure (unsigned binary,
// missing path, API error). Codesign failure is never fatal: the ancestor
// still belongs in the chain, just with empty identity fields.
//
// Field mapping (per spec):
//   - Subject Organization (O)  -> TeamID
//   - Subject Common Name (CN)  -> BundleIdentifier
//   - Issuer Common Name (CN)   -> AuthorityLeaf
func (windowsPlatform) Codesign(info ProcessInfo) ProcessInfo {
	if info.BinaryPath == "" {
		return info
	}
	wpath, err := syscall.UTF16PtrFromString(info.BinaryPath)
	if err != nil {
		return info
	}

	var cTeam, cBundle, cAuth *C.char
	rc := C.pidchain_authenticode((*C.wchar_t)(unsafe.Pointer(wpath)), &cTeam, &cBundle, &cAuth)
	if rc != 0 {
		return info
	}

	if cTeam != nil {
		info.TeamID = C.GoString(cTeam)
		C.free(unsafe.Pointer(cTeam))
	}
	if cBundle != nil {
		info.BundleIdentifier = C.GoString(cBundle)
		C.free(unsafe.Pointer(cBundle))
	}
	if cAuth != nil {
		info.AuthorityLeaf = C.GoString(cAuth)
		C.free(unsafe.Pointer(cAuth))
	}
	return info
}

// codesignDiag exposes pidchain_codesign_diag's return code for tests.
// Not part of the public Platform interface.
func codesignDiag(path string) int {
	wpath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return -1
	}
	return int(C.pidchain_codesign_diag((*C.wchar_t)(unsafe.Pointer(wpath))))
}
