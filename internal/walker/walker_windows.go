//go:build windows

package walker

/*
#cgo LDFLAGS: -lcrypt32

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <wincrypt.h>
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

// pidchain_authenticode extracts Subject O, Subject CN, and Issuer CN
// from the Authenticode signature embedded in the binary at path. Returns
// 0 on success and writes malloc'd C strings into the out parameters
// (any of which may be NULL if missing). Returns non-zero on failure
// (unsigned binary, API error); on failure all three out parameters are
// NULL. Caller must free any non-NULL out string.
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

    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        path,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &encoding,
        &contentType,
        &formatType,
        &certStore,
        &msg,
        NULL);
    if (!ok) return -1;

    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize) || signerInfoSize == 0) {
        if (msg) CryptMsgClose(msg);
        if (certStore) CertCloseStore(certStore, 0);
        return -1;
    }
    PCMSG_SIGNER_INFO signerInfo = (PCMSG_SIGNER_INFO)malloc(signerInfoSize);
    if (!signerInfo) {
        if (msg) CryptMsgClose(msg);
        if (certStore) CertCloseStore(certStore, 0);
        return -1;
    }
    if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo, &signerInfoSize)) {
        free(signerInfo);
        if (msg) CryptMsgClose(msg);
        if (certStore) CertCloseStore(certStore, 0);
        return -1;
    }

    CERT_INFO certInfo;
    certInfo.Issuer = signerInfo->Issuer;
    certInfo.SerialNumber = signerInfo->SerialNumber;
    PCCERT_CONTEXT signerCert = CertFindCertificateInStore(
        certStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        &certInfo,
        NULL);

    if (signerCert) {
        *out_bundle = extract_name_string(signerCert, 0, szOID_COMMON_NAME);
        *out_team = extract_name_string(signerCert, 0, szOID_ORGANIZATION_NAME);
        *out_auth = extract_name_string(signerCert, CERT_NAME_ISSUER_FLAG, szOID_COMMON_NAME);
        CertFreeCertificateContext(signerCert);
    }

    free(signerInfo);
    if (msg) CryptMsgClose(msg);
    if (certStore) CertCloseStore(certStore, 0);
    return 0;
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
