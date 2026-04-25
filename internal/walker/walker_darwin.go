//go:build darwin

package walker

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <stdlib.h>
#include <string.h>

// cfstring_to_cstring copies a CFStringRef into a malloc'd UTF-8 C string.
// Returns NULL on failure or empty input. Caller must free.
static char* cfstring_to_cstring(CFStringRef s) {
    if (s == NULL) return NULL;
    CFIndex len = CFStringGetLength(s);
    CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    char* buf = (char*)malloc(max);
    if (!buf) return NULL;
    if (!CFStringGetCString(s, buf, max, kCFStringEncodingUTF8)) {
        free(buf);
        return NULL;
    }
    return buf;
}

// pidchain_codesign extracts the three codesign fields for the binary at
// path via Security.framework. Returns 0 on success and writes malloc'd
// C strings into the out parameters (any of which may be NULL if the
// corresponding field wasn't present in the signature). Returns non-zero
// on failure (unsigned binary, API error, missing path); on failure all
// three out parameters are NULL.
//
// Caller must free any non-NULL out string.
static int pidchain_codesign(const char* path,
                             char** out_team,
                             char** out_bundle,
                             char** out_auth) {
    *out_team = NULL;
    *out_bundle = NULL;
    *out_auth = NULL;

    CFStringRef cfPath = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    if (!cfPath) return -1;

    CFURLRef url = CFURLCreateWithFileSystemPath(NULL, cfPath, kCFURLPOSIXPathStyle, false);
    CFRelease(cfPath);
    if (!url) return -1;

    SecStaticCodeRef code = NULL;
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (status != errSecSuccess || code == NULL) return -1;

    CFDictionaryRef info = NULL;
    status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
    CFRelease(code);
    if (status != errSecSuccess || info == NULL) return -1;

    CFStringRef team = (CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
    if (team) *out_team = cfstring_to_cstring(team);

    CFStringRef bundle = (CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
    if (bundle) *out_bundle = cfstring_to_cstring(bundle);

    CFArrayRef certs = (CFArrayRef)CFDictionaryGetValue(info, kSecCodeInfoCertificates);
    if (certs && CFArrayGetCount(certs) > 0) {
        SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(certs, 0);
        if (leaf) {
            CFStringRef summary = SecCertificateCopySubjectSummary(leaf);
            if (summary) {
                *out_auth = cfstring_to_cstring(summary);
                CFRelease(summary);
            }
        }
    }

    CFRelease(info);
    return 0;
}
*/
import "C"

import (
	"unsafe"

	"github.com/jwyattgh/pidchain/internal/types"
)

func init() {
	New = func() Platform { return darwinPlatform{} }
}

type darwinPlatform struct{}

// Lookup uses libproc (proc_pidpath, proc_pidinfo) to resolve a PID's
// kernel-attested binary path and parent PID. Returns ErrProcessDead on
// any failure: process gone, kernel terminator reached (typically PID 1
// where unprivileged callers can't read proc_bsdinfo), or short read.
func (darwinPlatform) Lookup(pid int) (int, string, error) {
	pathBuf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	pathRet := C.proc_pidpath(C.int(pid), unsafe.Pointer(&pathBuf[0]), C.uint32_t(len(pathBuf)))
	if pathRet <= 0 {
		return 0, "", types.ErrProcessDead
	}
	path := C.GoString((*C.char)(unsafe.Pointer(&pathBuf[0])))

	var bsd C.struct_proc_bsdinfo
	bsdSize := C.int(unsafe.Sizeof(bsd))
	bsdRet := C.proc_pidinfo(C.int(pid), C.PROC_PIDTBSDINFO, 0, unsafe.Pointer(&bsd), bsdSize)
	if bsdRet <= 0 || bsdRet < bsdSize {
		return 0, "", types.ErrProcessDead
	}
	return int(bsd.pbi_ppid), path, nil
}

// Codesign extracts the three signing fields from the binary at path via
// Security.framework. Returns empty strings on any failure (unsigned
// binary, missing path, API error, ad-hoc signed binary with no team).
// Codesign failure is never fatal: the ancestor still belongs in the
// chain, just with empty identity fields.
func (darwinPlatform) Codesign(path string) (string, string, string) {
	if path == "" {
		return "", "", ""
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var cTeam, cBundle, cAuth *C.char
	if rc := C.pidchain_codesign(cPath, &cTeam, &cBundle, &cAuth); rc != 0 {
		return "", "", ""
	}

	var team, bundle, auth string
	if cTeam != nil {
		team = C.GoString(cTeam)
		C.free(unsafe.Pointer(cTeam))
	}
	if cBundle != nil {
		bundle = C.GoString(cBundle)
		C.free(unsafe.Pointer(cBundle))
	}
	if cAuth != nil {
		auth = C.GoString(cAuth)
		C.free(unsafe.Pointer(cAuth))
	}
	return team, bundle, auth
}
