//go:build !cgo || (!darwin && !windows)

package pidchain_test

// platformSupported reports whether this build links a real walker. See
// platform_supported_test.go.
const platformSupported = false
