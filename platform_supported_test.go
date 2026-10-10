//go:build (darwin || windows) && cgo

package pidchain_test

// platformSupported reports whether this build links a real walker. The
// darwin and windows walkers call native APIs through CGo, so a build with
// CGo disabled falls back to the unsupported walker even on those OSes.
const platformSupported = true
