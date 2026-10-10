//go:build !cgo || (!darwin && !windows)

package walker

// The darwin and windows walkers need CGo, so this fallback also covers
// those OSes when CGo is disabled. Without it, New stays nil and Walk panics.
func init() {
	New = func() Platform { return unsupportedPlatform{} }
}

type unsupportedPlatform struct{}

func (unsupportedPlatform) Lookup(int) (int, string, error) {
	return 0, "", ErrPlatformUnsupported
}

func (unsupportedPlatform) Codesign(info ProcessInfo) ProcessInfo {
	return info
}
