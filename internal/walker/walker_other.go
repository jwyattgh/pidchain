//go:build !darwin && !windows

package walker

func init() {
	New = func() Platform { return unsupportedPlatform{} }
}

type unsupportedPlatform struct{}

func (unsupportedPlatform) Lookup(int) (int, string, error) {
	return 0, "", ErrPlatformUnsupported
}

func (unsupportedPlatform) Codesign(string) (string, string, string) {
	return "", "", ""
}
