//go:build !darwin && !windows

package walker

import "github.com/jwyattgh/pidchain/internal/types"

func init() {
	New = func() Platform { return unsupportedPlatform{} }
}

type unsupportedPlatform struct{}

func (unsupportedPlatform) Lookup(int) (int, string, error) {
	return 0, "", types.ErrPlatformUnsupported
}

func (unsupportedPlatform) Codesign(string) (string, string, string) {
	return "", "", ""
}
