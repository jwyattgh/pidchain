// Command probe is a test fixture for pidchain integration tests.
// It calls pidchain.Chain on its own PID and writes the returned
// ProcessChain to stdout as JSON. The chain begins with this probe
// binary and walks up through its ancestors, mirroring how
// the prototype probe.get_caller_signature reports self + parent_chain.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jwyattgh/pidchain"
)

func main() {
	chain, err := pidchain.Chain(os.Getpid())
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(chain); err != nil {
		fmt.Fprintf(os.Stderr, "probe: encode: %v\n", err)
		os.Exit(2)
	}
}
