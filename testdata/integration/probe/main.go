// Command probe is a test fixture for pidchain integration tests.
// It calls pidchain against a PID acquired via the channel selected by
// --channel, then writes the resulting Chain and Fingerprint to stdout
// as JSON.
//
// For --channel=stdio, the PID is os.Getppid() — the process that
// launched this binary via fork+exec. This mirrors the caller-probe
// pattern: Claude Desktop launches caller-probe; caller-probe calls
// pidchain to identify Claude Desktop.
//
// Exit codes: 0 on success; 2 for any helper-side error (unknown channel,
// JSON encode failure).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/jwyattgh/pidchain"
)

type probeOutput struct {
	Channel     string                `json:"channel"`
	CallerPID   int                   `json:"caller_pid"`
	Chain       pidchain.ProcessChain `json:"chain"`
	Fingerprint string                `json:"fingerprint"`
	ChainErr    string                `json:"chain_err,omitempty"`
	FpErr       string                `json:"fingerprint_err,omitempty"`
}

func main() {
	channel := flag.String("channel", "stdio", "PID acquisition channel: stdio (003e), uds (003f), namedpipe (003g)")
	flag.Parse()

	var callerPID int
	switch *channel {
	case "stdio":
		callerPID = os.Getppid()
	default:
		fmt.Fprintf(os.Stderr, "probe: unsupported channel %q (003f/003g not yet implemented)\n", *channel)
		os.Exit(2)
	}

	out := probeOutput{Channel: *channel, CallerPID: callerPID}

	chain, chainErr := pidchain.Chain(callerPID)
	out.Chain = chain
	if chainErr != nil {
		out.ChainErr = chainErr.Error()
	}

	fp, fpErr := pidchain.Fingerprint(callerPID)
	out.Fingerprint = fp
	if fpErr != nil {
		out.FpErr = fpErr.Error()
	}

	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "probe: encode: %v\n", err)
		os.Exit(2)
	}
}
