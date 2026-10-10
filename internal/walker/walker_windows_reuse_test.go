//go:build windows && cgo

package walker

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// helperEnv switches the test binary into a helper role when
// TestWalk_ReusedParentPIDIsNotTrusted re-runs it.
const helperEnv = "PIDCHAIN_WALKER_HELPER"

// TestHelperProcess is not a real test. TestWalk_ReusedParentPIDIsNotTrusted
// re-runs the test binary with helperEnv set so it can act as a middle
// process that starts a child and exits, or as that long-lived child.
func TestHelperProcess(t *testing.T) {
	switch os.Getenv(helperEnv) {
	case "middle":
		leaf := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		leaf.Env = append(os.Environ(), helperEnv+"=leaf")
		if err := leaf.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println(leaf.Process.Pid)
		os.Exit(0)
	case "leaf":
		time.Sleep(5 * time.Minute)
		os.Exit(0)
	default:
		t.Skip("helper process for TestWalk_ReusedParentPIDIsNotTrusted")
	}
}

// TestWalk_ReusedParentPIDIsNotTrusted runs against the real Windows
// process table. Windows does not reparent orphans: a child keeps its dead
// parent's PID in its snapshot record, and Windows later hands that PID to
// new processes. The walk must not adopt such a newcomer as the parent,
// because doing so adds an unrelated process (and its ancestors) to the
// chain and changes the fingerprint.
func TestWalk_ReusedParentPIDIsNotTrusted(t *testing.T) {
	// The impostor must be signed: unsigned entries add nothing to the
	// fingerprint, so an unsigned impostor could not show a changed one.
	const impostorPath = `C:\Windows\System32\PING.EXE`
	p := windowsPlatform{}
	if s := p.Codesign(ProcessInfo{BinaryPath: impostorPath}); s.TeamID == "" && s.BundleIdentifier == "" && s.AuthorityLeaf == "" {
		t.Fatalf("%s has no readable signature; the test needs a signed impostor", impostorPath)
	}

	// Start middle, which starts leaf and exits. Output waits for middle
	// and closes our handle to it, so Windows is free to reuse its PID.
	middle := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	middle.Env = append(os.Environ(), helperEnv+"=middle")
	out, err := middle.Output()
	if err != nil {
		t.Fatalf("middle helper: %v", err)
	}
	middlePID := middle.Process.Pid
	line, _, _ := bufio.NewReader(bytes.NewReader(out)).ReadLine()
	leafPID, err := strconv.Atoi(string(line))
	if err != nil {
		t.Fatalf("middle helper printed %q, want leaf PID: %v", out, err)
	}
	t.Cleanup(func() {
		if leaf, err := os.FindProcess(leafPID); err == nil {
			_ = leaf.Kill()
			_ = leaf.Release()
		}
	})
	t.Logf("middle PID %d exited; leaf PID %d still running", middlePID, leafPID)

	// Windows keeps reporting the dead middle as leaf's parent.
	ppid, _, err := p.Lookup(leafPID)
	if err != nil {
		t.Fatalf("Lookup(leaf): %v", err)
	}
	t.Logf("snapshot reports leaf's parent as PID %d", ppid)
	if ppid != middlePID {
		t.Fatalf("leaf's recorded parent is %d, want dead middle %d", ppid, middlePID)
	}

	before, err := Walk(leafPID)
	if err != nil {
		t.Fatalf("Walk(leaf) before reuse: %v", err)
	}
	logChain(t, "before reuse", before)
	if len(before.Entries) != 1 {
		t.Fatalf("before reuse the chain should be just leaf, got %d entries", len(before.Entries))
	}

	// Start suspended copies of a signed program, keeping each alive, until
	// Windows gives one the dead middle's PID.
	var fillers []*exec.Cmd
	t.Cleanup(func() {
		for _, c := range fillers {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	})
	const maxFillers = 1000
	deadline := time.Now().Add(3 * time.Minute)
	var impostorPID int
	for len(fillers) < maxFillers && time.Now().Before(deadline) {
		c := exec.Command(impostorPath, "-n", "300", "127.0.0.1")
		c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
		if err := c.Start(); err != nil {
			t.Fatalf("start filler: %v", err)
		}
		fillers = append(fillers, c)
		if c.Process.Pid == middlePID {
			impostorPID = c.Process.Pid
			break
		}
	}
	if impostorPID == 0 {
		t.Fatalf("inconclusive: Windows did not reuse PID %d within %d new processes", middlePID, len(fillers))
	}
	t.Logf("Windows reused PID %d for %s after %d new processes", middlePID, impostorPath, len(fillers))

	after, err := Walk(leafPID)
	if err != nil {
		t.Fatalf("Walk(leaf) after reuse: %v", err)
	}
	logChain(t, "after reuse", after)
	for _, e := range after.Entries {
		if e.PID == impostorPID {
			t.Errorf("chain adopted PID %d (%s), started after leaf, as leaf's parent", e.PID, e.BinaryPath)
		}
	}
	if after.Fingerprint != before.Fingerprint {
		t.Errorf("fingerprint changed after PID reuse: before %s, after %s", before.Fingerprint, after.Fingerprint)
	}
}

func logChain(t *testing.T, label string, c ProcessChain) {
	t.Helper()
	t.Logf("%s: fingerprint %s", label, c.Fingerprint)
	for i, e := range c.Entries {
		t.Logf("  [%d] PID %d parent %d %s (signer %q)", i, e.PID, e.ParentPID, e.BinaryPath, e.TeamID)
	}
}
