# 002g: Per-OS coverage gates at 95%

## Context

The current coverage gate in `.github/workflows/ci.yml` runs only on ubuntu-latest with Go 1.26 and compares against an 88% threshold:

```yaml
      - name: Coverage gate
        if: matrix.os == 'ubuntu-latest' && matrix.go-version == '1.26'
        shell: bash
        run: |
          COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          echo "Total coverage: ${COVERAGE}%"
          THRESHOLD=88
          if (( $(echo "$COVERAGE < $THRESHOLD" | bc -l) )); then
            echo "::error::Coverage ${COVERAGE}% is below threshold ${THRESHOLD}%"
            exit 1
          fi
          echo "Coverage ${COVERAGE}% meets threshold ${THRESHOLD}%"
```

This has a structural problem: the denominator depends on the OS. `walker_darwin.go` and `walker_windows.go` are excluded by build tags on Linux, so Linux coverage measures a different denominator than Darwin or Windows coverage. The 88% threshold was derived from a past measurement on Darwin but applied on Linux, so the current gate compares two unrelated percentages.

The correct pattern is three independent gates — one per OS — each measuring that OS's own coverage denominator against a shared threshold. pidchain's standard is 95%; any OS that currently measures below 95% represents a test-writing gap to close, not a justification for a lower threshold.

## Goal

Replace the single Linux-only gate with three per-OS gates. Each gate:

1. Runs on exactly one OS (ubuntu-latest, macos-latest, windows-latest) at Go 1.26.
2. Measures that OS's own `coverage.out` (already produced by the existing test step).
3. Compares against a 95% threshold.
4. Fails the matrix leg if the OS's coverage is below 95%.

If any OS currently falls below 95%, the gate fails and reveals the gap. Closing that gap (writing more tests for the under-covered code paths) is follow-up work, not part of this doc.

## Files

| Action | Path |
|---|---|
| EDIT | `/Users/jason/workspace/pidchain/.github/workflows/ci.yml` |

## Implementation

### Replace the single gate with per-OS gates

Remove the existing step:

```yaml
      - name: Coverage gate
        if: matrix.os == 'ubuntu-latest' && matrix.go-version == '1.26'
        ...
```

Add a new step that runs on all three OSes at Go 1.26:

```yaml
      - name: Coverage gate (per-OS)
        if: matrix.go-version == '1.26'
        shell: bash
        run: |
          COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          echo "Coverage on ${{ matrix.os }}: ${COVERAGE}%"
          THRESHOLD=95
          if (( $(echo "$COVERAGE < $THRESHOLD" | bc -l) )); then
            echo "::error::Coverage on ${{ matrix.os }} is ${COVERAGE}%, below threshold ${THRESHOLD}%"
            exit 1
          fi
          echo "Coverage on ${{ matrix.os }} meets threshold ${THRESHOLD}%"
```

### Why matrix.go-version == '1.26' only

The test matrix runs on two Go versions (1.25 and 1.26). Coverage numbers should not differ meaningfully between Go versions, and gating on both would double the gate signal without adding information. Pick the newer (1.26) for consistency with the current design and with 002e's govulncheck Go version.

### Codecov upload

The existing Codecov upload step is currently gated to ubuntu-latest + 1.26. Leave that unchanged: Codecov aggregates coverage reports and uploading three separate reports would produce duplicated data without a matching aggregation configuration. Codecov continues to receive only the Linux run. The per-OS GitHub Actions gates are the enforcement surface; Codecov is the visualization surface.

Leave this step as-is:

```yaml
      - name: Upload coverage to Codecov
        if: matrix.os == 'ubuntu-latest' && matrix.go-version == '1.26'
        uses: codecov/codecov-action@v5
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
          files: ./coverage.out
          fail_ci_if_error: false
```

### Anticipated behavior on first run

pidchain's actual per-OS coverage numbers have not been measured against the new gate. Three outcomes are possible per OS:

1. **At or above 95%.** Gate passes. No action required.
2. **Below 95% by a small margin.** Gate fails. Write tests to close the gap, then the gate passes.
3. **Below 95% by a large margin.** Gate fails hard. This indicates the OS has substantial untested code paths (likely platform-specific walker implementation on Darwin/Windows). Closing the gap is a non-trivial work item, to be tracked separately from this doc.

If the first post-merge CI run on main fails the gate on one or more OSes, that is the intended diagnostic signal. Do not lower the threshold; write the tests.

## Success criteria

After merge:

1. A push to main runs the six-leg test matrix. At Go 1.26 on each of the three OSes, the "Coverage gate (per-OS)" step runs.
2. Each gate prints its own coverage percentage and the 95% threshold.
3. Any OS below 95% fails its matrix leg with an explicit `::error::` message naming the OS and the measured coverage.
4. The ubuntu-latest leg continues to upload coverage to Codecov unchanged.
5. The "Coverage gate" step (singular) is gone from the workflow; only "Coverage gate (per-OS)" appears.

## Out of scope

- Writing additional tests to close per-OS coverage gaps. That is follow-up work after 002g lands and surfaces the actual gap per OS.
- Changing the 95% threshold. 95% is the project standard.
- Changing Codecov aggregation. The current single-report upload remains.
- Adding coverage differential gates ("fail if coverage drops by >N% vs main"). Not needed at this time.
- Measuring coverage for the two-Go-version matrix on both versions. Only 1.26 gates.
- Converting the matrix legs into required branch-protection checks. No branch protection exists; single-maintainer pushes directly.
