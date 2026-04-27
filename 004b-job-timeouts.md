# 004b — Per-Job Timeouts

## Goal

Add `timeout-minutes:` to every job in `ci.yml` and `release.yml` so a hung CGo build or wedged test reclaims the runner instead of waiting GitHub's 360-minute default.

Per CC's measurements (2026-04-27), the longest-observed job is Windows Go 1.25 at 5:19. 15 minutes gives ~3x headroom on that worst case, the standard rule of thumb for runaway-prevention timeouts.

## Files

- CHANGE: `.github/workflows/ci.yml`
- CHANGE: `.github/workflows/release.yml`

## Implementation

### `.github/workflows/ci.yml`

Add `timeout-minutes:` at the job level for each job. Place it directly under `runs-on:`.

| Job | Cap |
|---|---|
| `test` (matrix) | `15` |
| `lint` | `15` |
| `security` | `15` |
| `vuln` | `15` |
| `publish-test-results` | `10` |

Example placement:

````yaml
  test:
    name: Test (${{ matrix.os }}, Go ${{ matrix.go-version }})
    strategy:
      fail-fast: false
      matrix:
        os: [macos-latest, windows-latest, ubuntu-latest]
        go-version: ['1.25', '1.26']
    runs-on: ${{ matrix.os }}
    timeout-minutes: 15
    permissions:
      contents: read
      id-token: write
    steps:
      ...
````

### `.github/workflows/release.yml`

| Job | Cap |
|---|---|
| `verify` (matrix) | `15` |
| `release` | `10` |

Same placement: directly under `runs-on:`.

If 004c is applied first or in the same change, the `release` job is removed and only `verify` needs a timeout.

## Success Criteria

1. `grep -c 'timeout-minutes' .github/workflows/ci.yml` returns 5.
2. `grep -c 'timeout-minutes' .github/workflows/release.yml` returns 2 (or 1 if 004c has applied).
3. Existing CI runs continue to pass within their respective caps. None of the three baseline runs CC measured exceeded 5:20; 15-minute caps should never trip on healthy runs.

## Out of Scope

- Step-level timeouts (overkill at this scale).
- Tightening the 15-minute cap on test (would reduce headroom below 3x given CGo cold-cache variance on Windows).