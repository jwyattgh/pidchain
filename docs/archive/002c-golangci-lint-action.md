# 002c: Replace piped-curl golangci-lint install with golangci-lint-action

## Context

Two jobs in `.github/workflows/ci.yml` install golangci-lint by piping curl from the master branch of the golangci-lint repo:

```yaml
      - name: Install golangci-lint
        run: |
          curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
            | sh -s -- -b $(go env GOPATH)/bin v2.6.2
```

The `install.sh` script is fetched from the `master` branch at runtime. Whatever the maintainer of `golangci-lint` has on `master` today is what executes during the install. The `v2.6.2` argument only pins the binary version that the script downloads; it does not pin the script itself.

The canonical replacement is the official `golangci/golangci-lint-action`, which handles install, caches the binary, and exposes a `version:` parameter that keeps the `v2.6.2` version pin. No piped curl, no branch tracking, and the action's own source is a reviewable reference rather than a live-fetched script.

## Goal

Remove both piped-curl install steps from `ci.yml` and replace each with a `golangci/golangci-lint-action` step. Keep the `v2.6.2` version pin intact via the action's `version:` parameter.

## Files

| Action | Path |
|---|---|
| EDIT | `/Users/jason/workspace/pidchain/.github/workflows/ci.yml` |

## Implementation

### The `lint` job

Replace the two steps:

```yaml
      - name: Install golangci-lint
        run: |
          curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
            | sh -s -- -b $(go env GOPATH)/bin v2.6.2

      - name: Run golangci-lint
        run: golangci-lint run
```

with:

```yaml
      - name: Run golangci-lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: v2.6.2
```

### The `pr-verify` job (added by 002a)

Replace the same two steps in the `pr-verify` job with the same `golangci/golangci-lint-action@v6` step.

### Tag pin, not SHA

`golangci/golangci-lint-action@v6` is a floating major-version tag. This is intentional: pidchain treats CI tooling as tag-pinned and floating, not SHA-pinned. See the project-wide decision recorded in 002d context.

### Setup-go caching remains

`actions/setup-go@v5` already caches `$GOMODCACHE` and `$GOCACHE`. The golangci-lint-action adds its own binary cache for the golangci-lint binary. Both are compatible and no manual cache configuration is required.

## Success criteria

After merge:

1. `lint` job logs no longer contain the `curl | sh` install step.
2. `lint` job logs show a step running `golangci/golangci-lint-action@v6` with version `v2.6.2`.
3. `lint` job completes successfully, same findings as before (or clean).
4. On a PR, `pr-verify` job logs show the same action, same version, same outcome.
5. No network fetch from `raw.githubusercontent.com/golangci/...` appears in either job's logs.

## Out of scope

- Upgrading the golangci-lint version (stays at `v2.6.2`).
- Changes to `.golangci.yml` (002f touches this for gosec removal).
- SHA-pinning the action to a specific commit (see 002d).
- Changing any other action reference.
