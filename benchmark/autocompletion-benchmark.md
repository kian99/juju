# Autocompletion Benchmark — Baseline (Phase 1)

Baseline numbers for the **current bash completion script**
(`etc/bash_completion.d/juju`) before any re-implementation.

## Environment

| Field | Value |
|---|---|
| Machine | Intel Core Ultra X7 358H (16 vCPU, 30 GiB RAM) |
| OS | Ubuntu (linux/amd64) |
| Juju version | 4.0.10-ubuntu-amd64 |
| Controller | `bench-ctrl` (LXD localhost) |
| Models | `controller`, `production`, `staging`, `development`, `testing`, `alpha` (6 total) |
| Runs per scenario | 10 (cold — no completion cache) |
| Date | 2026-05-08 |

## Results

> Times measured by invoking the real `_juju_complete_2` bash completion
> function directly (same path bash takes on `<Tab>`). Cache preserved between
> runs (warm path after first call). 10 runs each.

| Scenario | min | p50 | p99 | max | mean |
|---|---:|---:|---:|---:|---:|
| `juju <Tab>` (subcommand list) | 174 ms | 273 ms | 353 ms | 353 ms | 276 ms |
| **`juju switch <Tab>`** (1 ctrl, 6 models) | **559 ms** | **719 ms** | **764 ms** | **764 ms** | **686 ms** |
| `juju -c <Tab>` (controller list only) | 59 ms | 61 ms | 68 ms | 68 ms | 61 ms |
| `juju deploy -<Tab>` (flag list) | 735 ms | 903 ms | 1005 ms | 1005 ms | 864 ms |
| `juju status -m <Tab>` (model list) | 289 ms | 353 ms | 452 ms | 452 ms | 359 ms |

Completions produced by `juju switch <Tab>` with the test controller:

```
bench-ctrl:admin/controller   bench-ctrl:admin/production
bench-ctrl:admin/staging      bench-ctrl:admin/development
bench-ctrl:admin/testing      bench-ctrl:admin/alpha
admin/controller              admin/production
admin/staging                 admin/development
admin/testing                 admin/alpha
```

## Key Observations

- **`juju switch <Tab>` costs ~720 ms p50** with one controller and six models.
  Each additional controller adds another `juju models` API round-trip, so
  latency scales linearly with the number of controllers.
- Flag completion (`juju deploy -<Tab>`) is surprisingly expensive (~900 ms p50)
  because the completion script runs `juju help deploy` as a subprocess on
  every invocation — there is no caching for help text.
- Controller-only completion (`juju -c <Tab>`) is the fastest scenario (~61 ms
  p50) because the controller list is small and cached.
- `juju status -m <Tab>` (model list) costs ~353 ms p50 due to the
  `juju models` API call.

## Benchmark Script

The script used to collect these numbers is at
[`scripts/bench-completion.sh`](../../scripts/bench-completion.sh).

To reproduce:

```bash
# Ensure the worktree juju binary is on PATH
export PATH="$(pwd)/bin:$PATH"

# Bootstrap a controller and add a few models (one-time setup)
juju bootstrap localhost bench-ctrl
for m in production staging development testing alpha; do
    juju add-model "$m"
done

# Run the benchmark (10 iterations each)
JUJU_BIN=./bin/juju RUNS=10 bash scripts/bench-completion.sh
```

Raw CSV output is written to `bench-completion-results.csv` in the working
directory.

## Phase 5 Target

After implementing `juju-complete`, re-run the same script against the new
binary and record numbers here for comparison.

| Scenario | Baseline p50 | Target p50 |
|---|---:|---:|
| `juju switch <Tab>` (1 ctrl, 6 models) | 719 ms | < 5 ms |
| `juju <Tab>` (subcommand list) | 273 ms | < 50 ms |
| `juju deploy -<Tab>` (flag list) | 903 ms | < 50 ms |
| `juju status -m <Tab>` (model list) | 353 ms | < 10 ms |
