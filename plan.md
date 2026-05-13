# Juju Shell Completion

Completion is embedded in the `juju` binary as `juju autocomplete`. Shell
wrappers call it and feed the output to the shell's completion machinery.
Dynamic entities are resolved from the local client store and direct Juju API
connections.

## Architecture

```
shell tab-press
  └─ etc/bash_completion.d/juju  (or etc/zsh/completions/_juju)
       └─ juju autocomplete --cword N --current W --word W ...
            ├─ completion.Describe(registerCommands)   → static snapshot
            │    └─ cmd.Info.Autocomplete              → command-owned rules
            └─ completion.Backend.Complete(snapshot, req)
                 ├─ offline: controllers, models       → local client store
                 └─ online:  applications, units,      → api/connector +
                             machines, config keys        api/client/*
```

## Key files

| File | Role |
|---|---|
| `cmd/cmd/cmd.go` | Shared command metadata, including `Info.Autocomplete` |
| `cmd/juju/commands/autocomplete.go` | `juju autocomplete` subcommand |
| `cmd/juju/completion/metadata.go` | Builds static snapshot of commands, flags, and autocomplete rules |
| `cmd/juju/completion/complete.go` | Routes a shell request to candidate sets |
| `cmd/juju/completion/backend.go` | Provides controllers/models/apps/units/machines/config keys |
| `cmd/juju-completion/main.go` | Standalone binary (retained, shares the same library) |
| `etc/bash_completion.d/juju` | Bash wrapper — `source` to activate |
| `etc/zsh/completions/_juju` | Zsh wrapper — `source` or add dir to `fpath` |

## Static snapshot

`completion.Describe(func(Registry))` accepts an injected registrar to avoid
an import cycle between `completion` and `commands`. Both `autocomplete.go`
and `juju-completion/main.go` pass `commands.RegisterCommands` through a small
local adapter struct. The snapshot now carries `cmd.Info.Autocomplete`, so the
completion engine can derive positional and flag-value resources from command
metadata instead of a hardcoded routing table.

## Dynamic backend

`Backend` in `backend.go` has two tiers:

**Offline (~0 ms)** — reads the local YAML client store directly:
- `Controllers()` — `store.AllControllers()`
- `Models()` — `store.AllModels(controller)` for every controller
- `currentModel(store)` — `JUJU_MODEL` env var → `store.CurrentController()` +
  `store.CurrentModel(controller)`; no subprocess

**Online (≤3 s dial timeout)** — opens a direct API connection:
- `Applications`, `Units`, `Machines` — resolve the model UUID from the local
  store, open `connector.NewClientStore(...)`, then call
  `api/client/client.NewClient(...).Status(...)`
- `ApplicationConfigKeys` — reuse the same model connection pattern and call
  `api/client/application.NewClient(...).Get(...)`

## Shell activation

```bash
# bash
source etc/bash_completion.d/juju

# zsh
source etc/zsh/completions/_juju
# or add to fpath:
fpath=(etc/zsh/completions $fpath) && autoload -Uz compinit && compinit
```

## Deferred

- snap packaging
- fish completion
- cache layer for status-backed completion

- fish completion
- REPL completion
- cache layer for status-backed completion
- benchmark documentation

## TL;DR

The implementation moved Juju bash completion to a separate `juju-completion` Go binary plus a
thin shell wrapper.

The shell layer now only forwards Bash completion state to the backend. The backend builds static
command and flag metadata directly from Juju's registered commands at runtime, and resolves dynamic
controller, model, application, unit, machine, and config-key completions from local client state
and direct Juju API calls.

This replaced the previous large bash/Python completion script and superseded the earlier
`juju-complete` prototype package.

## Final decisions

- **Binary**: use a separate `juju-completion` binary rather than embedding completion in `juju`
- **Shell**: keep Bash as a thin adapter only; move Juju-specific logic into Go
- **Static metadata**: generate command and flag metadata at runtime from `commands.RegisterCommands`
  rather than from a committed JSON artifact
- **Autocomplete rules**: define per-command completion resources in `cmd.Info.Autocomplete`
  so positional completion is owned by the command, not by `complete.go`
- **Dynamic metadata**: use the Juju client store for controllers and models, and use
  direct API connections for model-scoped entities
- **Tests**: add focused Go tests for metadata extraction, backend providers, and completion routing
- **Documentation**: add installation and developer testing documentation for the new flow
- **Scope**: Bash is implemented; zsh, fish, REPL completion, snap packaging changes, and caching
  remain deferred

---

## What was implemented

### 1. Separate backend binary

A new backend binary lives in `cmd/juju-completion/`.

Implemented entrypoints:

- `describe`
- `commands`
- `flags <command>`
- `controllers`
- `models`
- `applications --model <model>`
- `units --model <model> [--suffix value]`
- `machines --model <model>`
- `complete --cword N --current VALUE --word ...`

The `complete` subcommand is the shell-facing protocol used by the Bash wrapper.

### 2. Runtime static metadata snapshot

Static command and flag completion is implemented in `cmd/juju/completion/metadata.go`.

The backend does not scrape help output and does not load a generated JSON file. Instead it:

- calls `commands.RegisterCommands`
- records command names, aliases, args, and purpose
- builds a fresh `gnuflag.FlagSet` per command
- captures registered flags directly from `SetFlags`

To support that, `cmd/juju/commands/main.go` exports the registration hook used by completion.

### 3. Backend providers for dynamic entities

Dynamic completion is implemented in `cmd/juju/completion/backend.go`.

Current providers:

- **Controllers**: from `jujuclient.NewFileClientStore().AllControllers()`
- **Models**: from `AllModels(controller)`, returning `controller:model` entries for every
  controller
- **Current model resolution**:
  - use `JUJU_MODEL` when present
  - otherwise read `CurrentController()` + `CurrentModel()` from the client store
- **Applications / units / machines**:
  - resolve the target model UUID from `store.AllModels`
  - open a model-scoped API connection with `connector.NewClientStore`
  - call `api/client/client.Client.Status`
- **Application config keys**:
  - reuse the model-scoped API connection
  - call `api/client/application.Client.Get`

### 4. Shell completion routing in Go

Completion request routing lives in `cmd/juju/completion/complete.go`.

The current behavior is:

- first command position completes Juju commands and aliases
- `juju help ...` completes commands
- current token that looks like a flag completes flags for the selected command
- standard resource flags (`--controller`, `--model`, `--application`, `--unit`, `--machine`) resolve dynamically
- positional completion is driven by `cmd.Info.Autocomplete`
- positional parsing skips known flag values so completion works when flags are interleaved with args
- dependent resources can reference earlier positionals, e.g. `juju config <app> <key>`

Implemented command-owned routing currently includes:

- `switch` → controllers and models
- `config` → applications, then application config keys
- `refresh`, `expose`, `unexpose`, `remove-application`, `constraints`, `set-constraints` → applications
- `status` → applications and units
- `ssh`, `scp` → units and machines
- `debug-hooks`, `debug-code`, `resolved` → units
- `remove-unit` → units and applications
- `show-machine`, `remove-machine` → machines

### 5. Thin Bash wrapper

`etc/bash_completion.d/juju` was reduced to a thin Bash adapter.

The wrapper now:

- finds the `juju-completion` binary
- reads `COMP_WORDS` and `COMP_CWORD`
- calls `juju-completion complete ...`
- loads newline-separated results into `COMPREPLY`

The previous large Bash script and its Bash/Python heuristics were removed.

### 6. Documentation and tests

Documentation was added in `docs/howto/manage-bash-auto-completion.md` and linked from
`docs/howto/index.md`.

Focused tests were added for:

- static metadata extraction
- backend controller/model/application/unit/machine providers
- shell completion routing

The previous draft plan said not to add tests while the protocol was exploratory. The implemented
version did add tests because the request/response shape settled quickly and the routing logic was
small enough to lock down safely.

### 7. Old prototype removal

The previous `cmd/juju-complete/` package was removed in favor of the final
`cmd/juju-completion/` backend.

---

## What changed from the original proposal

The final implementation differs from the original plan in a few important ways.

### Implemented instead of planned

- `juju-completion` was used as the final binary name instead of `juju-complete`
- runtime metadata extraction replaced the planned generated static JSON file
- command-owned autocomplete metadata replaced the hardcoded positional routing table
- direct API connections were kept for model-scoped entities instead of shelling
  out through the CLI
- focused Go tests were added instead of keeping the implementation test-free
- Bash support and documentation landed; zsh support and broader packaging work did not

### Not implemented from the original draft

- generated `internal/completion/static.json`
- `cmd/juju-complete/generate/`
- zsh completion script
- Makefile completion helper targets
- snap packaging changes for the new backend
- benchmark script and benchmark documentation
- REPL completion support
- stale-cache / background-refresh behavior for dynamic completions

---

## Current limitations

- The current thin wrapper only targets Bash.
- Live completion for applications, units, machines, and config keys depends on
  the controller API being reachable for the selected model.
- There is no cache layer yet for status-backed completion.
- The metadata model is sequence-based. Commands with flag-conditioned or shape-conditioned
  argument semantics may need richer rule conditions than `Positionals` plus resource dependencies.

---

## Key files

- `cmd/juju-completion/main.go` — backend entrypoint and shell-facing `complete` command
- `cmd/juju/completion/metadata.go` — runtime command and flag snapshot generation
- `cmd/juju/completion/backend.go` — controller, model, application, unit, machine, and config-key providers via client store and API connections
- `cmd/juju/completion/complete.go` — metadata-driven routing from shell context to candidate sets
- `cmd/juju/commands/main.go` — exported command registration hook for completion metadata
- `etc/bash_completion.d/juju` — thin Bash wrapper
- `docs/howto/manage-bash-auto-completion.md` — install and developer testing instructions

## Validation performed

Focused validation for the implemented approach is:

1. `go test ./cmd/juju/completion`
2. `go build ./cmd/juju-completion`
3. `bash -n ./etc/bash_completion.d/juju`
4. shell simulation of command completion:
   - `juju help c`
5. shell simulation of flag completion:
   - `juju deploy --c`

Live model-backed completion was only partially validated because the environment can still require
interactive Juju credentials when opening a model-scoped API connection.

## Follow-up work

If this work continues, the next logical slices are:

1. add zsh support with the same backend protocol
2. decide whether model-backed completion needs caching to avoid repeated API calls
3. expand positional completion coverage command by command
4. wire the backend and wrapper into packaging and snap installation flows
5. benchmark the backend path against the removed legacy shell script
