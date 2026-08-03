# AGENTS.md

## Cursor Cloud specific instructions

`rh-mcp` is a single Python package (no web UI, no long-running server): a
default-deny read gateway exposed as a library (`RobinhoodGateway`) and a CLI
(`rh-mcp`). Development is driven with [`uv`](https://docs.astral.sh/uv/); the
authoritative spec is `DESIGN.md` and the CI contract is
`.github/workflows/ci.yml`.

### Environment

- `uv` is installed at `~/.local/bin/uv` and is already on `PATH` for login
  shells (the installer added it to `~/.bashrc` / `~/.profile`). The startup
  update script runs `uv sync --frozen`, which creates/updates the project
  virtualenv at `.venv`. If `uv` is ever not found in a non-login shell, invoke
  it by full path (`~/.local/bin/uv`).
- The interpreter is CPython 3.12.3, which is one of the two versions CI pins
  (`3.12.3` and `3.13`). `3.12.3` is deliberate: two stdlib loopback/URL
  behaviours the security boundary depends on are patch-version dependent (see
  the comments in `src/rh_mcp/config.py`). Do not "upgrade" the pinned dev
  interpreter to a newer 3.12.x to make something pass.

### Lint / type-check / test / run

Standard commands (same as the CI `test` job in `.github/workflows/ci.yml`),
run from the repo root:

- Lint: `uv run ruff check .`
- Types: `uv run mypy src`
- Tests: `uv run pytest`
- Build the wheel (the CI `package` job): `uv build`

Run the CLI with `uv run rh-mcp <command>`. Subcommands: `login`, `logout`,
`auth-status`, `status`, `capabilities`, `read`, `admin discover`.

### Non-obvious runtime notes

- Every command except `--help` requires `RH_MCP_EXPECTED_MANIFEST_DIGEST` (a
  `sha256:<64 hex>` value the consumer independently pins). Without it the CLI
  exits `3` (configuration error) and writes nothing to stdout — this is
  expected, not a crash. The currently committed manifest digest is published
  in `README.md`.
- `capabilities` is the only command that needs neither network nor
  credentials: it reads the packaged manifest and reports allowed/denied tools
  and whether the active manifest matches the pinned digest. It is the quickest
  end-to-end smoke check.
- Commands `status`, `read`, `login`, `admin discover` reach the live Robinhood
  MCP server and/or a stored OAuth credential, so they need real auth and
  network access; they cannot be fully exercised offline. For local
  experimentation use development mode (`RH_MCP_MODE=development` with
  `RH_MCP_DEV_URL` pointing at a loopback target, or `RH_MCP_DEV_STDIO_COMMAND`)
  — see `src/rh_mcp/config.py` for the full set of `RH_MCP_*` variables.
- CLI output contract (`src/rh_mcp/cli.py`): structured JSON goes to stdout only
  on success; all diagnostics/errors go to stderr; a failure emits nothing to
  stdout and signals via exit code.
