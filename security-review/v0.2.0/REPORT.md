# Independent Security Review Report

Reviewer: Cursor Cloud Agent (`bc-575f4ffe-b8cd-472b-a215-d25bf8a4ed27`), operating for repository owner Ke Li  
Reviewer type: AI-assisted  
Tool/model, if applicable: Cursor Cloud Agent (Composer)  
Review date: 2026-08-04  
Repository: `https://github.com/likefudan/rh-mcp`  
Release/tag: `v0.2.0`  
Commit: `46128a623c87f954c18d037870e4ac36b9e61e13`  
Wheel SHA-256: `45bdfa7ef191a5dca834ddf52249fd92cfce0cf33456ec26839bdc8024e657b9`  
Source distribution SHA-256: `da1d2231fd7be4129e035879eec4965727b968496c382bdaaa6f663bec11842c`  
Manifest version: `2026.08.03.1`  
Manifest digest: `sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b`  
Envelope version: `1.0`

## Independence statement

This is an **AI-assisted independent review**, not a human penetration test and
not a third-party certification.

- The immutable target is release `v0.2.0` / commit
  `46128a623c87f954c18d037870e4ac36b9e61e13`.
- Source was examined in an isolated git worktree at that commit
  (`/tmp/rh-mcp-v0.2.0-review`).
- Wheel, sdist, and `SHA256SUMS` were downloaded from the GitHub release and
  re-hashed locally. Build provenance was verified with
  `gh attestation verify`.
- No production code was modified. Deliverables are this report and
  reviewer-authored tests under `security-review/v0.2.0/`.
- No OAuth tokens, refresh tokens, DCR client data, passwords, account
  numbers, account payloads, or Keychain data were requested, displayed,
  stored, or pasted. All exercising was offline.

Independence limitation (disclosed): this review ran in the same Cursor Cloud
agent environment that previously authored the `v0.1.0` review and performed
environment setup. Those prior sessions did not author the `v0.2.0` production
fixes. This pass used a detached worktree at the pinned `v0.2.0` commit and
treats repository documentation/tests as claims, not proof.

Prior review binding: the `v0.1.0` report’s disposition does **not** cover
this artifact. This report is a fresh review of the new exact commit and
artifacts.

## Scope and exclusions

In scope: whether a consumer such as `ainvest` can safely use the exact
`v0.2.0` artifact with a write-capable Robinhood OAuth credential while relying
on the reviewed manifest to prevent every trading operation when integrating
against the **published** library/CLI surfaces (`GatewayConfig`,
`open_gateway` / `RobinhoodGateway.invoke`, `rh-mcp` CLI).

Out of scope:

- Approval of any `ainvest` adapter, CLI, Telegram, Paper, or deployment code.
- Live authenticated calls against Robinhood.
- Invoking any live mutation or trading capability.
- Treating in-process callers that deliberately import underscore-prefixed
  internals as within the published security boundary (DESIGN.md §3; see
  residual risks).

## Evidence and commands executed

### Baseline identity

```text
git rev-parse v0.2.0^{commit}
# 46128a623c87f954c18d037870e4ac36b9e61e13

gh release download v0.2.0 --repo likefudan/rh-mcp
sha256sum rh_mcp-0.2.0-py3-none-any.whl rh_mcp-0.2.0.tar.gz
# matches SHA256SUMS and the values in this report header
```

Annotated tag `v0.2.0` peels to the pinned commit.

### Artifact rebuild

```text
uv build
```

| Artifact | Released SHA-256 | Rebuilt SHA-256 | Bytes |
|---|---|---|---|
| wheel | `45bdfa7…657b9` | `45bdfa7…657b9` | **exact match** |
| sdist | `da1d223…1842c` | `da1d223…1842c` | **exact match** |

No `.claude/` (or other non-git developer path) in the released sdist.
`scripts/check_sdist.py` is enforced in `release.yml`.

### Build attestation

```text
gh attestation verify rh_mcp-0.2.0-py3-none-any.whl --repo likefudan/rh-mcp --format json
# exit 0
```

Verified Sigstore provenance binds the wheel to:

- workflow `.github/workflows/release.yml` at `refs/tags/v0.2.0`
- source commit `46128a623c87f954c18d037870e4ac36b9e61e13`
- GitHub Actions run `30864547250`

This is attestation evidence linking bytes → source/workflow. It is not
evidence that the source is secure; that is the rest of this report.

### Installed-wheel smoke (downloaded artifact)

```text
uv venv /tmp/rh-mcp-wheel-smoke-v020
VIRTUAL_ENV=... uv pip install rh_mcp-0.2.0-py3-none-any.whl
```

Observed from the installed package:

- version `0.2.0`
- manifest `2026.08.03.1` /
  `sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b`
  (byte-identical permissions surface to `v0.1.0`)
- counts **34 reads / 11 allowed mutations / 8 denied trading**
- `from rh_mcp.transport import *` binds only
  `PRODUCTION_EGRESS_HOSTS`, `HttpJsonResponse`, `PayloadSource`, `ToolPayload`
- legacy name `open_provider_session` is absent (`hasattr` false)
- unconfigured `rh-mcp capabilities` → exit `3`, empty stdout

### CI for the release commit

- CI run `30864511863`: `test (3.12.3)`, `test (3.13)`, `package` — success
- Release run `30864547250`: `build` — success (includes sdist allowlist check,
  tag/version match, attest-build-provenance, checksums)

### Repository quality gate (pinned source)

```text
uv sync --frozen
uv run --frozen ruff check .     # All checks passed
uv run --frozen mypy src         # Success: no issues in 13 source files
uv run --frozen pytest           # 1164 passed, 1 skipped
```

Including `tests/test_public_surface.py`: **43 passed**.

## Existing tests executed

Full suite at the pinned commit: **1164 passed, 1 skipped**.

Material additions since `v0.1.0`:

- Package-wide published-surface sweep (`tests/test_public_surface.py`) that
  would have failed on the `v0.1.0` `open_provider_session` export.
- Gateway wiring that sends `preflight.arguments` (frozen snapshot), with
  regression coverage.
- Release workflow + sdist path allowlist.

## Reviewer-authored adversarial tests

### Prior suite (must stay green)

```text
PYTHONPATH=. uv run --frozen pytest security-review/v0.1.0/test_adversarial_review.py -v
# 31 passed
```

Note: the committed `v0.1.0` adversarial file in this tree includes a small
post-fix edit (dropping the now-unimportable `open_provider_session` import
and documenting why). The four previously failing secure-property assertions
are green against `v0.2.0`. One of those assertions keys off the
`call_tool` parameter name (`provider_tool_name` → `reviewed_tool_name`);
that rename alone is not a security control — see residual risks. The
decisive `v0.2.0` properties are instead covered by the published-surface
sweep and the frozen-snapshot test below.

### New suite for this release

Path: `security-review/v0.2.0/test_adversarial_review_v020.py`

```text
PYTHONPATH=. uv run --frozen pytest security-review/v0.2.0/test_adversarial_review_v020.py -v
```

Expected: all pass. Covers star-import closure, absence of legacy session
opener name, immutable validated argument snapshot through `invoke`, and
records the residual underscore opener as a documented non-published path.

## Findings (P0 through P3)

### Prior P0 — Public transport bypass — **RESOLVED** on the published surface

1. **Title / severity:** Was P0 on `v0.1.0`; **resolved** for `v0.2.0` published API
2. **Evidence of fix:**
   - `rh_mcp.transport.__all__` no longer includes `open_provider_session` /
     `ProviderTransport` / `AccessTokenProvider` / `open_json_client`
   - `open_provider_session` renamed to `_open_provider_session` (legacy name
     absent from the installed module)
   - `StoredTokenProvider` / `open_credential_store` removed from their
     modules’ `__all__` (no longer star-imported / advertised)
   - `tests/test_public_surface.py` package-wide sweep passes
   - `v0.1.0` adversarial P0 expectations now pass
3. **Remaining nuance:** underscore-prefixed internals remain importable by
   deliberate name (see P2 residual below and DESIGN §3). That is not a
   reopening of the *published-contract* defect that blocked `v0.1.0`.

### Prior P1 — Argument TOCTOU — **RESOLVED**

1. **Title / severity:** Was P1 on `v0.1.0`; **resolved** on `v0.2.0`
2. **Location:** `src/rh_mcp/manifest.py` (`PreflightResult`,
   `preflight_read` returns frozen snapshot);
   `src/rh_mcp/gateway.py` `invoke` sends `preflight.arguments`
3. **Evidence:** Reviewer TOCTOU test now passes; transport receives a
   `mappingproxy` equal to the validated args; mutation after preflight cannot
   add `side` / `quantity`.

### P2 — Underscore-prefixed session opener remains importable in-process

1. **Title / severity:** Residual private import path — **P2**
2. **Location:** `src/rh_mcp/transport.py` `_open_provider_session`,
   `_PrivateSession.call_tool` (still trusts `reviewed_tool_name` with no
   manifest check by design of that private layer)
3. **Violated claim:** None against the published contract as restated in
   DESIGN / `test_public_surface.py`. Conflicts with a stronger reading of
   “no path exists anywhere in the package,” which DESIGN §3 explicitly
   rejects as the threat model.
4. **Reproduction:**
   ```python
   from rh_mcp.transport import _open_provider_session
   from rh_mcp.auth import StoredTokenProvider
   from rh_mcp.credentials import open_credential_store
   ```
5. **Observed / expected under published-contract model:** Observed —
   deliberate private imports still assemble a session. Expected for approval
   — published `import *` / documented constructors cannot. The stronger
   “no underscore import works” bar is out of scope per DESIGN §3.
6. **Impact:** A buggy consumer that ignores the published API and imports
   private names can still bypass the manifest. A consumer that only uses
   `open_gateway` / `invoke` cannot.
7. **Remediation (optional hardening):** further reduce assemblability (e.g.
   keep session opener module-private via split modules without re-export,
   or have `_PrivateSession.call_tool` accept only a capability token minted
   by preflight). Not required for approval under the stated model.
8. **Blocks approval:** **No**, if owner continues to accept DESIGN §3; recorded
   as an explicit residual risk and ainvest consumer requirement.

### P3 — `v0.1.0` adversarial P0 test partly keyed on parameter naming

1. **Title / severity:** Test-quality observation — **P3**
2. **Location:** `security-review/v0.1.0/test_adversarial_review.py`
   `test_call_tool_protocol_accepts_arbitrary_provider_name_without_manifest`
3. **Impact:** Renaming `provider_tool_name` → `reviewed_tool_name` greens that
   assertion without adding a manifest check. Mitigated by
   `tests/test_public_surface.py` and the new `v0.2.0` adversarial tests.
4. **Blocks approval:** No.

No new P0 or P1 findings were identified against the published surfaces of
this exact artifact.

### Allowed-mutation schema review

The packaged manifest is byte-identical in digest to `v0.1.0`. The exact 11
owner-approved mutations remain watchlist / saved-scan management with
`mutates=true`. No new trading-shaped schema was introduced in this release
(code-only change; permissions unchanged).

## Known limitations and residual risks

- OAuth credential remains write-capable (`internal` scope). The reviewed
  manifest on the **gateway** path is the restraint.
- In-process callers can still import underscore-prefixed transport/auth
  helpers (P2 residual above). DESIGN §3 states this is not the security
  boundary; the published contract is.
- Production credential adapter remains macOS Keychain-only for the bundled
  production store; other platforms need an injected secret-manager store.
- Provider `guide` / description / schema prose inside result envelopes remains
  provider-controlled prompt-injection material; consumers must discard it.
- `dataclasses.asdict` / `astuple` on credential objects can still expose
  secrets (documented).
- No live Robinhood authentication was performed in this review.
- This approval is bound to the exact commit and artifact digests in the
  header. A later tag/commit is not covered.

## Ainvest consumer requirements

`ainvest` may pin this exact release as a dependency for an independently
reviewed broker adapter, provided it:

1. Pins package version `0.2.0`, wheel SHA-256
   `45bdfa7ef191a5dca834ddf52249fd92cfce0cf33456ec26839bdc8024e657b9`,
   source commit `46128a623c87f954c18d037870e4ac36b9e61e13`, full-manifest
   digest
   `sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b`,
   and envelope version `1.0`.
2. Optionally verifies provenance:
   `gh attestation verify rh_mcp-0.2.0-py3-none-any.whl --repo likefudan/rh-mcp`.
3. Uses only `GatewayConfig` + `open_gateway` / `RobinhoodGateway.invoke` (and
   the CLI). Must not import `rh_mcp.transport._open_provider_session`,
   `_PrivateSession`, `StoredTokenProvider`, or treat any underscore name as
   supported API.
4. Keeps `invoke` inside a dedicated broker adapter; exposes only normalized
   ainvest operations downstream.
5. Discards provider `guide`, tool descriptions, and schema descriptions from
   model / Telegram / CLI / log context.
6. Gates writes using the reviewed `mutates` flag.
7. Resolves MCP SDK compatibility (`rh-mcp` requires `mcp>=2,<3`).
8. Completes a separate independent review of the ainvest adapter itself
   before production use.

## Final disposition

Disposition: **APPROVED_FOR_AINVEST_INTEGRATION**

This means only that the exact reviewed `v0.2.0` artifact is an acceptable
dependency for an independently reviewed `ainvest` adapter. It is not
authorization for live order execution, and it does not approve a future
artifact, changed tag, changed manifest digest, or changed provider surface.

Approval conditions satisfied:

- No unresolved P0 or P1 on the published surfaces
- P2 residual (underscore importability) explicitly accepted under DESIGN §3
  and listed as a consumer requirement / residual risk
- Exact 8 trading capabilities denied before transport on the gateway path
- Exact 11 owner-approved mutations identified; no automatic permission
  expansion (manifest digest unchanged from the reviewed `v0.1.0` surface)
- Manifest/schema/argument fail-closed behaviour confirmed under adversarial
  tests; P1 TOCTOU fixed
- Downloaded artifacts match recorded digests; wheel and sdist byte-reproducible
  from the tagged commit; provenance attestation verified
- Repository quality gate and reviewer-authored tests pass
- Verdict bound to the exact commit, artifacts, manifest, and envelope version
  in this header
