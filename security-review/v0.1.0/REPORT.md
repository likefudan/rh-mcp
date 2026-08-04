# Independent Security Review Report

Reviewer: Cursor Cloud Agent (`bc-575f4ffe-b8cd-472b-a215-d25bf8a4ed27`), operating for repository owner Ke Li  
Reviewer type: AI-assisted  
Tool/model, if applicable: Cursor Cloud Agent (Composer); exploratory sub-agent used for read-only source mapping  
Review date: 2026-08-03  
Repository: `https://github.com/likefudan/rh-mcp`  
Release/tag: `v0.1.0`  
Commit: `a81464f699fc3c9dc314e674a1198c7fe2b9ab8f`  
Wheel SHA-256: `554feaa444ca7be3f396e101ab7bdfdf22a8f83b839394439f3e989ad0b92593`  
Source distribution SHA-256: `60c0e15038989bcab672b3d4db40275fb79e7fb6a552c7b2378b55d36596f4d3`  
Manifest version: `2026.08.03.1`  
Manifest digest: `sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b`  
Envelope version: `1.0`

## Independence statement

This is an **AI-assisted independent review**, not a human penetration test and not a third-party certification.

Operating constraints followed:

- Review target was the immutable `v0.1.0` pin from `INDEPENDENT_SECURITY_REVIEW.md`.
- Source was examined in an isolated git worktree checked out at
  `a81464f699fc3c9dc314e674a1198c7fe2b9ab8f` (`/tmp/rh-mcp-v0.1.0-review`), not a
  newer `main` tip.
- Release wheel, sdist, and `SHA256SUMS` were downloaded independently from the
  GitHub release and re-hashed locally.
- No production code was modified during this review. Deliverables are this
  report and reviewer-authored adversarial tests under `security-review/v0.1.0/`.
- No OAuth tokens, refresh tokens, DCR client data, passwords, account numbers,
  account payloads, or Keychain data were requested, displayed, stored, or
  pasted. All exercising was offline with synthetic transports/fixtures.

Independence limitation (disclosed): this review ran in the same Cursor Cloud
agent environment that previously performed development-environment setup for
the repository. That earlier session did not change production code for
`v0.1.0`. The review itself used a detached worktree at the pinned commit and
treats repository documentation/tests as claims, not proof. Label remains
`AI-assisted independent review`.

## Scope and exclusions

In scope: whether a consumer such as `ainvest` can safely use the exact
`v0.1.0` artifact with a write-capable Robinhood OAuth credential while relying
on the reviewed manifest to prevent every trading operation (order place /
cancel / exercise / order simulation).

Out of scope:

- Approval of any `ainvest` adapter, CLI, Telegram, Paper, or deployment code.
- Live authenticated calls against Robinhood.
- Invoking any live mutation or trading capability.
- Fixing the findings in this pass (implementation must fix separately; then
  re-review the new exact commit/artifacts).

## Evidence and commands executed

### Baseline identity

```text
git rev-parse v0.1.0^{commit}
# a81464f699fc3c9dc314e674a1198c7fe2b9ab8f

gh release download v0.1.0 --repo likefudan/rh-mcp
sha256sum rh_mcp-0.1.0-py3-none-any.whl rh_mcp-0.1.0.tar.gz
# matches SHA256SUMS and the runbook pin exactly
```

Annotated tag `v0.1.0` peels to the pinned commit. Release author:
`likefudan`. Release was published manually (no dedicated release workflow in
`.github/workflows/`; only `ci.yml`).

### Artifact rebuild

From the pinned source:

```text
uv build
```

| Artifact | Released SHA-256 | Rebuilt SHA-256 | Bytes |
|---|---|---|---|
| wheel | `554feaa…b92593` | `554feaa…b92593` | **exact match** |
| sdist | `60c0e15…96f4d3` | `da96b7e…f38d01` | **differ** |

Content diff of released vs rebuilt sdist: the released sdist uniquely contains
`rh_mcp-0.1.0/.claude/settings.local.json` (not in git at the release commit).
All other tracked file content hashes matched. The wheel does **not** contain
`.claude` and byte-matches the rebuild.

### Installed-wheel smoke (downloaded artifact, clean venv)

```text
uv venv /tmp/rh-mcp-wheel-smoke
VIRTUAL_ENV=/tmp/rh-mcp-wheel-smoke uv pip install rh_mcp-0.1.0-py3-none-any.whl
```

Observed from the installed package (not the source tree):

- package version `0.1.0`
- packaged manifest present
- manifest version `2026.08.03.1`
- recomputed digest
  `sha256:70f88615716b05b8f547bf21ba756643ba2ded140202395998d428f63d84c91b`
- counts **34 reads / 11 allowed mutations / 8 denied trading**
- `LICENSE` and `NOTICE` present in the distribution
- unconfigured `rh-mcp capabilities` → exit `3`, empty stdout
- `rh_mcp.transport.__all__` includes `open_provider_session` and
  `ProviderTransport`

### Build attestation

GitHub artifact attestations API returned 404 for the wheel digest. No
verifiable provenance attestation was found. Checksums prove artifact
identity; they do **not** by themselves prove which workflow and source
produced the bytes. Residual supply-chain risk recorded below.

### CI for the release commit

`gh run list --commit a81464f…` → run `30811609747` conclusion `success`:

- `test (3.12.3)` success
- `test (3.13)` success
- `package` success

### Repository quality gate (pinned source)

```text
uv sync --frozen
uv run --frozen ruff check .     # All checks passed
uv run --frozen mypy src         # Success: no issues in 13 source files
uv run --frozen pytest           # 1118 passed, 1 skipped
```

## Existing tests executed

Full suite at the pinned commit: **1118 passed, 1 skipped**.

Notable existing coverage that held under review:

- Synthetic denied capability never reaches transport (`tests/test_gateway.py`).
- Undeclared argument keys refused before transport.
- Dependency-boundary tests keep `mcp.*` / `httpx2.*` out of public type
  surfaces.
- Packaged-manifest disposition counts and the exact 11-mutation set.
- Credential `repr` redaction (with documented `dataclasses.asdict` caveat).

Gaps that mattered for this review are listed with the findings and in
reviewer-authored tests.

## Reviewer-authored adversarial tests

Path: `security-review/v0.1.0/test_adversarial_review.py`

```text
cd /tmp/rh-mcp-v0.1.0-review   # pinned worktree
PYTHONPATH=/tmp/rh-mcp-v0.1.0-review \
  uv run --frozen pytest /path/to/security-review/v0.1.0/test_adversarial_review.py -v
```

Result against `a81464f`: **27 passed, 4 failed**.

| Result | What it proves |
|---|---|
| PASS ×8 | Each packaged denied trading capability refuses with `capability_denied` and **zero** `call_tool` invocations |
| PASS | Exact 34/11/8 packaged surface; listing exposes `mutates` |
| PASS ×12 | Case / Unicode / whitespace / look-alike / provider-name / non-string capability variants never reach transport |
| PASS | Unknown and denied share identical sanitized messages; undeclared keys blocked; digest mismatch blocks invoke |
| **FAIL ×3** | Public `rh_mcp.transport` still exports `open_provider_session` / `ProviderTransport` with arbitrary `provider_tool_name` (**Finding P0**) |
| **FAIL ×1** | After preflight, `invoke` sends the original mutable mapping; flipped undeclared keys (`side`, `quantity`) reached the spy transport (**Finding P1**) |

Raw log: retained in the review environment as
`/opt/cursor/artifacts/adversarial_review_pytest.txt`.

## Findings (P0 through P3)

### P0 — Public transport API bypasses the reviewed manifest

1. **Title / severity:** Public `open_provider_session` + `ProviderTransport.call_tool` is a manifest-free trading path — **P0**
2. **Location:** `src/rh_mcp/transport.py` lines 199–214, 1160–1204, 1478–1483, 1615–1625; also `src/rh_mcp/auth.py` (`StoredTokenProvider`), `src/rh_mcp/credentials.py` (`open_credential_store`)
3. **Violated claim:** DESIGN.md §1 / README / CHANGELOG: neither public surface exposes arbitrary tool names or a generic `call_tool`. The security model states the committed manifest is the only restraint on a write-capable `internal` token.
4. **Reproduction:** From the installed wheel:
   ```python
   from rh_mcp.transport import open_provider_session, ProviderTransport
   # ProviderTransport.call_tool(provider_tool_name, arguments, ...)
   # _PrivateSession.call_tool sends name=provider_tool_name with no manifest lookup
   ```
   Combine with the public credential helpers to attach the stored bearer token.
   The repository’s own `TestNoEscapeHatch` only inspects `RobinhoodGateway` and
   never asserts that `rh_mcp.transport` is non-public.
5. **Observed / expected:** Observed — arbitrary provider tool names including
   `place_equity_order` are accepted by the public call path with no disposition
   check. Expected — no public API accepts an arbitrary provider tool name;
   only `RobinhoodGateway.invoke(capability, …)` after preflight.
6. **Impact:** A broker-process caller (or a buggy `ainvest` adapter that imports
   transport helpers) can place/cancel/exercise/simulate orders while still
   “using rh-mcp.” The pin of the manifest digest does not constrain this path.
7. **Remediation:** Remove `open_provider_session` and `ProviderTransport` from
   the public export surface (make them module-private / delete from `__all__`);
   stop exporting credential+token helpers that assemble a write-capable raw
   session for general callers; add a regression test that fails if
   `rh_mcp.transport.__all__` or `dir(rh_mcp.transport)` re-exposes a generic
   `call_tool`. Keep injection of a transport available only to tests via a
   clearly non-public seam if needed.
8. **Blocks approval:** **Yes**

### P1 — Validated argument snapshot is discarded; live mapping is sent

1. **Title / severity:** Preflight validates a copy; `invoke` forwards the original mapping — **P1**
2. **Location:** `src/rh_mcp/manifest.py` 1262–1273; `src/rh_mcp/gateway.py` 222–229
3. **Violated claim:** DESIGN / `preflight_read` docstring: capability resolution
   and argument validation are one inseparable preflight event; only then may
   the transport be called.
4. **Reproduction:** Reviewer test
   `TestFindingP1ArgumentToctou.test_invoke_must_send_the_validated_argument_snapshot`
   flips a custom `MutableMapping` after `preflight_read` returns. Observed
   transport arguments: `{'synthetic_symbol': 'AAPL', 'side': 'buy', 'quantity': '100'}`.
5. **Observed / expected:** Observed — undeclared keys reach `call_tool`.
   Expected — transport receives only the immutable validated snapshot.
6. **Impact on rh-mcp / ainvest:** Does not by itself change the provider tool
   name (so it is not independently a trading-tool rename). It *does* defeat
   pinned input-schema / undeclared-key enforcement for allowed capabilities,
   including the 11 write-capable non-trading mutations. A concurrent or
   hostile mapping in-process can smuggle extra fields after validation.
7. **Remediation:** Have `preflight_read` return `(entry, safe_arguments)` (or
   equivalent) and make `invoke` send only that snapshot; freeze/deep-copy
   before return. Add a regression test with a flipping `MutableMapping`.
8. **Blocks approval:** **Yes**

### P2 — Released sdist packages a non-git developer file (`.claude/`)

1. **Title / severity:** Sdist contains `.claude/settings.local.json` absent from the git tree — **P2**
2. **Location:** released `rh_mcp-0.1.0.tar.gz` → `rh_mcp-0.1.0/.claude/settings.local.json`
3. **Violated claim:** Supply-chain expectation that the source distribution
   reflects the reviewed commit without accidental developer files (§11).
4. **Reproduction:** `tar -tzf rh_mcp-0.1.0.tar.gz | grep claude`; content hash
   differs from a clean rebuild of the same commit.
5. **Observed / expected:** Observed local Claude permission settings (including
   a developer filesystem path) in the released sdist. Expected — sdist ≡ git
   tree used for the tag (wheel was clean).
6. **Impact:** No credential secret found in the file; still a packaging
   hygiene / reproducibility failure and a signal that the release was built
   from a dirty local tree rather than a clean checkout.
7. **Remediation:** Rebuild and re-publish sdist from a clean tree; add
   `.claude/` to ignore/exclude packaging config; add a CI check that the built
   sdist contains no unexpected paths.
8. **Blocks approval:** No (owner may accept with follow-up), but must be
   visible; wheel remains the preferred install artifact.

### P2 — Material public-API / docs mismatches

1. **Title / severity:** DESIGN still describes `RobinhoodGateway(config, store)` + `read()` and manifest format `1.1` — **P2**
2. **Location:** `DESIGN.md` ~L26–35, ~L95–113, ~L371–387; implementation
   `open_gateway` + `invoke`; manifest format `1.2`
3. **Violated claim:** Public documentation must not claim constructors/methods
   the artifact does not implement (§10).
4. **Reproduction:** Compare DESIGN snippet to `gateway.py` / installed wheel.
5. **Observed / expected:** Docs disagree with the artifact. README also still
   says “not yet released” while CHANGELOG/`v0.1.0` declare the first release.
6. **Impact:** Consumer integration traps (wrong constructor/method), not a
   direct trading bypass when the correct API is used.
7. **Remediation:** Align DESIGN/README with `open_gateway` / `invoke` / format
   `1.2` / release status.
8. **Blocks approval:** No if explicitly owner-accepted with follow-up.

### P2 — No verifiable build provenance; manual release publication

1. **Title / severity:** No attestation; assets appear manually attached — **P2**
2. **Location:** GitHub release `v0.1.0`; workflows only `ci.yml`
3. **Claim:** §11 asks whether assets are built/published by a trusted workflow
   from the approved commit with verifiable provenance.
4. **Observed:** Wheel bytes are reproducible from the pinned source (good).
   Attestation API 404. Sdist dirty (above).
5. **Impact:** Checksum pinning works; substitution risk is higher without
   provenance. Distinct from “source is secure.”
6. **Remediation:** Publish via CI OIDC attestation (`gh attestation`) from the
   tagged commit; prefer wheel install.
7. **Blocks approval:** No if owner accepts residual risk.

### P3 — Gateway “no escape hatch” tests do not cover `rh_mcp.transport`

1. **Title / severity:** Test blind spot enabling P0 to ship green — **P3**
2. **Location:** `tests/test_gateway.py` `TestNoEscapeHatch` ~L236–264
3. **Impact:** Maintainability / false confidence.
4. **Remediation:** Extend escape-hatch tests to the transport module `__all__`.
5. **Blocks approval:** No (covered by P0 remediation).

### Allowed-mutation schema review (no separate finding)

The exact 11 owner-approved mutations were reviewed for hidden order / cancel /
exercise / money-movement / credential-management effects in their pinned
input schemas and rationales. They are watchlist and saved-scan management
only (`list_id`, symbols, scan filters/sort, etc.). No trading-tool schema
overlap was found that would reclassify them as P0. They remain owner-accepted
non-trading writes and are correctly flagged `mutates=true`.

## Known limitations and residual risks

- OAuth credential is write-capable (`internal` scope). Manifest enforcement on
  the **gateway** path is necessary but, given P0, not currently sufficient for
  every public import path in the package.
- Production credential adapter is macOS Keychain-only; other platforms need an
  injected secret-manager store (`credentials.py`).
- Provider `guide` / description / schema prose is returned inside result
  envelopes and is provider-controlled prompt-injection material. The gateway
  does not execute it; consumers must discard it during normalization.
- `dataclasses.asdict` / `astuple` on credential objects can expose secrets
  (documented and tested).
- No live Robinhood authentication was performed in this review.
- Manifest format 1.2 cannot distinguish omitted vs empty description/annotations
  (already disclosed in the release notes).
- This approval gate is bound to the exact commit/artifacts above; a later
  commit is never covered by this report.

## Ainvest consumer requirements

Until P0/P1 are fixed and re-reviewed, **do not** treat `v0.1.0` as an approved
dependency for an `ainvest` broker adapter that holds a real trading-capable
token.

After a future approved release, `ainvest` must still:

1. Pin package version, wheel SHA-256, source commit, full-manifest digest, and
   envelope version `1.0` independently at deployment/startup.
2. Use only `GatewayConfig` + `open_gateway` / `RobinhoodGateway.invoke` —
   never `rh_mcp.transport.open_provider_session` / raw `call_tool`.
3. Keep `invoke` inside a dedicated broker adapter; expose only normalized
   ainvest operations downstream.
4. Discard provider `guide`, tool descriptions, and schema descriptions; never
   place them in model, Telegram, CLI, or log context.
5. Resolve MCP SDK compatibility: `rh-mcp` requires `mcp>=2,<3`. An environment
   that also pins `mcp<2` cannot install both; isolate or remove the obsolete
   pin.
6. Gate writes using the reviewed `mutates` flag rather than inferring from names.
7. Complete a separate independent review of the ainvest adapter itself before
   production use.

## Final disposition

Disposition: **CHANGES_REQUIRED**

Unresolvable for approval on this exact artifact:

- **P0** public manifest-bypass trading path via `rh_mcp.transport`
- **P1** fail-open argument TOCTOU between preflight and transport

P2 items require owner fix or explicit acceptance with follow-up before a
later approval. After fixes, publish a new SemVer release from the approved
commit and repeat the affected checks against the new exact commit and
artifacts per `INDEPENDENT_SECURITY_REVIEW.md` §§2, 14.
