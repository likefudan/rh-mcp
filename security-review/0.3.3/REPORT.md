# Adversarial Security Review Report — rh-mcp 0.3.3 (source)

Reviewer: Claude Opus 5, operating as a fresh agent for repository owner Ke Li
Reviewer type: AI-assisted, **in-project** (see "Independence statement" — this
is *not* equivalent to the `v0.1.0` / `v0.2.0` external reviews)
Review date: 2026-08-25
Repository: `/Users/kel/codebase/rh-mcp` (`https://github.com/likefudan/rh-mcp`)
Branch/target: `main`
Commit: `ce8f839660040a2fed543525f01fb2f54e732aa4`
Declared package version: `0.3.3` — **no `v0.3.3` tag and no GitHub release exist**
Manifest version: `2026.08.22`
Full-manifest digest: `sha256:2ea0954b4a52d9469837bc2b167904ab871de893475e68b43dc2a8fb02e7f886`
Provider-surface digest: `sha256:3e3f1d3e3e63bef64a2270d9cd238e12c78b247e82c4e717fa3302b0e9e970f8`
Manifest format version: `1.2` · Canonicalization: `rh-canon-1` · Digest algorithm: `sha256`
Envelope version: `1.0`
Locally built (not released, not attested):
wheel `rh_mcp-0.3.3-py3-none-any.whl` `sha256:1965d743bcbae01a463470621103000b8c240487b59f18e578515249fd731034`;
sdist `rh_mcp-0.3.3.tar.gz` `sha256:4728b99a09122f3f0f3a28cb5ff6d7f7ae103d2c2dd7b56d171c3099618813f7`

Baseline reviewed against: `v0.2.0` / commit `46128a62` / manifest `2026.08.03.1`
/ digest `sha256:70f88615…4c91b` / envelope `1.0`, disposition
`APPROVED_FOR_AINVEST_INTEGRATION` (2026-08-04, `security-review/v0.2.0/`).

**Disposition: `INTERNAL_ADVERSARIAL_REVIEW_PASS_WITH_CONDITIONS`.**
Deliberately *not* labelled `APPROVED_FOR_AINVEST_INTEGRATION`. See
"Final disposition".

---

## Independence statement — read this before the findings

I am a fresh agent with no prior context on this repository. I did not write
any of the code, the manifest, the tests, or the prior reviews, and I did not
participate in any earlier round. In that narrow sense my reading is
independent.

**I am not an outside party.** The `v0.1.0` and `v0.2.0` reviewers were
external to the project and operated on immutable published artifacts
downloaded from GitHub. I am running inside the owner's working checkout, at
the owner's request, on the owner's machine, with the owner's live Robinhood
credential present in the environment. DESIGN §12.1's own argument for why the
external review mattered — *"a reviewer who shares an orchestrator with the
implementer inherits the implementer's idea of where to look"* — applies to me
with less force than to the four internal rounds it describes, but it does not
apply with zero force. My verdict must not be recorded as a third external
verdict, and `security-review/v0.3.3/` should be labelled as an internal
adversarial pass if these artifacts are committed at all.

The only external verdict this project holds is bound to `v0.2.0`. The current
artifact is **one new tool and two widened allowed writes** past it. See P2-4.

### What I did to the environment

No tracked file was modified; `git status --short` is empty at the end of this
review. All mutation work was done in a disposable copy of `git archive HEAD`
under the scratchpad. No commit, no push, no tag.

**Live provider contact — disclosed, and it is not nothing.** A valid,
unexpired, trading-capable credential (`granted_scope: internal`) was present
in the environment. Four `rh-mcp read <denied-capability>` invocations and one
`rh-mcp status` therefore opened a **real authenticated session against
`https://agent.robinhood.com/mcp/trading` and performed live `tools/list`
discovery**. No provider tool was ever invoked — discovery is the only call
that reached the wire, and all four reads refused at preflight with
`capability_denied`. I invoked **no** allowed capability (that would read the
owner's account data, which I was not asked to do) and **no** mutation. Both
prior reviewers explicitly performed no live call; I did, and it produced the
single strongest piece of evidence in this report (§"Live evidence").

---

## Scope and exclusions

**In scope:** whether the manifest at this exact commit, and the enforcement
code that reads it, still prevent every trading operation for a consumer using
only the published surfaces (`GatewayConfig`, `open_gateway` /
`RobinhoodGateway.invoke`, the `rh-mcp` CLI), given a trading-capable OAuth
credential.

**Out of scope:** any `ainvest` adapter; the release/tag/attestation pipeline as
a security control (no `v0.3.3` release exists to verify); invoking any allowed
capability against a live account; anything reachable only by importing
underscore-prefixed names (DESIGN §3, and P2-1 below).

---

## Method

Every claim below that says "guarded" or "unguarded" was established by
**mutation**, not by reading. Three mutation harnesses were used:

1. **`scripts/mutate.py`** (the project's own, 88 mutations) — run at this
   commit: **88/88 caught**.
2. **Nine independent enforcement-path mutations** I wrote, chosen precisely
   because they are *not* in `scripts/mutate.py` (default-deny, the two pinned
   digest rechecks, the readiness gate, the assessment/manifest binding, the
   caller-name-to-provider path, the loader's declared-digest check): **9/9
   caught**, each by a named test. Harness: `srcmut.py`.
3. **A simulated manifest refresh** — the decisive one. Mutate the manifest,
   recompute *all four* digest families (per-entry schema, per-entry metadata,
   `provider_surface_digest`, `full_manifest_digest`) with an independent
   re-implementation of `rh-canon-1`, then update every pin a real refresh PR
   updates (`README.md`, `CHANGELOG.md`, `DESIGN.md`, `tests/test_manifest.py`).
   This models DESIGN §12.4's stated residual exactly. A mutation that survives
   *this* is a widening no test holds.

The reseal implementation reproduces the shipped `full_manifest_digest` and all
54 pairs of per-entry digests **bit-for-bit from the specification alone**,
without importing `rh_mcp`. That is what makes harness 3 trustworthy: a
surviving mutation is a real gap, not a resealing bug. The first run of harness
3 was invalid (I had missed `provider_surface_digest`); every mutation "caught"
identically, which was the tell. That is recorded because the corrected run is
what produced the findings.

---

## Verification of the stated delta

Each item was re-derived, not accepted.

### `manifest.py` is docstring-only — **confirmed, provably**

Parsed both revisions with `ast`, stripped every module/class/function
docstring, and compared `ast.dump`. Identical (`4ca843f71a72731c…` both sides).
The change is 2 lines inside `load_active_manifest`'s docstring (53→54 tools,
45→46 allowed, plus a clause about refreshes).

### Every other source file is byte-identical to `v0.2.0` — **confirmed**

SHA-256 of all 13 modules under `src/rh_mcp/` against `v0.2.0`: 12 identical,
`manifest.py` differs by the docstring above. Every `__all__` is identical.

**This is the single most important structural fact in the review.** The entire
enforcement path — `gateway.py`, `transport.py`, `schema.py`, `validation.py`,
`canonical.py`, `auth.py`, `credentials.py`, `config.py`, `cli.py`,
`models.py`, `errors.py` — is the *same bytes* an external reviewer approved on
2026-08-04. §12.4's "any change to code on the enforcement path" trigger has
not fired. What is under review is the manifest data and nothing else.

### Permission delta — **confirmed exactly as stated**

| | `v0.2.0` (`2026.08.03.1`) | `main` (`2026.08.22`) |
|---|---|---|
| allowed / read (`mutates: false`) | 34 | **35** |
| allowed / mutating (`mutates: true`) | 11 | 11 |
| denied | 8 | 8 |
| total | 53 | 54 |

- Appeared: `get_limited_margin_upgrade_info` (`allowed`, `mutates: false`). Only.
- Disappeared: none.
- No pre-existing entry's `disposition`, `mutates`, `capability` or
  `provider_tool_name` moved. Verified field-by-field across all 53 common entries.
- `manifest_format_version` (`1.2`), `canonicalization_version` (`rh-canon-1`)
  and `digest_algorithm` (`sha256`) are unchanged — §12.4's
  format/canonicalization/digest-derivation trigger has not fired either.

### The denied set — **still exactly the trading surface**

`{place_equity_order, place_option_order, cancel_equity_order,
cancel_option_order, cancel_option_exercise, exercise_option,
review_equity_order, review_option_order}` — identical to `v0.2.0`, asserted as
a **set** in both directions, all eight `mutates: true`. DESIGN §2.1's
normative claim is **true** of this artifact.

Two of the eight (`place_option_order`, `review_option_order`) gained a
`direction` input property since `v0.2.0`. They are denied; it changes nothing
reachable, and it is disclosed in `CHANGELOG` `[0.3.0]` and DESIGN §12.4.

### Digests — **independently re-derived, all match**

Re-implementing `rh-canon-1` and the three digest constructions from the
specification (DESIGN §6 and `canonical.py`'s module docstring) *without
importing the package*:

- `full_manifest_digest` → `sha256:2ea0954b…f886` — **matches the declared value**
- `provider_surface_digest` → `sha256:3e3f1d3e…970f8` — **matches**
- all 54 `schema_digest` and all 54 `metadata_digest` — **0 mismatches**
- entries in the file are already in canonical order (sorted by
  `provider_tool_name`), so what a human reads is what gets hashed

The digest a consumer would pin is the one the artifact ships: the manifest
inside the locally built wheel is **byte-identical** to
`src/rh_mcp/manifests/read-manifest.json`, and `rh-mcp capabilities` reports
`manifest_digest == expected_manifest_digest`, `digest_matches: true`. README,
CHANGELOG `[0.3.3]`, DESIGN §12.5's automation block and
`tests/test_manifest.py::SHIPPED_DIGEST` all carry the same string.

### Live evidence (discovery only)

```
$ RH_MCP_EXPECTED_MANIFEST_DIGEST=sha256:2ea0954b… rh-mcp status
{ "ready": true, "manifest_version": "2026.08.22",
  "manifest_digest": "sha256:2ea0954b…f886",
  "expected_manifest_digest": "sha256:2ea0954b…f886",
  "findings": [] }
```

Against the **live** Robinhood MCP server on 2026-08-25, the shipped manifest's
provider-surface digest matches the provider's actual surface exactly: zero
drift findings. The manifest is current, not stale. And:

```
$ rh-mcp read place_equity_order   --input '{"symbol":"AAPL"}'
$ rh-mcp read review_equity_order  --input '{"symbol":"AAPL"}'
$ rh-mcp read exercise_option      --input '{"symbol":"AAPL"}'
$ rh-mcp read cancel_option_order  --input '{"symbol":"AAPL"}'
rh-mcp: capability_denied: capability is not a reviewed read capability of the active manifest
```

Four trading capabilities refused over a **real authenticated session with a
real trading-capable token**. Neither prior review had this.

---

## Findings

### P0 / P1 — none

No blocking finding. The `v0.1.0` P0 (public transport bypass) and P1 (argument
TOCTOU) remain resolved; both were re-verified by mutation at this commit rather
than inherited, and the code carrying those fixes is byte-identical to the
artifact that was externally approved.

---

### P2-1 — Underscore-prefixed internals remain importable (carried-forward residual)

1. **Severity:** P2 — unchanged from `v0.2.0`, accepted there.
2. **Location:** `src/rh_mcp/transport.py` `_open_provider_session`,
   `_PrivateSession.call_tool`; `rh_mcp.auth.StoredTokenProvider`;
   `rh_mcp.credentials.open_credential_store`.
3. **Status at this commit — confirmed still exactly the same shape, and
   nothing newly exported.** Every module's `__all__` is byte-identical to
   `v0.2.0`, and `transport.py`/`auth.py`/`credentials.py` are byte-identical
   files. Star-import closure verified live:
   `from rh_mcp.transport import *` binds exactly
   `{PRODUCTION_EGRESS_HOSTS, HttpJsonResponse, PayloadSource, ToolPayload}`;
   `from rh_mcp import *` binds no callable (only already-imported submodule
   objects, which is CPython behaviour, not an export — `rh_mcp` has no
   `__all__` and defines no name); `open_provider_session` absent,
   `_open_provider_session` present.
4. **Impact:** a consumer that deliberately imports private names can assemble a
   manifest-free session. A consumer using only `open_gateway` / `invoke` / the
   CLI cannot.
5. **Blocks approval:** **No** — DESIGN §3 states in-process separation is not
   the boundary, and the `v0.2.0` reviewer accepted it on that basis. It stays
   an ainvest consumer requirement.

---

### P2-2 — A widened allowed write went undetected, and the shipped rationale is now false

**This is the headline finding.** It is DESIGN §12.4's stated residual, not as a
theoretical concession but as something that has already happened a second time
and was *not* caught.

1. **Severity:** P2.
2. **Location:** `src/rh_mcp/manifests/read-manifest.json`, entry
   `update_scan_config`; `CHANGELOG.md` `[0.3.2]`; DESIGN §2.1.
3. **What changed.** The `2026.08.21` refresh (commit `3f013eb`, released as
   `0.3.2`) widened **two** of the eleven allowed mutations, not one:

   | capability | `v0.2.0` input properties | `main` input properties | `required` |
   |---|---|---|---|
   | `create_scan` | `preset, filters, title` | `scan_id, preset, filters, title, columns` | ∅ → ∅ |
   | `update_scan_config` | `scan_id, sorting_column, sorting_direction` | `scan_id, sorting_column, sorting_direction, columns` | `{scan_id, sorting_column, sorting_direction}` → **`{scan_id}`** |

   `update_scan_config`'s new `columns` array has **REPLACE semantics over the
   scan's entire extra-column set**, accepts expression-backed computed columns,
   and creates a new configuration version. Two previously mandatory arguments
   became optional.

4. **The violated claim, quoted.** `CHANGELOG.md` `[0.3.2]` says, of the 38
   entries whose digests moved in that refresh:

   > **One of those 38 is not like the others, and the flat list above cannot
   > show it.** `create_scan` is an *allowed write* (`mutates: true`), and this
   > refresh widened its input surface … **Every other moved entry is a
   > description or a read schema.**

   `update_scan_config` is in that list of 38, is an allowed write
   (`mutates: true`), and its input surface widened in the same refresh. The
   sentence is **false**. DESIGN §2.1 likewise narrates only `create_scan`'s
   expansion and never mentions this one.

5. **The sharper half — the shipped manifest now carries a false reviewer
   statement.** `update_scan_config`'s `rationale` has been carried forward
   verbatim through every refresh since the first commit:

   > *"Changes a saved scan's sort column and direction. **Overwrites those two
   > fields only.**"*

   That is no longer true of the schema shipping beside it. DESIGN §6 says the
   rationale *is* the review ("a disposition without a stated reason is not a
   review"), and §12.4's refresh contract carries `rationale` forward verbatim
   *by design*. This is precisely the failure mode that contract concedes, and
   it produced a manifest entry whose stated blast radius is materially
   narrower than its actual one. (`create_scan`'s rationale was updated on
   `2026.08.12` for `scan_id` but *also* never updated for `columns` — it too
   omits the column write, though there the decision was at least made
   explicitly in the changelog.)

6. **Reproduction / demonstration.** Under a full simulated refresh (manifest
   resealed, all four digest families recomputed, every pin updated), these
   mutations **survive the entire 1210-test suite green**:

   | mutation | result |
   |---|---|
   | `update_scan_config` gains a new **optional** write property | **SURVIVED** — 1210 passed |
   | `update_scan_config` gains a new **required** write property | **SURVIVED** — 1210 passed |
   | `update_scan_filters` gains a new write property | **SURVIVED** — 1210 passed |
   | `add_to_watchlist` gains a new write property | **SURVIVED** — 1210 passed |
   | `update_watchlist` gains `additionalProperties: true` (unbounded free-form write payload) | **SURVIVED** — 1210 passed |
   | a read (`get_portfolio`) gains `side` + `quantity` inputs | **SURVIVED** — 1210 passed |
   | an allowed entry's description rewritten to *"Place a real equity order with real money."* | **SURVIVED** — 1210 passed |
   | `create_scan` gains a new write property | CAUGHT (`test_create_scan_expanded_write_scope_is_explicit`) |
   | `get_limited_margin_upgrade_info` gains `accept_agreement` | CAUGHT (`test_the_two_upgrade_link_tools_are_treated_alike`) |
   | control: no manifest change, pins refreshed only | 1210 passed (harness is sound) |

   Exactly **three of 54 entries** have their schema pinned against a refresh
   today: `create_scan` by an explicit equality, and the two upgrade-link tools
   by an equality *with each other*. The other 51 — including 10 of the 11
   allowed mutations — are held only by a human reading the refresh report,
   which is the control that just failed.

7. **Impact.** Bounded, and I want to be precise about it because the headline
   is scarier than the substance. `update_scan_config` was already an approved
   saved-scan write with `mutates: true`; `columns` stays inside the
   saved-scanner configuration domain; no order, funds, position, or
   account-permission state is reachable through it; a consumer gating on the
   `mutates` flag still gates it. **It is not a trading exposure and it does not
   cross the reviewed boundary.** What it *is*: (a) a permission expansion in
   substance within an already-permitted tool — the capability went from
   overwriting two scalar fields to destructively replacing an arbitrary column
   set — that no human recorded and no test held; (b) a shipped reviewer
   statement that is false; and (c) proof that §12.4's "a human reads the
   refresh report" control does not reliably fire.
8. **Remediation.** (i) Correct `update_scan_config`'s rationale to state the
   column write and the relaxed `required` set — this alone changes the
   full-manifest digest and therefore forces a deliberate re-pin, which is the
   right cost. (ii) Pin the input property set and `additionalProperties: false`
   for **all eleven** allowed mutations, not one. A ready-to-use fixture is in
   `test_adversarial_review_v033.py::TestEveryAllowedMutationPinsItsWriteSurface`;
   with it in place, five of the seven surviving mutations above are caught.
   (iii) Correct or annotate the `[0.3.2]` changelog sentence.
9. **Blocks approval:** **No** for the trading boundary. **Yes** as a condition
   on ainvest: see consumer requirement 6.

---

### P2-3 — The refresh-report control has no automated floor, and reads are unpinned entirely

1. **Severity:** P2 (control gap; the generalisation of P2-2).
2. **Location:** `tests/test_manifest.py::TestTheShippedManifest`;
   DESIGN §12.4; `scripts/refresh_manifest.py`.
3. **Detail.** `refresh_manifest.py` genuinely cannot grant a permission — I
   confirmed it has no disposition-changing flag and that a post-write assertion
   covers it, and the mutation suite holds that. But nothing bounds what a
   carried-forward `allowed` may come to *mean*. Two survivals above are worth
   naming separately from P2-2:
   - a **read** capability gaining `side`/`quantity`-shaped inputs survives. All
     35 reads are unpinned; the only structural assertion about them is
     `test_no_read_capability_is_flagged_as_mutating`, which checks that their
     names start with `get_`/`run_`/`search` — a name check, not a schema check.
   - an allowed entry's **description** being rewritten to trading prose
     survives. Descriptions are digested, so the digest moves and a human is
     asked — which is the same human control that missed P2-2.
4. **Impact:** the automated floor under §12.4 is thinner than §12.4's own prose
   implies. §12.4 says the refresh report "names every entry whose digests moved
   precisely so a human reads what changed there" and calls that reading "the
   control". At `0.3.2` that reading produced a changelog sentence that was
   affirmatively wrong about which entries widened.
5. **Blocks approval:** **No.** It does not make trading reachable — the eight
   denials are set-asserted and would have to change disposition, which the
   refresh tool cannot do. Recorded as residual risk and consumer requirement 6.

---

### P2-4 — No committed external review covers the current permission surface

1. **Severity:** P2 (process / provenance).
2. **Location:** `security-review/` contains `v0.1.0/` and `v0.2.0/` only;
   DESIGN §12 preamble; DESIGN §12.4.
3. **Detail.** §12.4 lists **"a tool appearing or disappearing"** as a change
   that *does* need a new external review. `get_limited_margin_upgrade_info`
   appeared at manifest `2026.08.09` / release `0.3.0`. DESIGN §12's preamble
   states `v0.3.0` "ships the **independently reviewed** permission expansion",
   and DESIGN §2.1 says "review found the manifest had already answered the
   question" — but there is no `security-review/v0.3.0/` artifact, no report,
   and no reviewer-authored tests, in the shape §12.1 and §12.2 established for
   the two changes that did get one. The review referenced appears to have been
   an internal round (the `[0.3.0]` changelog describes it as "an independent
   review disproved by mutation five … claims", which is internal-round
   language).
4. **Impact.** ainvest's basis for trusting this dependency is the `v0.2.0`
   external verdict. That verdict is bound by its own header and by §12.3 to
   commit `46128a62` / manifest `2026.08.03.1` / digest `70f88615…`. The current
   artifact has one additional tool, two widened allowed writes, and a different
   digest. By the project's own rule, **it is not covered**, and this report
   does not cover it either in the way an external one would.
5. **Blocks approval:** **No** from me — I cannot block on my own lack of
   standing. But it is the reason my disposition is not
   `APPROVED_FOR_AINVEST_INTEGRATION`, and ainvest should treat it as a decision
   the owner must make explicitly rather than one this report makes.

---

### P3-1 — `get_limited_margin_upgrade_info`: right answer, weaker argument than stated

My verdict on the one new allowed capability. Attacking the reasoning as asked:

**Is "returns a link to a state change" a read?** Under DESIGN §6's actual
definition — *"whether **invoking** the capability changes provider state"* —
**yes**, and `mutates: false` is **correct**. The input is `{account_number}`
with `additionalProperties: false`; there is no argument through which a caller
can express consent, acceptance, or intent. Invoking returns a boolean, an
account-type string, and URLs. Nothing on Robinhood's side moves. The account
changes only if a **human** opens a link and completes identity verification and
agreement acceptance in Robinhood's own flow — a path no call through this
gateway can reach or shorten beyond producing a string the user could have found
in the app anyway.

**Does the precedent justify it, or merely match it?** It **merely matches it**,
and DESIGN §2.1 overstates this. §2.1's stated reason for allowing it is:

> The denial would have made this section's opening claim false — the denied set
> would no longer have been exactly the trading surface — which is the clearest
> statement of why the two had to agree.

That is an argument about keeping a *table* internally consistent, not about the
capability. It reasons from the document to the verdict. Consistency is a real
constraint — holding both positions at once was genuinely the defect, and the
test that pins the two together is a good test — but "our §2.1 sentence would
stop being true" is not why this is safe.

**Two things the stated rationale misses, one of which cuts against it.**

- *Against.* `get_option_level_upgrade_info` is not a sibling of the new tool —
  it is its **dependent**. Its own description says option level 3 "requires a
  margin or limited-margin account … the customer must first switch to a
  margin/limited-margin account **via `get_limited_margin_upgrade_info`**, then
  re-fetch `get_accounts`". So the manifest now surfaces, in one session, the
  **complete two-step escalation path** from a cash account to level-3 options
  (spreads, multi-leg). Before `2026.08.09` the first step was not available
  through this gateway. Calling the older tool a "precedent that gates a higher
  privilege" is true but incomplete: the new tool is the *missing prerequisite*
  for the old one, and composing them is new capability, not a repeat of an old
  one.
- *For, and decisive.* Even granting the full escalation — a user who follows
  both links and ends up with a limited-margin, level-3 account — **this gateway
  still cannot place a trade**, because all eight order/cancel/exercise/simulate
  capabilities are denied before transport. Limited margin's benefit ("trade
  with unsettled funds") is inert through this surface. That is the argument
  that actually bounds the capability, and neither §2.1 nor the entry's
  `rationale` states it.

**Would I have allowed it?** **Yes** — on the second argument, not the first,
and with the consumer requirement below. The URLs and especially the `guide`
field (which instructs a model to present an unmasked-account-number upgrade
link to the user, and says "masking it breaks the link") are exactly the
provider-controlled, model-directed content DESIGN §10 already tells consumers
to discard. That requirement is load-bearing here in a way it is not for a quote
lookup.

**Severity:** P3 — reasoning quality in DESIGN §2.1 and in the entry's
`rationale`, not a defect in the verdict. **Blocks approval: No.** Remediation:
state the real bound (trading is denied regardless) in the entry's rationale and
in §2.1, and drop the tidiness argument to a supporting note.

---

### P3-2 — `test_no_read_capability_is_flagged_as_mutating` asserts a naming convention

`assert all(e.capability.startswith(("get_", "run_", "search")) for e in reads)`
is a name check standing where a property check is implied. A provider tool
named `get_…` that mutates would satisfy it. It is inert today (the eight
mutating tools are all named `create_`/`update_`/`add_`/`remove_`/`follow_`/
`unfollow_`) and is not the load-bearing assertion — `test_every_allowed_
mutation_is_flagged` pins the eleven as a set. Recorded, not blocking.

### P3-3 — MCP SDK writes `Session termination failed: 400` to stderr on every CLI run

Emitted by `mcp/client/streamable_http.py`, not by `rh-mcp`. It appears even on
fully successful runs and reads like an error. stdout stays clean JSON, which is
the contract `tests/test_cli.py` pins, so this is cosmetic — but an operator
diagnosing a refusal will see it and misattribute it. Not blocking.

---

## Re-run of the previous reviewers' own adversarial suites

Both suites were run against this artifact, unmodified.

### `security-review/v0.2.0/test_adversarial_review_v020.py` — **7 passed, 0 failed**

Every property the `v0.2.0` reviewer asserted holds at this commit: star-import
closure, absence of the legacy session opener, `StoredTokenProvider` not
star-imported, the immutable validated-argument snapshot through `invoke`, a
denied synthetic never reaching transport, and the documented private residual.

### `security-review/v0.1.0/test_adversarial_review.py` — **30 passed, 1 failed**

The single failure is
`TestPackagedManifestBoundary::test_exact_8_trading_denied_and_11_mutations_allowed`,
and it fails on its **first line**:

```
assert manifest.manifest_version == "2026.08.03.1"
E   AssertionError: assert '2026.08.22' == '2026.08.03.1'
```

**This is fully explained by the version/digest pin and is not a finding.** I did
not take that on trust. I re-executed every assertion in that test *after* the
two pinned lines, against the current manifest, in a separate file
(`test_v010_pin_isolated.py`): the denied set still equals their
`DENIED_TRADING` exactly, the allowed-mutating set still equals their
`ALLOWED_MUTATIONS` exactly, every denied entry is still `mutates: true`, and
their allowed-read count of 34 is now 35 — accounted for entirely by
`get_limited_margin_upgrade_info`, the one documented addition. **Passed.**

No failure in either suite is unexplained by the pins. DESIGN §12.4's statement
about this test, and CI's deselection of it by name, are accurate.

---

## Enforcement-path verification

`manifest.py`'s change is docstring-only and every other module is
byte-identical to `v0.2.0` (proven above), so the enforcement path is literally
the approved code. I did not stop there. Nine independent mutations, none of
them drawn from `scripts/mutate.py`:

| mutation | result | caught by |
|---|---|---|
| default-deny: `if entry is None or not entry.read_allowed` → `if entry is None` | **CAUGHT** | `test_a_denied_capability`, `test_denies_a_denied_capability`, `test_denied_and_unknown_are_indistinguishable` |
| unknown capability falls back to the first manifest entry | **CAUGHT** | `test_an_unknown_capability`, `test_a_provider_tool_name_used_as_a_capability`, +2 |
| preflight skips the pinned **schema**-digest recheck | **CAUGHT** | `test_reverifies_each_pinned_digest[schema_digest]` |
| preflight skips the pinned **metadata**-digest recheck | **CAUGHT** | `test_reverifies_each_pinned_digest[metadata_digest]` |
| preflight no longer requires readiness | **CAUGHT** | `test_refuses_when_the_gateway_is_not_ready`, +3 |
| preflight accepts an assessment for a different manifest | **CAUGHT** | `test_refuses_an_assessment_for_a_different_manifest` |
| `invoke` forwards the **caller's** name instead of `entry.provider_tool_name` | **CAUGHT** | `test_calls_the_provider_tool_the_manifest_pins`, +3 |
| `invoke` skips readiness entirely | **CAUGHT** | `test_an_auth_failure_during_discovery_reaches_the_library_caller` |
| loader trusts the declared `full_manifest_digest` instead of recomputing | **CAUGHT** | `test_rejects_a_declared_digest_that_does_not_match_the_contents` |

Plus the project's own harness: **88/88 caught**, including the `v0.1.0` P0 and
P1 reversions specifically.

The properties asked about, each established by the mutation that failed to
survive rather than by reading:

- **Default-deny holds** — reverting it fails three named tests.
- **Validation applies to the object actually forwarded** — `invoke` sends
  `preflight.arguments` (a deep-frozen snapshot), and both the "send the
  caller's mapping instead" and "return a mutable copy instead" reversions are
  caught. The `v0.1.0` P1 cannot recur silently.
- **No public generic `call_tool`** — `transport.__all__` binds four value types
  and one constant; nothing star-imported is callable into the network; the
  escape-hatch *detector itself* has a mutation proving it still detects.
- **A caller-supplied name cannot reach the provider** — `invoke` passes
  `entry.provider_tool_name`; substituting the caller's string fails four tests.
  Confirmed live: four provider trading tool names used as capabilities were
  refused at preflight over a real session.

`tests/test_public_surface.py` was not merely trusted: five of the project's 88
mutations attack it directly (re-adding each withdrawn name to an `__all__`, and
renaming the detector's own targets), and all five are caught.

---

## Repository quality gate

```
PYTHONDONTWRITEBYTECODE=1 uv run pytest -p no:cacheprovider -q   → 1210 passed
uv run ruff check .                                             → All checks passed!
uv run mypy src                                                 → no issues in 13 source files
uv run python scripts/mutate.py                                 → 88/88 mutations caught
uv build && uv run python scripts/check_sdist.py …tar.gz        → 62 files, all allowlisted
git status --short                                              → (empty)
```

---

## Reviewer-authored tests

`test_adversarial_review_v033.py`, beside this report. **31 pass, 1 fails by
design.**

- `TestTheDeniedSetIsStillExactlyTheTradingSurface` — the 8 as a set, all
  `mutates: true`, and the 35/11/8 split.
- `TestEveryAllowedMutationPinsItsWriteSurface` — **the P2-2 remediation.** Pins
  the exact input property set and `additionalProperties: false` for all eleven
  allowed mutations, plus a blunt trip-wire refusing any
  `side`/`quantity`/`price`/`order_id`-shaped argument on a mutation. Verified
  to close five of the seven surviving mutations from harness 3.
- `TestReviewerRationalesStillDescribeTheShippedSchema` — **written to FAIL**
  against this artifact. It is the executable form of P2-2 and should go green
  when `update_scan_config`'s rationale is corrected, not by being edited.
- `TestTheTwoUpgradeLinkToolsStayAligned` — both upgrade-link tools are reads
  with exactly `{account_number}` and `additionalProperties: false`, so no
  consent-expressing argument can arrive in a refresh (P3-1).
- `TestPublishedSurfaceIsStillClosed` — the `v0.1.0` P0, re-asked here rather
  than inherited.

`test_v010_pin_isolated.py` — re-runs the `v0.1.0` reviewer's assertions with
only the version/digest pin removed, so "the failure is just the pin" is
demonstrated rather than asserted.

---

## Ainvest consumer requirements

If the owner accepts this report's disposition, `ainvest` may pin this artifact
for an independently reviewed broker adapter, provided it:

1. Pins package version `0.3.3`, source commit
   `ce8f839660040a2fed543525f01fb2f54e732aa4`, full-manifest digest
   `sha256:2ea0954b4a52d9469837bc2b167904ab871de893475e68b43dc2a8fb02e7f886`,
   manifest version `2026.08.22`, and envelope version `1.0` — supplying the
   digest through `GatewayConfig(expected_manifest_digest=…)` /
   `RH_MCP_EXPECTED_MANIFEST_DIGEST`.
2. **Pins a released artifact, which does not yet exist.** There is no `v0.3.3`
   tag, no GitHub release, no published wheel/sdist SHA-256 and no Sigstore
   attestation for this commit. The hashes in my header are from a *local* build
   and are evidence of nothing beyond that. ainvest must not pin a wheel until
   the tag workflow has published one and `gh attestation verify` passes against
   it, and must re-confirm at that point that the released manifest digest is
   still `sha256:2ea0954b…f886`. Take the digest from the artifact being pinned,
   never from a changelog line (DESIGN §12.5 documents an existing instance of
   that hazard).
3. Uses only `GatewayConfig` + `open_gateway` / `RobinhoodGateway.invoke` and
   the `rh-mcp` CLI. Must not import `rh_mcp.transport._open_provider_session`,
   `_PrivateSession`, `rh_mcp.auth.StoredTokenProvider`,
   `rh_mcp.credentials.open_credential_store`, or treat any underscore-prefixed
   name as supported API (P2-1).
4. Keeps `invoke` inside a dedicated broker adapter and exposes only normalized
   ainvest operations downstream.
5. Discards provider `guide` text, tool descriptions and schema descriptions
   from model, Telegram, CLI and log context. **This is load-bearing for
   `get_limited_margin_upgrade_info` and `get_option_level_upgrade_info`
   specifically**: their `guide` fields instruct a model to present
   privilege-upgrade links with the account number unmasked (P3-1).
6. Gates writes on the reviewed `mutates` flag — **and does not rely on any
   individual capability's `rationale` as an accurate statement of its blast
   radius.** `update_scan_config`'s rationale understates what it writes (P2-2),
   and 10 of the 11 mutations have no automated schema pin (P2-3). Treat all
   eleven as "may destructively replace a watchlist or saved-scan object" and
   gate accordingly. If ainvest re-derives a per-capability risk tier from
   rationale prose, that derivation is currently unsound.
7. Re-reads the refresh diff itself on every digest bump it accepts, comparing
   the `input_schema` of all eleven allowed mutations structurally (descriptions
   stripped) against the previously pinned manifest. The project-side control
   for this did not fire at `0.3.2`. The fixture in
   `test_adversarial_review_v033.py` does this mechanically and can be vendored.
8. Resolves MCP SDK compatibility (`rh-mcp` requires `mcp>=2,<3`).
9. Completes a separate independent review of the ainvest adapter itself before
   production use.
10. **Obtains the owner's explicit decision on P2-4** — that no committed
    external review covers a permission surface that has gained a tool and two
    widened writes since the last one — rather than reading this report as that
    review.

---

## Known limitations and residual risks

- The OAuth credential is trading-capable (`internal` scope); Robinhood offers
  no read-only scope. The reviewed manifest on the gateway path is the only
  restraint. Confirmed live: `granted_scope: internal`.
- **§12.4's residual is live, not theoretical.** A refresh can carry a reviewed
  `allowed` onto a schema that widened underneath it, and did so at `0.3.2` for
  `update_scan_config` without any human or test noticing (P2-2, P2-3). Three of
  54 entries are schema-pinned today.
- Provider-controlled prose — `guide`, descriptions, schema descriptions —
  remains prompt-injection material inside result envelopes, and two allowed
  reads now carry `guide` text that actively directs a model to hand the user a
  privilege-upgrade link.
- `create_scan` and `update_scan_config` accept caller-supplied **market-data
  expression strings** that Robinhood evaluates server-side. The gateway
  validates them only structurally (`type: string`; no length bound). This is
  the widest caller-controlled free-text surface among the allowed writes. It
  reaches Robinhood's scanner expression evaluator, not any trading path.
- In-process callers can still import underscore-prefixed internals (P2-1);
  DESIGN §3 states this is not the boundary.
- Production credential storage is macOS Keychain-only for the bundled store.
- `dataclasses.asdict` / `astuple` on credential objects can still expose
  secrets (documented upstream).
- The `0.3.2` changelog contains a factually incorrect statement about which
  entries widened (P2-2 §4); the `0.1.0`/`0.2.0` changelog digest discrepancy
  documented in DESIGN §12.5 also remains.
- This verdict is bound to commit `ce8f839` and manifest digest
  `sha256:2ea0954b…f886`. A later commit, tag, or digest inherits nothing.

---

## What I could not verify

Stated plainly, because the value of this report depends on its boundaries.

1. **I am not an outside party.** I am a fresh agent, but I ran inside the
   owner's checkout at the owner's request. The `v0.1.0` and `v0.2.0` reviewers
   were external to the project and worked from published artifacts. My
   independence is weaker than theirs and my verdict should not be recorded as
   equivalent. (DESIGN §12.1's own argument about shared context applies to me
   partially.)
2. **No live *tool* call against Robinhood, and no verification of what any
   allowed capability actually does.** I performed live authenticated
   **discovery** (`tools/list`) — disclosed above, and it is more provider
   contact than either prior review had — but I invoked **no** capability,
   allowed or denied. I have not observed a single provider response body. Every
   statement about what `update_scan_config`, `create_scan`, or
   `get_limited_margin_upgrade_info` *do* on Robinhood's side is read from the
   provider's own schemas and prose, which DESIGN §2 correctly says is evidence
   and never authority. In particular I cannot confirm that
   `get_limited_margin_upgrade_info` has no server-side effect; I can only
   confirm that nothing in its input can express one and that its schema
   declares none.
3. **No released artifact, no reproducible-build check, no attestation.** There
   is no `v0.3.3` tag or GitHub release. I built locally; I did not verify that
   the build is byte-reproducible on another machine, and there is no Sigstore
   provenance to verify. The `v0.2.0` review had all three. This is the largest
   evidentiary gap between that report and this one.
4. **I did not review the release, tag, or manifest-refresh CI as a security
   control.** `manifest-refresh.yml`, `auto-release.yml`, `release.yml`,
   `verify_release_pr.py`, the two GitHub Apps, the CMS encryption of
   candidates, and the self-hosted Mac runner all changed substantially since
   `v0.2.0` and all sit on the path by which a manifest reaches consumers. I
   read enough of `refresh_manifest.py` and `manifest_automation.py` to confirm
   the refresh tool cannot change a disposition; I did **not** audit the
   workflows, their permissions, their trigger surfaces, or the key handling.
   Given that this artifact's only change is a bot-produced manifest, that is a
   material gap and should be reviewed separately.
5. **I did not audit `auth.py`, `credentials.py`, `transport.py` or `config.py`
   line by line.** I established they are byte-identical to the externally
   approved `v0.2.0` and relied on that review plus the project's 88-mutation
   harness. If the `v0.2.0` review missed something in those files, this report
   inherits the miss.
6. **No dependency / supply-chain review.** `uv.lock` moved (httpx2, dev
   tooling, actions bumps). I ran `tests/test_dependency_bounds.py` and
   `test_dependency_boundary.py` as part of the suite; I did not audit the new
   versions or their provenance.
7. **No verification of the human review claimed for `0.3.0`.** DESIGN asserts
   the permission expansion was independently reviewed; I found no committed
   artifact and could not confirm the claim either way (P2-4).
8. **The `update_scan_config` finding is a finding about a control, not a
   demonstrated exploit.** I did not show that anything harmful can be done with
   `columns`. I showed that the schema widened, that the shipped rationale is
   now false about it, that the changelog says it did not happen, and that no
   test would have caught it. Whether the widened capability is acceptable is
   the owner's call; that it was never made is the finding.
9. **`candidate.json` (445 KB, untracked, gitignored) sits in the working tree**
   from a prior local refresh run. I confirmed it is a discovery candidate
   document (`{candidate, observed_at, tools}`) and is excluded from git and
   from the sdist. I did not read its contents and cannot say whether it holds
   anything sensitive.

---

## Final disposition

**`INTERNAL_ADVERSARIAL_REVIEW_PASS_WITH_CONDITIONS`**

Not `APPROVED_FOR_AINVEST_INTEGRATION`. That label belongs to the two external
reviews, and I have argued above (Independence statement, P2-4, "What I could
not verify" 1 and 3) why mine should not carry it: I am inside the project, and
I reviewed source with no released, attested artifact behind it.

**The property under review holds.** On the evidence in this report:

- The denied set is *exactly* the eight trading capabilities, asserted as a set
  in both directions, all `mutates: true`. DESIGN §2.1's normative claim is true
  of this artifact.
- The entire enforcement path is **byte-identical** to the artifact an external
  reviewer approved on 2026-08-04. No §12.4 code trigger has fired.
- All four digest families re-derive independently and match; the manifest the
  wheel ships is the manifest the repo carries is the digest a consumer pins.
- Verified against the **live** provider: zero drift, and four trading
  capabilities refused before the wire with a real trading-capable token.
- 88/88 project mutations, 9/9 independent enforcement mutations, and both prior
  reviewers' suites hold — the one failure being a version pin, proven so by
  re-running the test's substance with only the pin removed.
- The single new allowed capability is a genuine read whose escalation path
  requires a human action this gateway cannot perform, and which is inert
  through this surface because trading is denied regardless.

**No P0 or P1. Nothing here blocks on the trading boundary.**

The conditions are consumer requirements 1–10, and the three that carry weight
are **2** (do not pin an artifact that does not exist yet), **6** (do not trust
a capability's `rationale` as its blast radius), and **10** (the owner must
decide P2-4 explicitly).

I would also recommend, though it does not block: correct `update_scan_config`'s
rationale, land the eleven-mutation property pin, and annotate the `[0.3.2]`
changelog sentence. The first of those moves the manifest digest, which is the
correct cost for correcting a permission record.
