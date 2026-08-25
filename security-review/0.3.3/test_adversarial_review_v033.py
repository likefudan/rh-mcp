"""Adversarial tests authored for the rh-mcp 0.3.3 review (commit ce8f839).

Run from a checkout root:

    PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 uv run pytest -p no:cacheprovider \
        security-review/v0.3.3/test_adversarial_review_v033.py -v

Two classes here are *not* restatements of the repository's own suite:

* `TestEveryAllowedMutationPinsItsWriteSurface` closes the gap that
  `TestTheShippedManifest::test_create_scan_expanded_write_scope_is_explicit`
  leaves open. That test pins one of the eleven allowed mutations. The other
  ten were unpinned, and this review demonstrated by mutation that a new
  write property — optional *or required* — can be added to
  `update_scan_config`, `update_scan_filters`, `add_to_watchlist` or
  `update_watchlist` and survive a full refresh (manifest resealed, README /
  CHANGELOG / DESIGN / test pins updated) with 1210/1210 green.
* `TestReviewerRationalesStillDescribeTheShippedSchema` records the finding
  that `update_scan_config`'s carried-forward rationale ("Overwrites those two
  fields only") stopped being true when the 2026.08.21 refresh added a
  REPLACE-semantics `columns` array. It is written to FAIL until either the
  rationale is corrected or the schema narrows, because a reviewer statement
  that is false about the artifact it ships in is the exact thing DESIGN §6
  says the rationale field exists to prevent.

Everything else pins properties this review verified and wants held.
"""

from __future__ import annotations

import pytest

from rh_mcp.manifest import load_active_manifest

TRADING = (
    "place_equity_order",
    "place_option_order",
    "cancel_equity_order",
    "cancel_option_order",
    "cancel_option_exercise",
    "exercise_option",
    "review_equity_order",
    "review_option_order",
)

# The eleven owner-approved non-trading mutations, with the exact input
# property set each one shipped at manifest 2026.08.22. Pinned as equality in
# both directions: a subset check is what let the 2026.08.21 widening of
# `update_scan_config` through.
ALLOWED_MUTATION_PROPERTIES = {
    "add_option_to_watchlist": {"option_ids", "position_type"},
    "add_to_watchlist": {"list_id", "symbols", "index_ids", "currency_pair_ids"},
    "create_scan": {"scan_id", "preset", "filters", "title", "columns"},
    "create_watchlist": {"display_name", "icon_emoji", "display_description"},
    "follow_watchlist": {"list_id"},
    "remove_from_watchlist": {"list_id", "symbols", "index_ids", "currency_pair_ids"},
    "remove_option_from_watchlist": {"option_ids", "position_type"},
    "unfollow_watchlist": {"list_id"},
    "update_scan_config": {"scan_id", "sorting_column", "sorting_direction", "columns"},
    "update_scan_filters": {"scan_id", "filters"},
    "update_watchlist": {"list_id", "display_name", "icon_emoji", "display_description"},
}


class TestTheDeniedSetIsStillExactlyTheTradingSurface:
    def test_denied_is_that_set_and_nothing_else(self) -> None:
        """DESIGN §2.1's normative claim, asserted as a set in both directions."""
        manifest = load_active_manifest()
        denied = {e.provider_tool_name for e in manifest.entries if not e.read_allowed}
        assert denied == set(TRADING)

    def test_every_denied_entry_is_flagged_mutating(self) -> None:
        manifest = load_active_manifest()
        for name in TRADING:
            assert manifest.capabilities[name].mutates is True

    def test_the_split_is_35_reads_11_mutations_8_denied(self) -> None:
        manifest = load_active_manifest()
        entries = manifest.entries
        assert len(entries) == 54
        assert sum(1 for e in entries if e.read_allowed and not e.mutates) == 35
        assert sum(1 for e in entries if e.read_allowed and e.mutates) == 11
        assert sum(1 for e in entries if not e.read_allowed) == 8


class TestEveryAllowedMutationPinsItsWriteSurface:
    """The §12.4 residual, closed for all eleven rather than for one.

    A refresh carries `allowed` forward onto a schema the provider changed.
    The repository pins `create_scan`'s property set for exactly that reason.
    These pin the other ten the same way.
    """

    @pytest.mark.parametrize("capability", sorted(ALLOWED_MUTATION_PROPERTIES))
    def test_the_write_surface_is_the_reviewed_one(self, capability: str) -> None:
        entry = load_active_manifest().capabilities[capability]
        assert entry.disposition == "allowed"
        assert entry.mutates is True
        assert set(entry.input_schema.get("properties", {})) == (
            ALLOWED_MUTATION_PROPERTIES[capability]
        )

    @pytest.mark.parametrize("capability", sorted(ALLOWED_MUTATION_PROPERTIES))
    def test_no_allowed_mutation_accepts_undeclared_arguments(self, capability: str) -> None:
        """`additionalProperties: false` is what bounds a forwarded payload.

        Flipping it to `true` on `update_watchlist` survived a full simulated
        refresh in this review, so it is pinned rather than assumed.
        """
        entry = load_active_manifest().capabilities[capability]
        assert entry.input_schema.get("additionalProperties") is False

    def test_no_allowed_mutation_names_an_order_shaped_argument(self) -> None:
        """A cheap, blunt trip-wire on the direction that actually matters."""
        forbidden = {"side", "quantity", "price", "limit_price", "order_id", "order_type"}
        for entry in load_active_manifest().entries:
            if not (entry.read_allowed and entry.mutates):
                continue
            assert not (set(entry.input_schema.get("properties", {})) & forbidden), entry.capability


class TestReviewerRationalesStillDescribeTheShippedSchema:
    """DESIGN §6: the rationale is the review, not decoration.

    `scripts/refresh_manifest.py` carries `rationale` forward verbatim while
    provider-derived schemas move underneath it (DESIGN §12.4). That is fine
    until the carried string becomes false. This asserts the one case where it
    did.
    """

    def test_update_scan_config_rationale_covers_its_column_write(self) -> None:
        entry = load_active_manifest().capabilities["update_scan_config"]
        assert "columns" in entry.input_schema["properties"], (
            "precondition: the shipped schema takes a `columns` array"
        )
        rationale = entry.rationale.lower()
        assert "overwrites those two fields only" not in rationale, (
            "the shipped rationale claims this capability writes exactly "
            "sorting_column and sorting_direction; manifest 2026.08.21 gave it a "
            "REPLACE-semantics `columns` array and relaxed both of those out of "
            "`required`. The reviewer statement no longer describes the artifact."
        )
        assert "column" in rationale, (
            "a rationale that does not mention the column write does not state "
            "this capability's blast radius"
        )


class TestTheTwoUpgradeLinkToolsStayAligned:
    """The 2026.08.09 addition, checked against its own stated justification."""

    def test_both_are_reads_with_the_same_single_input(self) -> None:
        manifest = load_active_manifest()
        limited = manifest.capabilities["get_limited_margin_upgrade_info"]
        options = manifest.capabilities["get_option_level_upgrade_info"]
        for entry in (limited, options):
            assert entry.disposition == "allowed"
            assert entry.mutates is False
            assert set(entry.input_schema["properties"]) == {"account_number"}
            assert entry.input_schema.get("additionalProperties") is False

    def test_neither_accepts_anything_that_could_express_consent(self) -> None:
        """`mutates: false` holds only while invoking cannot carry an intent.

        An `accept_agreement` / `confirm` argument would make the call itself
        the state change. `additionalProperties: false` plus this exact
        property set is what keeps that from arriving in a refresh.
        """
        manifest = load_active_manifest()
        for name in ("get_limited_margin_upgrade_info", "get_option_level_upgrade_info"):
            properties = set(manifest.capabilities[name].input_schema["properties"])
            assert properties == {"account_number"}


class TestPublishedSurfaceIsStillClosed:
    """The v0.1.0 P0, re-asked at this commit rather than assumed from v0.2.0."""

    def test_transport_star_import_binds_no_call_surface(self) -> None:
        namespace: dict[str, object] = {}
        exec("from rh_mcp.transport import *", namespace)  # noqa: S102
        bound = {k for k in namespace if not k.startswith("__")}
        assert bound == {
            "PRODUCTION_EGRESS_HOSTS",
            "HttpJsonResponse",
            "PayloadSource",
            "ToolPayload",
        }

    def test_the_top_level_package_re_exports_nothing(self) -> None:
        """DESIGN §1: `rh_mcp` itself binds no gateway, transport or credential name.

        A star-import still binds *submodule* names for submodules the process
        has already imported, which is CPython's behaviour and not an export.
        What matters is that nothing callable or constructible is bound there.
        """
        import types

        import rh_mcp

        namespace: dict[str, object] = {}
        exec("from rh_mcp import *", namespace)  # noqa: S102
        bound = {k: v for k, v in namespace.items() if not k.startswith("__")}
        assert not hasattr(rh_mcp, "__all__")
        assert all(isinstance(v, types.ModuleType) for v in bound.values()), bound

    def test_the_legacy_session_opener_name_is_still_absent(self) -> None:
        import rh_mcp.transport as transport

        assert not hasattr(transport, "open_provider_session")
        # The accepted P2 residual, recorded rather than asserted away.
        assert hasattr(transport, "_open_provider_session")
