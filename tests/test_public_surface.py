"""DESIGN.md §1/§2: the *package* offers no way to obtain a raw call surface.

This file exists because the test it replaces was the right idea at the wrong
scope. `tests/test_gateway.py::TestNoEscapeHatch` asserted that
`RobinhoodGateway` exposes no session, no transport and no `call_tool` — and
it passed, correctly, for the whole of v0.1.0. It was also the only thing
guarding a claim DESIGN.md §1, the README and the CHANGELOG all make about
*both* public surfaces:

> Neither surface exposes an MCP `ClientSession`, raw MCP result types,
> arbitrary tool names, or a generic `call_tool`.

An independent security reviewer read that sentence, ignored the gateway
entirely, and imported `rh_mcp.transport.open_provider_session` — which was in
`__all__`, returned an object with an unrestricted `call_tool`, and accepted
`call_tool("place_equity_order", ...)` against a synthetic server. The claim
was false and every test in the repository was green, because the test asked
about one class while the claim was about a package.

So the questions here are asked of every module, and they are asked of the
*advertised* surface rather than a list of known-bad names:

1. What does `from rh_mcp.<module> import *` actually put in a namespace?
   Not `__all__` — the real thing, which for a module without `__all__` is
   every name not starting with an underscore. A blocklist of the four names
   the reviewer found would be a test that catches exactly the bug already
   fixed; the sweep below catches the fifth one nobody has written yet.
2. Of everything that lands there, is anything a raw call surface — an object
   with a public `call_tool`, or a bearer-token factory with a public
   `access_token`?
3. Does any of it *hand one back*: a function or context manager whose return
   type, unwrapped through `AsyncIterator` and friends, is such a surface?

Question 3 is the one that catches `open_provider_session`, and it is
deliberately asymmetric with injection. `open_gateway(transport=...)` still
takes a `ProviderTransport`, and that is safe for a reason worth stating:
supplying a fake transport is how the tests and `admin discover` work, and it
grants nothing — you had to already possess the object. Being *handed* one by
the package is the escape hatch. `test_transport_injection_points_are_exactly_the_two_reviewed_ones`
keeps that exemption from silently widening.

What none of this claims: §3 says in-process separation is not a security
boundary, and it still is not. Anything inside the broker process can import
`rh_mcp.transport._open_provider_session` and read the credential store
directly, and no test here prevents that. These tests defend a narrower and
still worthwhile property — that the package's *published* contract is true,
so that a consumer integrating against it cannot reach a trading path by
importing something that looked supported.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import typing
from collections.abc import AsyncIterator, Awaitable, Iterator, Mapping
from typing import Any

import pytest

import rh_mcp

# A method named here makes its owner a "raw call surface": an object that can
# reach the network, or authorize a request to it, below the layer that knows
# what a capability is.
#
# `call_tool` sends an arbitrary tool name. `access_token` mints the
# `Authorization: Bearer` header for a write-capable `internal` credential —
# on its own it sends nothing, but the reviewer's P0 chain was exactly
# credential store -> token provider -> session, and a package that publishes
# a token factory is publishing two thirds of it.
#
# The three HTTP verbs are `GuardedJsonClient`, the seam `auth.py` reaches the
# network through. They are here after a deliberate check rather than by
# analogy: `open_json_client(config)` accepts no token provider and the verbs
# accept no headers, so nothing reachable this way can carry a credential, and
# pointing one at the pinned MCP endpoint yields an unauthenticated request.
# They are **not** a `call_tool` equivalent.
#
# Listing them is a judgement about the export surface, not about exploitability.
# Four names were withdrawn from `__all__` for P0; a fifth HTTP helper left
# standing beside them reads as deliberately retained, and this release's whole
# argument is that exported names get used. Deriving the rule — "no published
# name is, or hands back, something that talks to the network" — is what makes
# the sweep answer for the helper nobody has written yet, which is the same
# reason it is not a list of the names already found.
RAW_CALL_SURFACE_METHODS = frozenset(
    {"call_tool", "access_token", "get_json", "post_json", "post_form"}
)

# The published names allowed to *accept* a transport: the two context
# managers and the two classes they construct. All four are injection seams
# for tests and for `admin discover`, which observes and cannot read; none of
# them returns a transport. Adding a fifth is a security-boundary change (§12).
TRANSPORT_INJECTION_POINTS = frozenset(
    {
        "open_gateway",
        "open_admin_discovery",
        "RobinhoodGateway",
        "AdminDiscoveryContext",
    }
)


def _module_names() -> list[str]:
    return sorted(f"rh_mcp.{info.name}" for info in pkgutil.iter_modules(rh_mcp.__path__))


MODULE_NAMES = _module_names()


def _star_imported_names(module: Any) -> list[str]:
    """Exactly what `from module import *` binds.

    `__all__` when the module defines one, every non-underscore name otherwise
    — which is why a module can not opt out of this sweep by deleting its
    `__all__`.
    """
    declared = getattr(module, "__all__", None)
    if declared is not None:
        return list(declared)
    return [name for name in vars(module) if not name.startswith("_")]


def _has_raw_call_surface(obj: Any) -> str | None:
    """The forbidden method `obj` publicly offers, if any."""
    for method in sorted(RAW_CALL_SURFACE_METHODS):
        if callable(getattr(obj, method, None)):
            return method
    return None


def _unwrap_return(annotation: Any) -> Any:
    """Peel container types off a return annotation to reach what is yielded.

    `@asynccontextmanager` functions annotate `AsyncIterator[T]`, coroutines
    `Awaitable[T]`, generators `Iterator[T]`. The escape hatch is `T`, so a
    check that read the annotation literally would see `AsyncIterator` — which
    has no `call_tool` — and pass on precisely the shape of
    `open_provider_session`.
    """
    for _ in range(8):
        origin = typing.get_origin(annotation)
        if origin in (AsyncIterator, Awaitable, Iterator, typing.AsyncGenerator, typing.Generator):
            args = typing.get_args(annotation)
            if not args:
                return annotation
            annotation = args[0]
            continue
        union_members = [a for a in typing.get_args(annotation) if a is not type(None)]
        if origin is not None and union_members and str(origin).startswith("typing.Union"):
            annotation = union_members[0]
            continue
        return annotation
    return annotation


def _resolved_return(obj: Any, module: Any) -> Any:
    """The resolved return annotation of a callable, or `None`.

    `from __future__ import annotations` makes every annotation a string, so
    these must be evaluated against the defining module's globals rather than
    matched as text.
    """
    target = inspect.unwrap(obj)
    try:
        hints = typing.get_type_hints(target, globalns=vars(module))
    except Exception:  # noqa: BLE001 - an unresolvable hint is not a finding here
        return None
    return hints.get("return")


# ==========================================================================
# Guards against the sweep passing because it found nothing
# ==========================================================================


def test_the_sweep_found_the_package_modules() -> None:
    """A sweep over an empty list passes every assertion in this file."""
    assert len(MODULE_NAMES) >= 10
    assert "rh_mcp.transport" in MODULE_NAMES
    assert "rh_mcp.gateway" in MODULE_NAMES
    assert "rh_mcp.auth" in MODULE_NAMES
    assert "rh_mcp.credentials" in MODULE_NAMES


def test_the_package_still_contains_raw_call_surfaces_to_find() -> None:
    """The detector must detect. Otherwise every assertion below is vacuous.

    `ProviderTransport` and the concrete session are supposed to exist and are
    supposed to be unpublished. If `_has_raw_call_surface` ever stops
    recognising them — a rename of `call_tool`, a typo in the frozenset — the
    sweep would report a clean package for the wrong reason.
    """
    from rh_mcp.transport import GuardedJsonClient, ProviderTransport

    assert _has_raw_call_surface(ProviderTransport) == "call_tool"
    # The HTTP seam, checked separately: it is detected by a different method
    # name, so a frozenset that had lost the verbs would still pass the line
    # above and report a clean package.
    assert _has_raw_call_surface(GuardedJsonClient) == "get_json"

    from rh_mcp.auth import StoredTokenProvider

    assert _has_raw_call_surface(StoredTokenProvider) == "access_token"


def test_the_return_unwrapper_sees_through_an_async_context_manager() -> None:
    """The v0.1.0 escape hatch was `AsyncIterator[ProviderTransport]`."""
    from rh_mcp.transport import ProviderTransport, _open_provider_session

    resolved = _resolved_return(_open_provider_session, importlib.import_module("rh_mcp.transport"))
    assert _unwrap_return(resolved) is ProviderTransport


# ==========================================================================
# The sweep
# ==========================================================================


@pytest.mark.parametrize("module_name", MODULE_NAMES)
def test_no_star_imported_name_is_a_raw_call_surface(module_name: str) -> None:
    """§1: no published name *is* a way to call the provider."""
    module = importlib.import_module(module_name)
    for name in _star_imported_names(module):
        obj = getattr(module, name)
        offending = _has_raw_call_surface(obj)
        assert offending is None, (
            f"{module_name}.{name} is published and offers a public "
            f"{offending!r}; it is a manifest-free provider call surface"
        )


@pytest.mark.parametrize("module_name", MODULE_NAMES)
def test_no_star_imported_callable_returns_a_raw_call_surface(module_name: str) -> None:
    """§1: no published name *hands back* a way to call the provider.

    This is the assertion that would have failed on v0.1.0's
    `open_provider_session`, and it fails on any future function shaped like
    it without anyone having to remember to add its name anywhere.
    """
    module = importlib.import_module(module_name)
    for name in _star_imported_names(module):
        obj = getattr(module, name)
        if not callable(obj):
            continue
        resolved = _resolved_return(obj, module)
        if resolved is None:
            continue
        yielded = _unwrap_return(resolved)
        offending = _has_raw_call_surface(yielded)
        assert offending is None, (
            f"{module_name}.{name} is published and returns {yielded!r}, "
            f"which offers a public {offending!r}"
        )


@pytest.mark.parametrize("module_name", MODULE_NAMES)
def test_every_star_imported_name_resolves(module_name: str) -> None:
    """An `__all__` entry naming nothing hides whatever it was meant to name."""
    module = importlib.import_module(module_name)
    for name in _star_imported_names(module):
        assert hasattr(module, name), f"{module_name}.__all__ names a missing {name!r}"


def test_transport_injection_points_are_exactly_the_two_reviewed_ones() -> None:
    """Accepting a transport is safe; the exemption must not spread.

    A function that takes `transport=` cannot leak one — the caller already
    had it. But each such parameter is a place where a future edit could start
    *returning* the session instead, so the set is pinned rather than allowed
    to grow quietly.
    """
    found: set[str] = set()
    for module_name in MODULE_NAMES:
        module = importlib.import_module(module_name)
        for name in _star_imported_names(module):
            obj = getattr(module, name)
            if not callable(obj):
                continue
            try:
                parameters = inspect.signature(inspect.unwrap(obj)).parameters
            except (TypeError, ValueError):
                continue
            if "transport" in parameters:
                found.add(name)
    assert found == TRANSPORT_INJECTION_POINTS


# ==========================================================================
# Named regressions the generic sweep above does not reach
# ==========================================================================


def test_the_credential_store_factory_is_not_advertised() -> None:
    """`credentials.open_credential_store`, out of `__all__` — a narrow case.

    Honest about what this is: the sweep above cannot catch it generically,
    because a `CredentialStore` is not a call surface and the store *types*
    are legitimately published as `open_gateway(store=...)` injection targets.
    So this is a named regression rather than a derived property, and it is
    worth one assertion because it was the first link in the reviewer's P0
    chain — store, then `StoredTokenProvider`, then a session.

    The factory is still importable. §3 is explicit that in-process separation
    is not a boundary, so an underscore would buy nothing; what is withdrawn
    is the advertisement, which is what a consumer's linter and IDE read.
    """
    credentials = importlib.import_module("rh_mcp.credentials")
    assert "open_credential_store" not in _star_imported_names(credentials)
    assert callable(credentials.open_credential_store)


def test_the_capability_argument_is_not_a_provider_tool_name() -> None:
    """§2: the one public call takes a *capability*, never a tool name.

    `RobinhoodGateway.invoke` is the only published method that reaches the
    provider at all, and the distinction its first parameter draws is the
    whole default-deny model: a capability is a name a human reviewed into the
    manifest, a provider tool name is whatever Robinhood happens to serve.
    """
    from rh_mcp.gateway import RobinhoodGateway

    parameters = list(inspect.signature(RobinhoodGateway.invoke).parameters)
    assert parameters == ["self", "capability", "arguments"]

    from rh_mcp.transport import ProviderTransport

    transport_parameters = list(inspect.signature(ProviderTransport.call_tool).parameters)
    assert "provider_tool_name" not in transport_parameters


def test_the_gateway_sends_only_the_validated_snapshot() -> None:
    """Finding P1, at the public surface rather than at `preflight_read`.

    `tests/test_manifest.py` proves the snapshot is returned and
    `tests/test_gateway.py` proves `invoke` sends it. This asserts the type
    contract that makes forwarding the caller's mapping a mypy error rather
    than a code-review responsibility: `preflight_read` no longer returns
    something a caller can send, so the wiring bug cannot silently return.
    """
    from rh_mcp.manifest import PreflightResult, preflight_read

    resolved = typing.get_type_hints(preflight_read)
    assert resolved["return"] is PreflightResult
    fields = typing.get_type_hints(PreflightResult)
    assert set(fields) == {"entry", "arguments"}
    assert typing.get_origin(fields["arguments"]) is Mapping or fields["arguments"] is Mapping
