"""DESIGN.md §4/§11: no MCP SDK or HTTP client type may be public.

Step 3 is where this stops being free. Until now no module imported `mcp` or
`httpx2` at all, so the boundary was a one-line import sweep. Now exactly one
module does, and the rule becomes the one §4 actually states:

> No public signature, exception, serialized result, or type annotation may
> contain an `mcp.*` or `httpx2.*` type.

Four checks enforce it, and they are deliberately different in kind:

1. **Import containment.** Only `transport.py` may import the SDK. Everything
   else stays stdlib-plus-`rh_mcp`, so `import rh_mcp.models` in a consumer
   still costs nothing and pulls in no SDK.
2. **Annotation inspection.** Every public name in every module is walked —
   functions, classes, dataclass fields, protocol methods — and no resolved
   annotation may come from an SDK package. `from __future__ import
   annotations` makes every annotation a string at runtime, so these are
   resolved with `typing.get_type_hints` rather than read literally; a
   string-only check would pass on a signature that genuinely names an
   `httpx2.AsyncClient`.
3. **Import isolation, in a subprocess.** Importing the public model modules
   must not drag the SDK into `sys.modules`. This is the property a consumer
   on another MCP major version actually depends on, and it cannot be
   established by reading source.
4. **`__all__` discipline.** A module that imports the SDK must not re-export
   an SDK name.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import subprocess
import sys
import typing
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Any

import httpx2
import pytest

import rh_mcp

# `mcp_types` is the SDK's wire-type package and `pydantic`/`anyio` are its
# runtime substrate. All four are private implementation detail for the same
# reason: a consumer must be free to hold a different version of any of them.
FORBIDDEN_TOP_LEVEL_IMPORTS = frozenset(
    {"mcp", "mcp_types", "httpx", "httpx2", "pydantic", "anyio"}
)

# The single module §4 places inside the boundary. Adding a name here is a
# security-boundary change and needs the §12 release-gate review.
SDK_MODULES = frozenset({"transport.py"})

PACKAGE_ROOT = Path(rh_mcp.__file__).parent
MODULE_PATHS = sorted(PACKAGE_ROOT.rglob("*.py"))
MODULE_IDS = [str(path.relative_to(PACKAGE_ROOT)) for path in MODULE_PATHS]


def _imported_top_level_modules(source: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def _module_for(path: Path) -> Any:
    relative = path.relative_to(PACKAGE_ROOT).with_suffix("")
    parts = [part for part in relative.parts if part != "__init__"]
    return importlib.import_module(".".join(["rh_mcp", *parts]) if parts else "rh_mcp")


def test_discovery_found_the_package_modules() -> None:
    """Guard against every sweep below passing because it found nothing."""
    assert {
        "__init__.py",
        "canonical.py",
        "config.py",
        "errors.py",
        "manifest.py",
        "models.py",
        "schema.py",
        "transport.py",
        "validation.py",
    } <= set(MODULE_IDS)


# --------------------------------------------------------------------------
# 1. Import containment
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", MODULE_PATHS, ids=MODULE_IDS)
def test_only_the_transport_imports_the_sdk(path: Path) -> None:
    imported = _imported_top_level_modules(path.read_text(encoding="utf-8"))
    forbidden = imported & FORBIDDEN_TOP_LEVEL_IMPORTS
    if str(path.relative_to(PACKAGE_ROOT)) in SDK_MODULES:
        return
    assert not forbidden, f"{path.name} imports {sorted(forbidden)}"


@pytest.mark.parametrize("path", MODULE_PATHS, ids=MODULE_IDS)
def test_no_module_imports_a_third_party_package_outside_the_sdk(path: Path) -> None:
    """Nothing but the reviewed SDK dependencies, anywhere (§12)."""
    imported = _imported_top_level_modules(path.read_text(encoding="utf-8"))
    third_party = imported - sys.stdlib_module_names - {"rh_mcp"}
    if str(path.relative_to(PACKAGE_ROOT)) in SDK_MODULES:
        third_party -= FORBIDDEN_TOP_LEVEL_IMPORTS
    assert not third_party


def test_the_transport_really_does_import_the_sdk() -> None:
    """Otherwise the allowlist above would be vacuous."""
    imported = _imported_top_level_modules(
        (PACKAGE_ROOT / "transport.py").read_text(encoding="utf-8")
    )
    assert {"mcp", "httpx2"} <= imported


# --------------------------------------------------------------------------
# 2. Annotation inspection
# --------------------------------------------------------------------------


def _annotation_sources(annotation: Any, seen: set[int] | None = None) -> set[str]:
    """Every top-level package an annotation and its arguments come from."""
    seen = set() if seen is None else seen
    if id(annotation) in seen:
        return set()
    seen.add(id(annotation))

    packages: set[str] = set()
    module = getattr(annotation, "__module__", None)
    if isinstance(module, str):
        packages.add(module.split(".")[0])
    for argument in typing.get_args(annotation):
        packages |= _annotation_sources(argument, seen)
    return packages


def _public_members(module: Any) -> list[tuple[str, Any]]:
    exported = getattr(module, "__all__", None)
    names = (
        list(exported)
        if exported is not None
        else [name for name in vars(module) if not name.startswith("_")]
    )
    members: list[tuple[str, Any]] = []
    for name in names:
        value = getattr(module, name, None)
        if value is None or getattr(value, "__module__", None) != module.__name__:
            continue
        members.append((name, value))
    return members


def _annotations_of(name: str, value: Any) -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    targets: list[tuple[str, Any]] = [(name, value)]
    if inspect.isclass(value):
        if is_dataclass(value):
            for field in fields(value):
                found.append((f"{name}.{field.name}", field.type))
        for attribute, member in vars(value).items():
            if attribute.startswith("_") or not callable(member):
                continue
            targets.append((f"{name}.{attribute}", member))
    for label, target in targets:
        if not callable(target):
            continue
        try:
            hints = typing.get_type_hints(target)
        except Exception:  # noqa: BLE001 - an unresolvable hint is checked as text
            raw = getattr(target, "__annotations__", {})
            found.extend((f"{label}:{key}", text) for key, text in raw.items())
            continue
        found.extend((f"{label}:{key}", hint) for key, hint in hints.items())
    return found


@pytest.mark.parametrize("path", MODULE_PATHS, ids=MODULE_IDS)
def test_no_public_annotation_names_an_sdk_type(path: Path) -> None:
    module = _module_for(path)
    for name, value in _public_members(module):
        for label, annotation in _annotations_of(name, value):
            if isinstance(annotation, str):
                for package in FORBIDDEN_TOP_LEVEL_IMPORTS:
                    assert package not in annotation, f"{module.__name__}.{label}"
                continue
            leaked = _annotation_sources(annotation) & FORBIDDEN_TOP_LEVEL_IMPORTS
            assert not leaked, f"{module.__name__}.{label} is annotated with {sorted(leaked)}"


def test_the_annotation_sweep_can_actually_detect_a_leak() -> None:
    """A mutation guard for the check above.

    The sweep resolves string annotations, so a version of it that only read
    `__annotations__` literally would pass on this signature. This proves it
    does not.
    """

    def leaky(client: httpx2.AsyncClient) -> None: ...

    leaked = set()
    for _, annotation in _annotations_of("leaky", leaky):
        leaked |= _annotation_sources(annotation) & FORBIDDEN_TOP_LEVEL_IMPORTS
    assert leaked == {"httpx2"}


@pytest.mark.parametrize("path", MODULE_PATHS, ids=MODULE_IDS)
def test_no_sdk_symbol_is_reachable_as_a_public_module_attribute(path: Path) -> None:
    """`__all__` is not the boundary; the names bound in the module are.

    `__all__` governs `from ... import *` and nothing else, so
    `from rh_mcp.transport import stdio_client` would still have worked while
    every §4 test passed — and that name's annotations are `mcp.*` types,
    which is the literal thing §4 forbids. Binding every SDK import to a
    private name closes it by construction. This sweep is what keeps it
    closed: it looks at what the module actually holds, not at what it says it
    exports.
    """
    module = _module_for(path)
    for name, value in vars(module).items():
        if name.startswith("_"):
            continue
        origin = getattr(value, "__module__", None)
        if not isinstance(origin, str):
            # A module object rather than a class or function, e.g. a stray
            # `import httpx2`. Its own name is what identifies it.
            origin = getattr(value, "__name__", "")
        assert origin.split(".")[0] not in FORBIDDEN_TOP_LEVEL_IMPORTS, (
            f"{module.__name__}.{name} exposes an SDK symbol as a public attribute"
        )


def test_that_sweep_would_have_caught_the_unaliased_imports() -> None:
    """A mutation guard: prove the check above is not vacuous.

    Re-binds the SDK names the way the module had them before aliasing and
    confirms the same predicate rejects them. Without this, the sweep passing
    would be indistinguishable from the sweep finding nothing to look at.
    """
    import types

    import mcp

    pretend = types.ModuleType("pretend")
    pretend.stdio_client = mcp.stdio_client  # type: ignore[attr-defined]
    pretend.httpx2 = httpx2  # type: ignore[attr-defined]

    leaked = set()
    for name, value in vars(pretend).items():
        if name.startswith("_"):
            continue
        origin = getattr(value, "__module__", None)
        if not isinstance(origin, str):
            origin = getattr(value, "__name__", "")
        package = origin.split(".")[0]
        if package in FORBIDDEN_TOP_LEVEL_IMPORTS:
            leaked.add(name)
    assert leaked == {"stdio_client", "httpx2"}


def test_the_transport_keeps_its_sdk_typed_helpers_private() -> None:
    """Named explicitly, because these are the ones that would leak first."""
    import rh_mcp.transport as transport

    for name in (
        "_GuardedAsyncTransport",
        "_EgressPolicy",
        "_build_http_client",
        "_new_base_transport",
        "_CappedStream",
        "_open_over_connector",
    ):
        assert hasattr(transport, name)
        assert name.startswith("_")
        assert name not in transport.__all__


# --------------------------------------------------------------------------
# 3. Import isolation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module", ["rh_mcp", "rh_mcp.models", "rh_mcp.errors", "rh_mcp.manifest", "rh_mcp.config"]
)
def test_importing_a_public_module_does_not_load_the_sdk(module: str) -> None:
    """The property a consumer on another MCP major version relies on."""
    script = (
        f"import {module}, sys;"
        "leaked = sorted(n for n in sys.modules if n.split('.')[0] in "
        "{'mcp', 'mcp_types', 'httpx2', 'pydantic'});"
        "print(leaked)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )
    assert completed.stdout.strip() == "[]", completed.stdout


# --------------------------------------------------------------------------
# 4. Exports and exceptions
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", MODULE_PATHS, ids=MODULE_IDS)
def test_no_module_re_exports_an_sdk_name(path: Path) -> None:
    module = _module_for(path)
    for name in getattr(module, "__all__", []):
        value = getattr(module, name)
        origin = getattr(value, "__module__", module.__name__)
        assert origin.split(".")[0] not in FORBIDDEN_TOP_LEVEL_IMPORTS, name


def test_every_public_exception_type_is_the_packages_own() -> None:
    """§4: an SDK exception must not reach a consumer through this package."""
    from rh_mcp.errors import GatewayError

    for path in MODULE_PATHS:
        module = _module_for(path)
        for name, value in _public_members(module):
            if inspect.isclass(value) and issubclass(value, BaseException):
                assert issubclass(value, GatewayError), f"{module.__name__}.{name}"
