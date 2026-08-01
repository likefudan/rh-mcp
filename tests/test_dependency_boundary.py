"""DESIGN.md §4/§11: no MCP SDK or HTTP client type may be public.

Step 1 has no transport yet, so the check that can be made now is the import
boundary: nothing in the package may import `mcp` or `httpx2` at all. The test
walks every module in `src/rh_mcp` rather than a hand-listed subset, so a later
module cannot quietly opt out of the boundary.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

import rh_mcp

FORBIDDEN_TOP_LEVEL_IMPORTS = frozenset({"mcp", "httpx", "httpx2"})

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


def test_discovery_found_the_package_modules() -> None:
    """Guard against the sweep below passing because it found nothing."""
    assert {"__init__.py", "config.py", "errors.py", "models.py"} <= set(MODULE_IDS)


@pytest.mark.parametrize("path", MODULE_PATHS, ids=MODULE_IDS)
def test_module_has_no_sdk_dependency(path: Path) -> None:
    imported = _imported_top_level_modules(path.read_text(encoding="utf-8"))
    assert not (imported & FORBIDDEN_TOP_LEVEL_IMPORTS)


@pytest.mark.parametrize("path", MODULE_PATHS, ids=MODULE_IDS)
def test_module_has_no_runtime_dependency_outside_the_stdlib(path: Path) -> None:
    """Step 1 is stdlib-only and offline (DESIGN.md §14)."""
    imported = _imported_top_level_modules(path.read_text(encoding="utf-8"))
    third_party = imported - sys.stdlib_module_names - {"rh_mcp"}
    assert not third_party
