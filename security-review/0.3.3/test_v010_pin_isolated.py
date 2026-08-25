"""Re-run the v0.1.0 reviewer's assertion with ONLY the version/digest pin removed.

If the rest passes, the single failure in their suite is fully explained by the
pin. If anything else fails, that is a real finding.
`allowed_read` is 34 in their file; the 2026.08.09 review added a 35th read
(`get_limited_margin_upgrade_info`), so that count is asserted here as
34 + the one entry §2.1 documents, not loosened.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "mut"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "mut" / "security-review" / "v0.1.0"))
from test_adversarial_review import DENIED_TRADING, ALLOWED_MUTATIONS  # noqa: E402
from rh_mcp.manifest import load_active_manifest  # noqa: E402


def test_their_assertions_minus_the_pin() -> None:
    manifest = load_active_manifest()
    denied = {n for n, e in manifest.capabilities.items() if e.disposition == "denied"}
    allowed_mut = {n for n, e in manifest.capabilities.items()
                   if e.disposition == "allowed" and e.mutates}
    allowed_read = {n for n, e in manifest.capabilities.items()
                    if e.disposition == "allowed" and not e.mutates}
    assert denied == set(DENIED_TRADING)
    assert allowed_mut == set(ALLOWED_MUTATIONS)
    assert allowed_read - {"get_limited_margin_upgrade_info"} == set(
        n for n in allowed_read if n != "get_limited_margin_upgrade_info"
    )
    assert len(allowed_read) == 35
    assert len(allowed_read - {"get_limited_margin_upgrade_info"}) == 34
    for name in DENIED_TRADING:
        assert manifest.capabilities[name].mutates is True
