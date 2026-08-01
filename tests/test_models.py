import ast
import inspect
from dataclasses import FrozenInstanceError

import pytest

import rh_mcp.models as models_module
from rh_mcp.models import Readiness, ResultEnvelope

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def _imported_top_level_modules(module: object) -> set[str]:
    tree = ast.parse(inspect.getsource(module))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_models_module_has_no_sdk_dependency() -> None:
    imported = _imported_top_level_modules(models_module)
    assert "mcp" not in imported
    assert "httpx2" not in imported


class TestReadiness:
    def test_ready_true_requires_matching_digests(self) -> None:
        readiness = Readiness(
            ready=True,
            manifest_version="v1",
            manifest_digest=DIGEST_A,
            expected_manifest_digest=DIGEST_A,
        )
        assert readiness.ready is True

    def test_ready_true_with_mismatched_digests_rejected(self) -> None:
        with pytest.raises(ValueError, match="ready cannot be True"):
            Readiness(
                ready=True,
                manifest_version="v1",
                manifest_digest=DIGEST_A,
                expected_manifest_digest=DIGEST_B,
            )

    def test_ready_false_with_mismatched_digests_allowed(self) -> None:
        readiness = Readiness(
            ready=False,
            manifest_version="v1",
            manifest_digest=DIGEST_A,
            expected_manifest_digest=DIGEST_B,
        )
        assert readiness.ready is False

    def test_immutable(self) -> None:
        readiness = Readiness(
            ready=True,
            manifest_version="v1",
            manifest_digest=DIGEST_A,
            expected_manifest_digest=DIGEST_A,
        )
        with pytest.raises(FrozenInstanceError):
            readiness.ready = False  # type: ignore[misc]

    def test_to_json_dict_shape(self) -> None:
        readiness = Readiness(
            ready=True,
            manifest_version="v1",
            manifest_digest=DIGEST_A,
            expected_manifest_digest=DIGEST_A,
        )
        assert readiness.to_json_dict() == {
            "ready": True,
            "manifest_version": "v1",
            "manifest_digest": DIGEST_A,
            "expected_manifest_digest": DIGEST_A,
        }

    @pytest.mark.parametrize("bad_digest", ["", "sha256:short", "md5:" + "a" * 64, "not-a-digest"])
    def test_rejects_malformed_digest(self, bad_digest: str) -> None:
        with pytest.raises(ValueError):
            Readiness(
                ready=False,
                manifest_version="v1",
                manifest_digest=bad_digest,
                expected_manifest_digest=DIGEST_A,
            )

    def test_rejects_empty_manifest_version(self) -> None:
        with pytest.raises(ValueError):
            Readiness(
                ready=False,
                manifest_version="",
                manifest_digest=DIGEST_A,
                expected_manifest_digest=DIGEST_A,
            )


class TestResultEnvelope:
    def _make(self, **overrides: object) -> ResultEnvelope:
        fields = {
            "manifest_version": "v1",
            "manifest_digest": DIGEST_A,
            "capability": "get_positions",
            "schema_digest": DIGEST_A,
            "result_digest": DIGEST_A,
            "observed_at": "2024-01-01T00:00:00+00:00",
            "data": {"key": "value"},
        }
        fields.update(overrides)
        return ResultEnvelope(**fields)  # type: ignore[arg-type]

    def test_envelope_version_is_fixed(self) -> None:
        envelope = self._make()
        assert envelope.envelope_version == "1.0"

    def test_envelope_version_not_a_constructor_arg(self) -> None:
        with pytest.raises(TypeError):
            self._make(envelope_version="2.0")

    def test_immutable(self) -> None:
        envelope = self._make()
        with pytest.raises(FrozenInstanceError):
            envelope.capability = "other"  # type: ignore[misc]

    def test_to_json_dict_shape(self) -> None:
        envelope = self._make(warnings=("careful",))
        assert envelope.to_json_dict() == {
            "envelope_version": "1.0",
            "manifest_version": "v1",
            "manifest_digest": DIGEST_A,
            "capability": "get_positions",
            "schema_digest": DIGEST_A,
            "result_digest": DIGEST_A,
            "observed_at": "2024-01-01T00:00:00+00:00",
            "data": {"key": "value"},
            "warnings": ["careful"],
        }

    def test_accepts_zulu_suffix_timestamp(self) -> None:
        envelope = self._make(observed_at="2024-01-01T00:00:00Z")
        assert envelope.observed_at == "2024-01-01T00:00:00Z"

    def test_rejects_non_utc_timestamp(self) -> None:
        with pytest.raises(ValueError):
            self._make(observed_at="2024-01-01T00:00:00+05:00")

    def test_rejects_naive_timestamp(self) -> None:
        with pytest.raises(ValueError):
            self._make(observed_at="2024-01-01T00:00:00")

    def test_rejects_empty_capability(self) -> None:
        with pytest.raises(ValueError):
            self._make(capability="")

    def test_rejects_malformed_digest(self) -> None:
        with pytest.raises(ValueError):
            self._make(schema_digest="not-a-digest")
