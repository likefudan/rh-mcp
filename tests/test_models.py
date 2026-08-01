import json
from dataclasses import FrozenInstanceError

import pytest

from rh_mcp.errors import (
    EXIT_CODE_CONFIGURATION_ERROR,
    EXIT_CODE_PROVIDER_FAILURE,
    ErrorCode,
    GatewayError,
    exit_code_for,
)
from rh_mcp.models import Readiness, ResultEnvelope, is_digest

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class TestIsDigest:
    @pytest.mark.parametrize("value", [DIGEST_A, "sha256:" + "0123456789abcdef" * 4])
    def test_accepts_exact_form(self, value: str) -> None:
        assert is_digest(value)

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "sha256:short",
            "md5:" + "a" * 64,
            "not-a-digest",
            "sha256:" + "a" * 63,
            "sha256:" + "a" * 65,
            "sha256:" + "A" * 64,
            "SHA256:" + "a" * 64,
            "sha256:" + "a" * 64 + "\n",
            "sha256:" + "a" * 64 + "\n\n",
            "\nsha256:" + "a" * 64,
            " sha256:" + "a" * 64 + " ",
            "sha256:" + "a" * 64 + "\nsha256:" + "b" * 64,
        ],
    )
    def test_rejects_anything_else(self, value: str) -> None:
        assert not is_digest(value)


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
        with pytest.raises(GatewayError, match="ready cannot be True"):
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

    @pytest.mark.parametrize(
        "bad_digest",
        ["", "sha256:short", "md5:" + "a" * 64, "not-a-digest", DIGEST_A + "\n"],
    )
    def test_rejects_malformed_digest(self, bad_digest: str) -> None:
        with pytest.raises(GatewayError) as excinfo:
            Readiness(
                ready=False,
                manifest_version="v1",
                manifest_digest=bad_digest,
                expected_manifest_digest=DIGEST_A,
            )
        assert excinfo.value.code is ErrorCode.NOT_READY

    def test_rejects_empty_manifest_version(self) -> None:
        with pytest.raises(GatewayError):
            Readiness(
                ready=False,
                manifest_version="",
                manifest_digest=DIGEST_A,
                expected_manifest_digest=DIGEST_A,
            )

    @pytest.mark.parametrize("truthy", [1, 0, "yes", None])
    def test_ready_must_be_a_bool(self, truthy: object) -> None:
        """§7.1 pins `ready` to a JSON boolean."""
        with pytest.raises(GatewayError):
            Readiness(
                ready=truthy,  # type: ignore[arg-type]
                manifest_version="v1",
                manifest_digest=DIGEST_A,
                expected_manifest_digest=DIGEST_A,
            )

    def test_validation_failures_use_the_public_error_contract(self) -> None:
        """§7.3: a public type must not leak a bare ValueError to the CLI."""
        with pytest.raises(GatewayError) as excinfo:
            Readiness(
                ready=False,
                manifest_version="v1",
                manifest_digest="nope",
                expected_manifest_digest=DIGEST_A,
            )
        assert excinfo.value.code is ErrorCode.NOT_READY
        assert excinfo.value.retryable is False

    def test_local_faults_land_in_the_configuration_exit_bucket(self) -> None:
        """§7.3: a mis-pinned digest is a local fault, not a provider failure.

        Exit 1 would send an operator to the "Robinhood had a transient
        failure, retry" runbook during precisely the §6.2 drift scenario that
        readiness exists to surface.
        """
        cases = [
            {"manifest_digest": DIGEST_A, "expected_manifest_digest": "bad"},
            {"manifest_digest": DIGEST_A, "expected_manifest_digest": DIGEST_B},
        ]
        for overrides in cases:
            with pytest.raises(GatewayError) as excinfo:
                Readiness(ready=True, manifest_version="v1", **overrides)  # type: ignore[arg-type]
            assert excinfo.value.code is ErrorCode.NOT_READY
            assert exit_code_for(excinfo.value) == EXIT_CODE_CONFIGURATION_ERROR


class TestResultEnvelope:
    def _make(self, **overrides: object) -> ResultEnvelope:
        fields: dict[str, object] = {
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
        with pytest.raises(GatewayError):
            self._make(observed_at="2024-01-01T00:00:00+05:00")

    def test_rejects_naive_timestamp(self) -> None:
        with pytest.raises(GatewayError):
            self._make(observed_at="2024-01-01T00:00:00")

    def test_rejects_empty_capability(self) -> None:
        with pytest.raises(GatewayError):
            self._make(capability="")

    def test_rejects_malformed_digest(self) -> None:
        with pytest.raises(GatewayError):
            self._make(schema_digest="not-a-digest")

    def test_rejects_digest_with_trailing_newline(self) -> None:
        with pytest.raises(GatewayError):
            self._make(result_digest=DIGEST_A + "\n")

    def test_rejects_non_mapping_data(self) -> None:
        with pytest.raises(GatewayError):
            self._make(data=[1, 2, 3])

    # §7.1: `result_digest` is computed over `data` before the envelope is
    # returned, so `data` must stop tracking the caller's object.
    def test_data_is_copied_at_construction(self) -> None:
        payload = {"positions": 1}
        envelope = self._make(data=payload)
        payload["positions"] = 999_999
        payload["injected"] = True  # type: ignore[assignment]
        assert envelope.to_json_dict()["data"] == {"positions": 1}
        assert dict(envelope.data) == {"positions": 1}

    def test_nested_data_is_copied_at_construction(self) -> None:
        payload = {"account": {"buying_power": 1}, "rows": [{"symbol": "AAPL"}]}
        envelope = self._make(data=payload)
        payload["account"]["buying_power"] = 999_999  # type: ignore[index]
        payload["rows"].append({"symbol": "INJECTED"})  # type: ignore[attr-defined]
        payload["rows"][0]["symbol"] = "TSLA"  # type: ignore[index]
        assert envelope.to_json_dict()["data"] == {
            "account": {"buying_power": 1},
            "rows": [{"symbol": "AAPL"}],
        }

    def test_data_is_not_mutable_through_the_envelope(self) -> None:
        envelope = self._make(data={"account": {"buying_power": 1}})
        with pytest.raises(TypeError):
            envelope.data["injected"] = True  # type: ignore[index]
        with pytest.raises(TypeError):
            envelope.data["account"]["buying_power"] = 2  # type: ignore[index]

    def test_to_json_dict_returns_a_detached_copy(self) -> None:
        envelope = self._make(data={"account": {"buying_power": 1}})
        rendered = envelope.to_json_dict()
        rendered["data"]["account"]["buying_power"] = 999_999
        assert envelope.to_json_dict()["data"] == {"account": {"buying_power": 1}}

    def test_warnings_are_copied_and_frozen(self) -> None:
        warnings = ["careful"]
        envelope = self._make(warnings=warnings)
        warnings.append("injected")
        assert envelope.warnings == ("careful",)

    def test_rejects_non_string_warning(self) -> None:
        with pytest.raises(GatewayError):
            self._make(warnings=(1,))

    def test_validation_failures_are_protocol_errors(self) -> None:
        """An envelope is assembled from provider-derived data (§7.1)."""
        with pytest.raises(GatewayError) as excinfo:
            self._make(schema_digest="not-a-digest")
        assert excinfo.value.code is ErrorCode.PROTOCOL_ERROR
        assert exit_code_for(excinfo.value) == EXIT_CODE_PROVIDER_FAILURE

    @pytest.mark.parametrize(
        "payload",
        [
            {"rows": {1, 2}},
            {"blob": bytearray(b"abc")},
            {"blob": b"abc"},
            {"when": object()},
            {"nested": {"rows": {1, 2}}},
            {"rows": [{"tags": {"a"}}]},
        ],
    )
    def test_rejects_non_json_value_types(self, payload: object) -> None:
        """Anything outside the JSON type set stays mutable by reference."""
        with pytest.raises(GatewayError) as excinfo:
            self._make(data=payload)
        assert excinfo.value.code is ErrorCode.PROTOCOL_ERROR

    @pytest.mark.parametrize("payload", [{1: "a"}, {("a", "b"): 1}, {None: 1}, {"ok": {2: "x"}}])
    def test_rejects_non_string_keys(self, payload: object) -> None:
        """`to_json_dict()` must stay serializable; a tuple key raises."""
        with pytest.raises(GatewayError):
            self._make(data=payload)

    def test_accepts_the_json_scalar_types(self) -> None:
        payload = {"s": "x", "i": 1, "f": 1.5, "t": True, "n": None, "l": [1, "a", None]}
        assert self._make(data=payload).to_json_dict()["data"] == payload

    def test_cyclic_payload_raises_the_public_error_not_recursionerror(self) -> None:
        payload: dict[str, object] = {}
        payload["self"] = payload
        with pytest.raises(GatewayError) as excinfo:
            self._make(data=payload)
        assert excinfo.value.code is ErrorCode.PROTOCOL_ERROR

    def test_deeply_nested_payload_raises_the_public_error(self) -> None:
        payload: dict[str, object] = {}
        cursor = payload
        for _ in range(5_000):
            child: dict[str, object] = {}
            cursor["next"] = child
            cursor = child
        with pytest.raises(GatewayError):
            self._make(data=payload)

    def test_rendered_payload_is_json_serializable(self) -> None:
        envelope = self._make(data={"rows": [{"symbol": "AAPL", "qty": 3}], "ok": True})
        assert json.loads(json.dumps(envelope.to_json_dict()))["data"] == {
            "rows": [{"symbol": "AAPL", "qty": 3}],
            "ok": True,
        }
