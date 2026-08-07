"""CLI stream discipline and exit codes (§7.2, §7.3, §11).

Two properties matter here and they are the ones a consumer depends on:

* stdout carries a complete structured payload or nothing at all;
* the exit code comes from the single mapping in `errors.py`, not a second one.

Every test drives `main()` with injected streams, so nothing touches a real
credential store, a real network, or the developer's terminal.
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

import rh_mcp.cli as cli
from rh_mcp.errors import (
    EXIT_CODE_AUTH_REQUIRED,
    EXIT_CODE_CONFIGURATION_ERROR,
    EXIT_CODE_PROVIDER_FAILURE,
    EXIT_CODE_SUCCESS,
    EXIT_CODE_USAGE_ERROR,
    ErrorCode,
    GatewayError,
)

DIGEST = "sha256:" + "a" * 64


@pytest.fixture(autouse=True)
def production_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RH_MCP_EXPECTED_MANIFEST_DIGEST", DIGEST)
    monkeypatch.delenv("RH_MCP_MODE", raising=False)


def invoke(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


class TestNoEscapeHatch:
    """§7.2: no `call` command, no flag that relaxes enforcement."""

    def test_there_is_no_call_command(self) -> None:
        code, out, err = invoke(["call", "anything"])
        assert code == EXIT_CODE_USAGE_ERROR
        assert out == ""

    def test_no_flag_mentions_disabling_or_skipping_enforcement(self) -> None:
        help_text = cli.build_parser().format_help()
        for option in ["--no-manifest", "--unsafe", "--force", "--allow-any-tool"]:
            assert option not in help_text

    def test_the_command_set_is_exactly_what_the_design_lists(self) -> None:
        assert set(cli._COMMANDS) == {
            "login",
            "logout",
            "auth-status",
            "status",
            "capabilities",
            "read",
            "admin-discover",
        }


class TestFailuresEmitNothingToStdout:
    """§7.2: a consumer that reads a byte from stdout read a success."""

    @pytest.mark.parametrize(
        ("code", "expected_exit"),
        [
            (ErrorCode.AUTH_REQUIRED, EXIT_CODE_AUTH_REQUIRED),
            (ErrorCode.NOT_READY, EXIT_CODE_CONFIGURATION_ERROR),
            (ErrorCode.CONFIGURATION_ERROR, EXIT_CODE_CONFIGURATION_ERROR),
            (ErrorCode.CAPABILITY_DENIED, EXIT_CODE_USAGE_ERROR),
            (ErrorCode.INPUT_INVALID, EXIT_CODE_USAGE_ERROR),
            (ErrorCode.PROVIDER_ERROR, EXIT_CODE_PROVIDER_FAILURE),
            (ErrorCode.PROTOCOL_ERROR, EXIT_CODE_PROVIDER_FAILURE),
            (ErrorCode.TIMEOUT, EXIT_CODE_PROVIDER_FAILURE),
            (ErrorCode.RESPONSE_TOO_LARGE, EXIT_CODE_PROVIDER_FAILURE),
        ],
    )
    def test_every_error_code_maps_through_the_single_table(
        self, monkeypatch: pytest.MonkeyPatch, code: ErrorCode, expected_exit: int
    ) -> None:
        async def failing(*_: Any, **__: Any) -> int:
            raise GatewayError(code, "a safe message")

        monkeypatch.setitem(cli._COMMANDS, "capabilities", failing)
        exit_code, out, err = invoke(["capabilities"])
        assert exit_code == expected_exit
        assert out == ""
        assert "a safe message" in err

    # Golden fixture (DESIGN.md §7.3, §12.5). §12.5 names the CLI's stderr line
    # as one of the two places a consumer meets an error's **wire string**, so
    # the line has to be pinned here, in `cli.py`'s own tests, and not inferred.
    #
    # Nothing pinned it before. An independent review rewrote `cli.py`'s error
    # line to `f"{PROGRAM} error [{exc.code.name}]: {exc.message}"` — changing
    # the format *and* emitting `CAPABILITY_DENIED` where a consumer had been
    # promised `capability_denied` — and the whole suite stayed green. The
    # fixture in `tests/test_errors.py` asserts `str(ErrorCode.X) == "x"`, which
    # is a property of `StrEnum`, not evidence that this module puts that string
    # on stderr. Asserting the adjacent property is the §12.1 `TestNoEscapeHatch`
    # defect, and it does not stop being that because the claim it defends is
    # one paragraph away.
    _EXPECTED_STDERR_LINES: dict[ErrorCode, str] = {
        ErrorCode.AUTH_REQUIRED: "rh-mcp: auth_required: a safe message",
        ErrorCode.NOT_READY: "rh-mcp: not_ready: a safe message",
        ErrorCode.CAPABILITY_DENIED: "rh-mcp: capability_denied: a safe message",
        ErrorCode.INPUT_INVALID: "rh-mcp: input_invalid: a safe message",
        ErrorCode.PROVIDER_ERROR: "rh-mcp: provider_error: a safe message",
        ErrorCode.TIMEOUT: "rh-mcp: timeout: a safe message",
        ErrorCode.RESPONSE_TOO_LARGE: "rh-mcp: response_too_large: a safe message",
        ErrorCode.PROTOCOL_ERROR: "rh-mcp: protocol_error: a safe message",
        ErrorCode.CONFIGURATION_ERROR: "rh-mcp: configuration_error: a safe message",
    }

    def test_the_stderr_error_line_carries_the_wire_string_verbatim(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§12.5: `rh-mcp: <code>: <message>`, with `<code>` the wire string."""
        assert set(self._EXPECTED_STDERR_LINES) == set(ErrorCode)
        for code, expected_line in self._EXPECTED_STDERR_LINES.items():

            async def failing(*_: Any, __code: ErrorCode = code, **___: Any) -> int:
                raise GatewayError(__code, "a safe message")

            monkeypatch.setitem(cli._COMMANDS, "capabilities", failing)
            _, out, err = invoke(["capabilities"])
            assert out == ""
            # The first line exactly. `auth_required` adds a second pointing at
            # `rh-mcp login`, which the test below covers.
            assert err.splitlines()[0] == expected_line

    def test_auth_required_points_at_login(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def failing(*_: Any, **__: Any) -> int:
            raise GatewayError(ErrorCode.AUTH_REQUIRED, "credential expired")

        monkeypatch.setitem(cli._COMMANDS, "capabilities", failing)
        exit_code, out, err = invoke(["capabilities"])
        assert exit_code == EXIT_CODE_AUTH_REQUIRED
        assert "rh-mcp login" in err
        assert out == ""

    def test_a_mismatched_pin_still_lists_but_says_so(self) -> None:
        """§7.1: the listing is of the committed manifest, not a permission grant.

        `capabilities` reports what the installed manifest says and stays exit
        0 — making it fail under a mismatch would break the command that best
        explains a mismatch — but it must not let a reader mistake the listing
        for a statement about what is currently permitted.
        """
        exit_code, out, err = invoke(["capabilities"])
        assert exit_code == EXIT_CODE_SUCCESS
        payload = json.loads(out)
        assert payload["digest_matches"] is False
        assert payload["expected_manifest_digest"] == DIGEST
        assert "not the one this deployment pinned" in err

    def test_a_missing_expected_digest_is_a_configuration_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("RH_MCP_EXPECTED_MANIFEST_DIGEST", raising=False)
        exit_code, out, err = invoke(["capabilities"])
        assert exit_code == EXIT_CODE_CONFIGURATION_ERROR
        assert out == ""

    # Golden fixture (DESIGN.md §7.2, §12.5): the JSON `rh-mcp capabilities`
    # actually writes to stdout, read back off the stream.
    #
    # `tests/test_gateway.py` pins `CapabilityDescription.to_json_dict`, which
    # is the object this command serializes — not what it emits. `_cmd_capabilities`
    # builds its top-level dict inline, so that fixture reached the list entries
    # and nothing reached the four keys around them. An independent review added
    # a fifth top-level key, and renamed `manifest_version`/`manifest_digest` to
    # `mv`/`md`, and got 1184 passing both times with the CLI demonstrably
    # emitting the renamed keys.
    #
    # That is the third appearance in this change of the rule §12.5 states: pin
    # the surface the promise names, not the type behind it. Round 1 caught it in
    # the stderr line; fixing that one and then pinning the object the CLI
    # serializes reproduced it one layer up. The lesson that generalises is that
    # "the serialized type is pinned" and "the emitted payload is pinned" are
    # different claims whenever a caller assembles a payload around the type.
    _EXPECTED_CAPABILITIES_STDOUT_KEYS: frozenset[str] = frozenset(
        {
            "manifest_version",
            "manifest_digest",
            "expected_manifest_digest",
            "digest_matches",
            "capabilities",
        }
    )
    _EXPECTED_CAPABILITY_ENTRY_KEYS: frozenset[str] = frozenset(
        {
            "capability",
            "allowed",
            "mutates",
            "description",
            "schema_digest",
            "rationale",
            "input_schema",
        }
    )

    def test_the_capabilities_stdout_key_set_is_pinned_in_both_directions(self) -> None:
        """§12.5: what the command writes, not what the dataclass renders."""
        exit_code, out, _ = invoke(["capabilities"])
        assert exit_code == EXIT_CODE_SUCCESS
        payload = json.loads(out)
        assert set(payload) == self._EXPECTED_CAPABILITIES_STDOUT_KEYS
        assert payload["capabilities"]
        for entry in payload["capabilities"]:
            assert set(entry) == self._EXPECTED_CAPABILITY_ENTRY_KEYS
            # §2.1: the 1.1 spelling must not reappear on a listing where 11
            # allowed capabilities write.
            assert "read_allowed" not in entry


class TestInputParsing:
    @pytest.mark.parametrize("raw", ["not json", "[1,2]", '"a string"', "7"])
    def test_input_must_be_a_json_object(self, raw: str) -> None:
        with pytest.raises(GatewayError) as excinfo:
            cli._parse_input(raw)
        assert excinfo.value.code is ErrorCode.INPUT_INVALID

    def test_absent_input_is_an_empty_object(self) -> None:
        assert cli._parse_input(None) == {}

    def test_a_valid_object_round_trips(self) -> None:
        assert cli._parse_input('{"a": 1}') == {"a": 1}

    def test_a_bad_input_never_reaches_stdout(self) -> None:
        exit_code, out, err = invoke(["read", "alpha_reading", "--input", "not json"])
        assert exit_code == EXIT_CODE_USAGE_ERROR
        assert out == ""


class TestLogoutConfirmation:
    """§5.2: deleting a credential needs explicit consent."""

    def test_refuses_without_a_terminal_and_without_yes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class NotATty(io.StringIO):
            def isatty(self) -> bool:
                return False

        monkeypatch.setattr(cli.sys, "stdin", NotATty("y\n"))
        exit_code, out, err = invoke(["logout"])
        assert exit_code == EXIT_CODE_USAGE_ERROR
        assert out == ""
        assert "interactive confirmation" in err

    @pytest.mark.parametrize("answer", ["n", "no", "", "maybe", "Y E S", "yes please"])
    def test_only_an_exact_yes_confirms(self, answer: str) -> None:
        class Tty(io.StringIO):
            def isatty(self) -> bool:
                return True

        err = io.StringIO()
        assert cli._confirm("delete?", err, Tty(answer + "\n")) is False

    @pytest.mark.parametrize("answer", ["y", "yes", "YES", " Yes "])
    def test_accepted_confirmations(self, answer: str) -> None:
        class Tty(io.StringIO):
            def isatty(self) -> bool:
                return True

        err = io.StringIO()
        assert cli._confirm("delete?", err, Tty(answer + "\n")) is True

    def test_the_prompt_goes_to_stderr_not_stdout(self) -> None:
        class Tty(io.StringIO):
            def isatty(self) -> bool:
                return True

        err = io.StringIO()
        cli._confirm("delete the credential?", err, Tty("n\n"))
        assert "delete the credential?" in err.getvalue()


class TestSuccessfulOutputIsParseable:
    def test_stdout_is_exactly_one_json_document(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def succeeding(_: Any, out: Any, err: Any) -> int:
            err.write("a diagnostic that must not pollute stdout\n")
            cli._emit({"ok": True, "nested": {"a": [1, 2]}}, out)
            return 0

        monkeypatch.setitem(cli._COMMANDS, "capabilities", succeeding)
        exit_code, out, err = invoke(["capabilities"])
        assert exit_code == EXIT_CODE_SUCCESS
        assert json.loads(out) == {"ok": True, "nested": {"a": [1, 2]}}
        assert "diagnostic" in err
        assert "diagnostic" not in out


class TestUsageErrors:
    def test_no_command_is_a_usage_error(self) -> None:
        exit_code, out, _ = invoke([])
        assert exit_code == EXIT_CODE_USAGE_ERROR
        assert out == ""

    def test_an_unknown_command_is_a_usage_error(self) -> None:
        exit_code, out, _ = invoke(["nonsense"])
        assert exit_code == EXIT_CODE_USAGE_ERROR
        assert out == ""

    def test_admin_requires_a_subcommand(self) -> None:
        exit_code, out, _ = invoke(["admin"])
        assert exit_code == EXIT_CODE_USAGE_ERROR
        assert out == ""


class TestStatusHonoursTheOriginatingErrorCode:
    """§7.3: an expired credential must reach exit 4, not a generic not-ready.

    `DriftFinding.error_code` was added in step 2 for exactly this mapping.
    Reporting an auth failure as not-ready sends an operator hunting manifest
    drift when the answer is `rh-mcp login`.

    These drive the real `_cmd_status` with `open_gateway` replaced, rather
    than re-implementing its body — a test that restates the code it checks
    would pass even if that code were deleted.
    """

    def _run_status(
        self, monkeypatch: pytest.MonkeyPatch, code: ErrorCode | None
    ) -> tuple[int, str, str]:
        import contextlib

        from rh_mcp.manifest import DriftFinding, DriftReason, ReadinessAssessment
        from rh_mcp.models import Readiness

        findings = (
            (DriftFinding(DriftReason.DISCOVERY_FAILED, "provider discovery failed", code),)
            if code is not None
            else (DriftFinding(DriftReason.UNKNOWN_PROVIDER_TOOL, "an unreviewed tool"),)
        )
        assessment = ReadinessAssessment(
            readiness=Readiness(
                ready=False,
                manifest_version="v1",
                manifest_digest="sha256:" + "d" * 64,
                expected_manifest_digest=DIGEST,
            ),
            findings=findings,
        )

        class FakeGateway:
            async def readiness(self) -> ReadinessAssessment:
                return assessment

        @contextlib.asynccontextmanager
        async def fake_open(*_: Any, **__: Any) -> Any:
            yield FakeGateway()

        monkeypatch.setattr(cli, "open_gateway", fake_open)
        return invoke(["status", "--skip-metadata-check"])

    def test_auth_required_during_discovery_exits_four(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        code, out, err = self._run_status(monkeypatch, ErrorCode.AUTH_REQUIRED)
        assert code == EXIT_CODE_AUTH_REQUIRED
        assert "rh-mcp login" in err
        assert json.loads(out)["ready"] is False

    def test_a_provider_failure_exits_one(self, monkeypatch: pytest.MonkeyPatch) -> None:
        code, _, _ = self._run_status(monkeypatch, ErrorCode.PROVIDER_ERROR)
        assert code == EXIT_CODE_PROVIDER_FAILURE

    def test_plain_drift_still_exits_three(self, monkeypatch: pytest.MonkeyPatch) -> None:
        code, out, err = self._run_status(monkeypatch, None)
        assert code == EXIT_CODE_CONFIGURATION_ERROR
        assert "rh-mcp login" not in err
        assert json.loads(out)["ready"] is False

    # Golden fixture (DESIGN.md §7.1, §7.2, §12.5): the JSON `rh-mcp status`
    # writes to stdout, read back off the stream.
    #
    # `tests/test_manifest.py` pins `ReadinessAssessment.to_json_dict`, which is
    # what this command serializes. `_cmd_status` is a one-line `_emit` today, so
    # the two shapes coincide — but that is a property of `cli.py`, not of the
    # assessment, and it is exactly what `_cmd_capabilities` does *not* do. An
    # independent review added a top-level key at the `_emit` call and got 1184
    # passing. §12.5 promises this payload's shape to a consumer, and a payload
    # with no `envelope_version` of its own has nothing else that would notice.
    _EXPECTED_STATUS_STDOUT_KEYS: frozenset[str] = frozenset(
        {
            "ready",
            "manifest_version",
            "manifest_digest",
            "expected_manifest_digest",
            "findings",
        }
    )
    _EXPECTED_STATUS_FINDING_KEYS: frozenset[str] = frozenset({"reason", "detail", "error_code"})

    def test_the_status_stdout_key_set_is_pinned_in_both_directions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§12.5: what the command writes, not what the dataclass renders."""
        _, out, _ = self._run_status(monkeypatch, ErrorCode.AUTH_REQUIRED)
        payload = json.loads(out)
        assert set(payload) == self._EXPECTED_STATUS_STDOUT_KEYS
        assert payload["findings"]
        for finding in payload["findings"]:
            assert set(finding) == self._EXPECTED_STATUS_FINDING_KEYS


class TestLogoutAsksBeforeItPrepares:
    """Consent comes before any setup that can fail for unrelated reasons.

    CI caught the original ordering: `open_credential_store` ran first, and on
    a host without a keychain it raised before the prompt was ever reached, so
    the refusal a user saw had nothing to do with what they were asked.
    """

    def test_the_store_is_not_opened_before_confirmation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened: list[Any] = []

        def spy_open(*args: Any, **kwargs: Any) -> Any:
            opened.append(args)
            raise AssertionError("the credential store must not be opened before consent")

        class NotATty(io.StringIO):
            def isatty(self) -> bool:
                return False

        monkeypatch.setattr(cli, "open_credential_store", spy_open)
        monkeypatch.setattr(cli.sys, "stdin", NotATty(""))
        exit_code, out, err = invoke(["logout"])
        assert exit_code == EXIT_CODE_USAGE_ERROR
        assert opened == []
        assert out == ""

    def test_a_declined_confirmation_opens_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened: list[Any] = []

        class Tty(io.StringIO):
            def isatty(self) -> bool:
                return True

        monkeypatch.setattr(cli, "open_credential_store", lambda *a, **k: opened.append(a))
        monkeypatch.setattr(cli.sys, "stdin", Tty("n\n"))
        exit_code, out, _ = invoke(["logout"])
        assert exit_code == EXIT_CODE_USAGE_ERROR
        assert opened == []
        assert out == ""


class TestCapabilitiesNeedsNoCredential:
    """It reads a file inside the package (§7.2).

    CI caught the original: `capabilities` went through `open_gateway`, which
    opens a credential store before anything else, so on a host without a
    keychain the command failed with a configuration error while the manifest
    sat right there readable. The local suite could not see it — macOS has a
    keychain — which is the same shape as the logout ordering defect.
    """

    def test_no_credential_store_is_opened(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def explode(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("capabilities must not open a credential store")

        monkeypatch.setattr(cli, "open_credential_store", explode)
        exit_code, out, _ = invoke(["capabilities"])
        assert exit_code == EXIT_CODE_SUCCESS
        assert json.loads(out)["capabilities"]

    def test_no_session_is_opened(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def explode(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("capabilities must not open a provider session")

        monkeypatch.setattr(cli, "open_gateway", explode)
        exit_code, out, _ = invoke(["capabilities"])
        assert exit_code == EXIT_CODE_SUCCESS
        assert json.loads(out)["capabilities"]
