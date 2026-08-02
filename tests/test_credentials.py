"""The credential store and its adapters (DESIGN.md §5.2, §11).

No test here touches a real Keychain: the `security` runner is injected, and
the one test that proves the production adapter shells out at all asserts on
the *argv it would have used*. The file adapter runs against `tmp_path`.

The redaction tests are the ones to keep honest. They plant a known secret,
run it through every channel that has ever leaked one — `repr`, `str`,
f-strings, exception text, `logging` — and assert the string is absent. A test
that only checked `repr` would have passed on the account-id leak an earlier
review caught.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

import pytest

import rh_mcp.credentials as credentials
from rh_mcp.config import GatewayConfig, ResourceLimits
from rh_mcp.credentials import (
    ClientRegistration,
    CommandResult,
    FileCredentialStore,
    InMemoryCredentialStore,
    KeychainCredentialStore,
    TokenCredential,
    check_namespace,
    open_credential_store,
)
from rh_mcp.errors import ErrorCode, GatewayError

DIGEST = "sha256:" + "a" * 64

SECRET = "s3cr3t-access-token-DO-NOT-LEAK"
REFRESH = "s3cr3t-refresh-token-DO-NOT-LEAK"
CLIENT_ID = "s3cr3t-client-id-DO-NOT-LEAK"


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


def refused(coro: Coroutine[Any, Any, Any]) -> GatewayError:
    with pytest.raises(GatewayError) as caught:
        run(coro)
    return caught.value


def token(**overrides: Any) -> TokenCredential:
    settings: dict[str, Any] = {
        "access_token": SECRET,
        "refresh_token": REFRESH,
        "expires_at": 1_000.0,
        "granted_scope": "internal",
        "issuer": "https://agent.robinhood.com/mcp/trading",
        "obtained_at": 0.0,
    }
    settings.update(overrides)
    return TokenCredential(**settings)


def registration(**overrides: Any) -> ClientRegistration:
    settings: dict[str, Any] = {
        "client_id": CLIENT_ID,
        "issuer": "https://agent.robinhood.com/mcp/trading",
        "redirect_uri": "http://127.0.0.1:8765/callback",
    }
    settings.update(overrides)
    return ClientRegistration(**settings)


# ==========================================================================
# Redaction (§5.2, §7.3, §8)
# ==========================================================================


def via_format(value: Any) -> str:
    """`str.format`, through a variable template so ruff leaves it alone.

    It is a genuinely different channel from an f-string: `format()` consults
    `__format__`, which a dataclass inherits from `object` and which falls
    back to `__str__` only for an empty format spec.
    """
    template = "{}"
    return template.format(value)


@pytest.mark.parametrize(
    "render",
    [repr, str, lambda value: f"{value}", via_format, lambda value: f"{value!r}"],
    ids=["repr", "str", "fstring", "format", "fstring-repr"],
)
def test_no_rendering_of_a_token_reveals_it(render: Any) -> None:
    rendered = render(token())
    assert SECRET not in rendered
    assert REFRESH not in rendered
    assert "<redacted>" in rendered


@pytest.mark.parametrize(
    "render",
    [repr, str, lambda value: f"{value}", via_format],
    ids=["repr", "str", "fstring", "format"],
)
def test_no_rendering_of_a_registration_reveals_the_client_id(render: Any) -> None:
    """§5.1: registration metadata is credential-shaped even for a public client."""
    rendered = render(registration())
    assert CLIENT_ID not in rendered
    assert "<redacted>" in rendered


def test_a_token_in_a_log_record_is_redacted(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    logging.getLogger("test").debug("credential=%s", token())
    logging.getLogger("test").debug("credential=%r", token())
    assert SECRET not in caplog.text
    assert REFRESH not in caplog.text


def test_a_token_inside_an_exception_message_is_redacted() -> None:
    error = GatewayError(ErrorCode.AUTH_REQUIRED, f"could not use {token()}")
    assert SECRET not in str(error)
    assert SECRET not in repr(error)


def test_a_validation_failure_never_echoes_the_offending_secret() -> None:
    with pytest.raises(GatewayError) as caught:
        TokenCredential(access_token=SECRET + "\n" + SECRET)
    assert SECRET not in caught.value.message
    assert caught.value.code is ErrorCode.CONFIGURATION_ERROR


def test_the_records_expose_no_public_serialization() -> None:
    """§5.2: read/update/delete 'without exposing serialized secrets'."""
    for record in (token(), registration()):
        for name in ("to_json_dict", "to_dict", "as_json", "serialize", "json"):
            assert not hasattr(record, name), name


def test_the_serialized_form_is_module_private() -> None:
    for name in ("_encode_token", "_decode_token", "_encode_registration", "_decode_registration"):
        assert hasattr(credentials, name)
        assert name not in credentials.__all__


# ==========================================================================
# Record validation
# ==========================================================================


def test_a_token_with_a_newline_is_refused() -> None:
    """A header-splitting credential must not even reach the store."""
    with pytest.raises(GatewayError) as caught:
        TokenCredential(access_token="abc\r\nX-Evil: 1")
    assert caught.value.code is ErrorCode.CONFIGURATION_ERROR


@pytest.mark.parametrize("bad", ["", "a b", "a\tb", "abc\x00", "café"])
def test_a_token_outside_printable_ascii_is_refused(bad: str) -> None:
    with pytest.raises(GatewayError):
        TokenCredential(access_token=bad)


def test_an_oversized_token_is_refused() -> None:
    with pytest.raises(GatewayError):
        TokenCredential(access_token="a" * (credentials.MAX_TOKEN_CHARS + 1))


def test_only_a_bearer_token_can_be_stored() -> None:
    with pytest.raises(GatewayError) as caught:
        TokenCredential(access_token=SECRET, token_type="mac")
    assert "Bearer" in caught.value.message


def test_a_bearer_token_type_is_accepted_case_insensitively() -> None:
    assert TokenCredential(access_token=SECRET, token_type="bearer").token_type == "bearer"


def test_expiry_uses_the_skew_so_a_token_never_expires_in_flight() -> None:
    credential = token(expires_at=1_000.0)
    assert credential.is_expired(900.0, skew_s=60.0) is False
    assert credential.is_expired(941.0, skew_s=60.0) is True
    assert credential.is_expired(1_001.0, skew_s=60.0) is True


def test_a_token_with_no_expiry_is_never_treated_as_expired() -> None:
    """Guessing an expiry would either churn or discard a live credential."""
    assert token(expires_at=None).is_expired(10**12) is False


def test_a_registration_expiry_of_zero_means_never() -> None:
    """RFC 7591 uses 0 for 'does not expire'; a naive comparison inverts it."""
    assert registration(client_id_expires_at=0).is_expired(10**12) is False
    assert registration(client_id_expires_at=2_000).is_expired(2_001) is True
    assert registration(client_id_expires_at=2_000).is_expired(1_999) is False


def test_a_registration_needs_an_http_issuer_and_redirect() -> None:
    with pytest.raises(GatewayError):
        registration(issuer="not-a-url")
    with pytest.raises(GatewayError):
        registration(redirect_uri="javascript:alert(1)")


# ==========================================================================
# Round-tripping through the serialized form
# ==========================================================================


def test_an_in_memory_store_round_trips_both_records() -> None:
    store = InMemoryCredentialStore()

    async def scenario() -> tuple[Any, Any]:
        await store.store_token(token())
        await store.store_registration(registration())
        return await store.load_token(), await store.load_registration()

    loaded_token, loaded_registration = run(scenario())
    assert loaded_token == token()
    assert loaded_registration == registration()


def test_an_empty_store_returns_none_rather_than_raising() -> None:
    store = InMemoryCredentialStore()
    assert run(store.load_token()) is None
    assert run(store.load_registration()) is None


def test_delete_reports_whether_anything_was_removed() -> None:
    store = InMemoryCredentialStore()

    async def scenario() -> tuple[bool, bool]:
        await store.store_token(token())
        return await store.delete_token(), await store.delete_token()

    assert run(scenario()) == (True, False)


def test_a_record_of_the_wrong_kind_is_refused() -> None:
    """Keying confusion must not silently produce a half-populated record."""
    store = InMemoryCredentialStore()

    async def scenario() -> Any:
        await store.store_registration(registration())
        store._records["token"] = store._records["client_registration"]
        return await store.load_token()

    error = refused(scenario())
    assert error.code is ErrorCode.CONFIGURATION_ERROR
    assert "wrong kind" in error.message


def test_a_record_from_an_unsupported_format_version_is_refused() -> None:
    store = InMemoryCredentialStore()

    async def scenario() -> Any:
        await store.store_token(token())
        stored = store._records["token"]
        store._records["token"] = stored.replace(b'"version":"1"', b'"version":"2"')
        return await store.load_token()

    error = refused(scenario())
    assert "format version" in error.message


def test_an_unreadable_record_is_refused_without_echoing_it() -> None:
    store = InMemoryCredentialStore()

    async def scenario() -> Any:
        store._records["token"] = b"{not json" + SECRET.encode()
        return await store.load_token()

    error = refused(scenario())
    assert SECRET not in error.message


def test_storing_the_wrong_record_type_is_refused() -> None:
    store = InMemoryCredentialStore()
    error = refused(store.store_token(registration()))  # type: ignore[arg-type]
    assert error.code is ErrorCode.CONFIGURATION_ERROR


# ==========================================================================
# Namespace policy (§5.2)
# ==========================================================================


def test_a_write_client_namespace_is_refused_in_every_mode() -> None:
    """§2.5: a future write client gets its own namespace; reads never open it."""
    for mode in ("production", "development"):
        with pytest.raises(GatewayError) as caught:
            check_namespace("write-rh-mcp", mode=mode)
        assert "write client" in caught.value.message


def test_a_development_namespace_is_refused_in_production() -> None:
    with pytest.raises(GatewayError):
        check_namespace("dev-rh-mcp", mode="production")


def test_a_production_namespace_is_refused_in_development() -> None:
    with pytest.raises(GatewayError):
        check_namespace("rh-mcp", mode="development")


def test_the_matching_namespaces_are_accepted() -> None:
    check_namespace("rh-mcp", mode="production")
    check_namespace("dev-rh-mcp", mode="development")


# ==========================================================================
# The file adapter (§5.2)
# ==========================================================================


def dev_config(tmp_path: Path, **overrides: Any) -> GatewayConfig:
    settings: dict[str, Any] = {
        "expected_manifest_digest": DIGEST,
        "mode": "development",
        "credential_adapter": "file_dev",
        "credential_namespace": "dev-rh-mcp",
        "dev_url": "http://127.0.0.1:9999/mcp",
    }
    settings.update(overrides)
    return GatewayConfig(**settings)


def file_store(tmp_path: Path, **overrides: Any) -> FileCredentialStore:
    return FileCredentialStore("dev-rh-mcp", directory=tmp_path, **overrides)


def test_the_file_store_refuses_a_production_namespace() -> None:
    with pytest.raises(GatewayError):
        FileCredentialStore("rh-mcp")


def test_the_file_store_round_trips(tmp_path: Path) -> None:
    store = file_store(tmp_path)

    async def scenario() -> Any:
        await store.store_token(token())
        return await store.load_token()

    assert run(scenario()) == token()


def test_the_credential_directory_is_0700_and_the_file_is_0600(tmp_path: Path) -> None:
    """§5.2, and proven under a permissive umask so the mode is really ours."""
    store = file_store(tmp_path)
    previous = os.umask(0o000)
    try:
        run(store.store_token(token()))
    finally:
        os.umask(previous)
    assert oct(store.directory.stat().st_mode & 0o777) == "0o700"
    path = store.directory / "token.json"
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_a_credential_file_readable_by_others_is_refused_on_read(tmp_path: Path) -> None:
    """The interesting case is a mode that changed *after* this process wrote it."""
    store = file_store(tmp_path)
    run(store.store_token(token()))
    path = store.directory / "token.json"
    os.chmod(path, 0o644)
    error = refused(store.load_token())
    assert error.code is ErrorCode.CONFIGURATION_ERROR
    assert "group or other" in error.message


def test_a_pre_existing_group_readable_directory_is_refused_not_repaired(tmp_path: Path) -> None:
    """Repairing the mode does not un-read a token that sat there readable.

    An earlier draft chmodded the directory to 0700 before checking it, which
    made this refusal unreachable while the comment claimed otherwise.
    """
    directory = tmp_path / "dev-rh-mcp"
    directory.mkdir(mode=0o750)
    store = file_store(tmp_path)
    error = refused(store.store_token(token()))
    assert error.code is ErrorCode.CONFIGURATION_ERROR
    assert "group or other" in error.message
    assert not (directory / "token.json").exists()


def test_a_symlinked_credential_file_is_not_followed(tmp_path: Path) -> None:
    """O_NOFOLLOW: a symlink dropped in place must not redirect the read."""
    store = file_store(tmp_path)
    run(store.store_token(token()))
    path = store.directory / "token.json"
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_bytes(path.read_bytes())
    os.chmod(elsewhere, 0o600)
    path.unlink()
    path.symlink_to(elsewhere)
    error = refused(store.load_token())
    assert "symlink" in error.message


def test_a_credential_file_owned_by_another_user_is_refused(tmp_path: Path) -> None:
    """Checked against a synthetic stat rather than by becoming another user."""
    store = file_store(tmp_path)
    run(store.store_token(token()))
    real = os.stat(store.directory / "token.json")
    foreign = os.stat_result(
        (real.st_mode, real.st_ino, real.st_dev, real.st_nlink, os.getuid() + 1)
        + tuple(real)[5:10]
    )
    with pytest.raises(GatewayError) as caught:
        credentials._check_file_security(foreign, "the file")
    assert "another user" in caught.value.message


def test_a_credential_file_that_is_not_a_regular_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(GatewayError) as caught:
        credentials._check_file_security(os.stat(tmp_path), "the file")
    assert "regular file" in caught.value.message


def test_a_missing_credential_file_reads_as_absent(tmp_path: Path) -> None:
    assert run(file_store(tmp_path).load_token()) is None


def test_writing_leaves_no_temporary_file_behind(tmp_path: Path) -> None:
    store = file_store(tmp_path)
    run(store.store_token(token()))
    run(store.store_token(token(access_token="second-" + SECRET)))
    names = sorted(item.name for item in store.directory.iterdir())
    assert names == ["token.json"]


def test_a_replacement_is_atomic_and_leaves_a_complete_record(tmp_path: Path) -> None:
    """`os.replace`: a reader sees the old record or the new one, never half."""
    store = file_store(tmp_path)
    run(store.store_token(token()))
    original = (store.directory / "token.json").read_bytes()
    run(store.store_token(token(access_token="rotated-token")))
    replaced = (store.directory / "token.json").read_bytes()
    assert original != replaced
    assert run(store.load_token()).access_token == "rotated-token"  # type: ignore[union-attr]


def test_deleting_removes_the_file(tmp_path: Path) -> None:
    store = file_store(tmp_path)

    async def scenario() -> tuple[bool, bool]:
        await store.store_token(token())
        first = await store.delete_token()
        return first, await store.delete_token()

    assert run(scenario()) == (True, False)
    assert not (store.directory / "token.json").exists()


def test_an_oversized_credential_file_is_refused(tmp_path: Path) -> None:
    store = file_store(tmp_path)
    run(store.store_token(token()))
    path = store.directory / "token.json"
    path.write_bytes(b"x" * (credentials.MAX_SECRET_BYTES + 1))
    os.chmod(path, 0o600)
    assert "too large" in refused(store.load_token()).message


# -- locking ---------------------------------------------------------------


LOCK_HOLDER = """
import fcntl, sys, time
handle = open(sys.argv[1], "a+b")
fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
print("held", flush=True)
time.sleep(float(sys.argv[2]))
"""


def test_exclusive_serializes_against_another_process(tmp_path: Path) -> None:
    """§5.2: 'serialized across processes by the adapter'."""
    store = file_store(tmp_path, lock_timeout_s=0.3)
    run(store.store_token(token()))  # creates the directory
    lock_path = store.directory / ".lock"
    holder = subprocess.Popen(
        [sys.executable, "-c", LOCK_HOLDER, str(lock_path), "5"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "held"

        async def scenario() -> None:
            async with store.exclusive():
                pass

        error = refused(scenario())
        assert error.code is ErrorCode.TIMEOUT
        assert error.retryable is True
    finally:
        holder.kill()
        holder.wait()


def test_exclusive_is_reacquirable_after_release(tmp_path: Path) -> None:
    """A lock that is never released is a lock that deadlocks the next read."""
    store = file_store(tmp_path, lock_timeout_s=0.5)

    async def scenario() -> None:
        for _ in range(3):
            async with store.exclusive():
                await store.store_token(token())

    run(scenario())


def test_the_lock_file_holds_no_credential_material(tmp_path: Path) -> None:
    store = file_store(tmp_path)

    async def scenario() -> None:
        async with store.exclusive():
            await store.store_token(token())

    run(scenario())
    assert (store.directory / ".lock").read_bytes() == b""


def test_store_operations_inside_exclusive_do_not_deadlock(tmp_path: Path) -> None:
    """The reason the individual methods do not take the lock themselves."""
    store = file_store(tmp_path, lock_timeout_s=0.5)

    async def scenario() -> Any:
        async with store.exclusive():
            await store.store_token(token())
            loaded = await store.load_token()
            await store.delete_token()
            return loaded

    assert run(asyncio.wait_for(scenario(), timeout=5)) == token()


# ==========================================================================
# The Keychain adapter (§5.2) — never touches a real Keychain
# ==========================================================================


class FakeSecurity:
    """A `security` stand-in that records exactly what it was asked to run."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], str] = {}
        self.calls: list[tuple[list[str], str | None]] = []
        self.force_returncode: int | None = None

    def __call__(self, argv: list[str], stdin: str | None) -> CommandResult:
        self.calls.append((list(argv), stdin))
        if self.force_returncode is not None:
            return CommandResult(self.force_returncode, "")
        if argv[:2] == ["security", "-i"]:
            assert stdin is not None
            words = stdin.strip().split(" ")
            assert words[0] == "add-generic-password"
            account = words[words.index("-a") + 1]
            service = words[words.index("-s") + 1]
            self.items[(service, account)] = words[words.index("-w") + 1]
            return CommandResult(0, "")
        command = argv[1]
        account = argv[argv.index("-a") + 1]
        service = argv[argv.index("-s") + 1]
        if command == "find-generic-password":
            value = self.items.get((service, account))
            return CommandResult(0, value + "\n") if value is not None else CommandResult(44, "")
        if command == "delete-generic-password":
            if self.items.pop((service, account), None) is None:
                return CommandResult(44, "")
            return CommandResult(0, "attributes...\n")
        raise AssertionError(f"unexpected security command {command}")  # pragma: no cover


def keychain(tmp_path: Path, runner: FakeSecurity, **overrides: Any) -> KeychainCredentialStore:
    return KeychainCredentialStore(
        "rh-mcp", runner=runner, lock_directory=tmp_path, **overrides
    )


def test_the_keychain_store_round_trips(tmp_path: Path) -> None:
    runner = FakeSecurity()
    store = keychain(tmp_path, runner)

    async def scenario() -> Any:
        await store.store_token(token())
        await store.store_registration(registration())
        return await store.load_token(), await store.load_registration()

    loaded_token, loaded_registration = run(scenario())
    assert loaded_token == token()
    assert loaded_registration == registration()


def test_the_secret_never_appears_in_argv(tmp_path: Path) -> None:
    """`security -w <secret>` would put a write-capable token in `ps` output."""
    runner = FakeSecurity()
    run(keychain(tmp_path, runner).store_token(token()))
    argv, stdin = runner.calls[-1]
    assert argv == ["security", "-i"]
    assert all(SECRET not in argument for argument in argv)
    assert stdin is not None
    # It is in the *stdin* command, base64-encoded, which is the whole point.
    assert "add-generic-password" in stdin


def test_exactly_one_command_is_written_per_invocation(tmp_path: Path) -> None:
    """`security -i` reports only the last command's status (measured)."""
    runner = FakeSecurity()
    run(keychain(tmp_path, runner).store_token(token()))
    _argv, stdin = runner.calls[-1]
    assert stdin is not None
    assert stdin.count("\n") == 1
    assert len([line for line in stdin.splitlines() if line.strip()]) == 1


def test_the_stdin_command_carries_only_base64(tmp_path: Path) -> None:
    """No character in the payload can be read as a command separator."""
    runner = FakeSecurity()
    run(keychain(tmp_path, runner).store_token(token()))
    _argv, stdin = runner.calls[-1]
    assert stdin is not None
    words = stdin.strip().split(" ")
    payload = words[words.index("-w") + 1]
    assert credentials._BASE64_PATTERN.fullmatch(payload)
    assert SECRET not in stdin


def test_a_missing_keychain_item_reads_as_absent(tmp_path: Path) -> None:
    assert run(keychain(tmp_path, FakeSecurity()).load_token()) is None


def test_a_missing_keychain_item_deletes_as_false(tmp_path: Path) -> None:
    assert run(keychain(tmp_path, FakeSecurity()).delete_token()) is False


def test_a_keychain_failure_reports_only_the_status(tmp_path: Path) -> None:
    runner = FakeSecurity()
    runner.force_returncode = 51
    error = refused(keychain(tmp_path, runner).load_token())
    assert "51" in error.message
    assert SECRET not in error.message


def test_a_non_base64_keychain_value_is_refused(tmp_path: Path) -> None:
    runner = FakeSecurity()
    runner.items[("rh-mcp:rh-mcp", "rh-mcp-token")] = "not base64!!"
    assert "base64" in refused(keychain(tmp_path, runner).load_token()).message


def test_an_empty_keychain_value_is_refused(tmp_path: Path) -> None:
    runner = FakeSecurity()
    runner.items[("rh-mcp:rh-mcp", "rh-mcp-token")] = ""
    assert "empty" in refused(keychain(tmp_path, runner).load_token()).message


def test_an_oversized_keychain_record_is_refused(tmp_path: Path) -> None:
    """The keychain path has no file-size check, so `_decode`'s bound is the
    only thing between a stuffed keychain item and an unbounded decode."""
    import base64

    runner = FakeSecurity()
    oversized = base64.b64encode(b"x" * (credentials.MAX_SECRET_BYTES + 1)).decode()
    runner.items[("rh-mcp:rh-mcp", "rh-mcp-token")] = oversized
    assert "too large" in refused(keychain(tmp_path, runner).load_token()).message


def test_the_command_result_type_carries_no_stderr() -> None:
    """`security` echoes the command it failed on, and that command has a token."""
    assert not hasattr(CommandResult(0, ""), "stderr")
    assert "stderr" not in CommandResult.__dataclass_fields__


def test_the_keychain_store_refuses_a_write_client_namespace(tmp_path: Path) -> None:
    with pytest.raises(GatewayError):
        KeychainCredentialStore("write-rh-mcp", runner=FakeSecurity(), lock_directory=tmp_path)


def test_the_keychain_store_serializes_across_processes(tmp_path: Path) -> None:
    """A keychain item is shared by every process of the user (§5.2)."""
    runner = FakeSecurity()
    store = keychain(tmp_path, runner, lock_timeout_s=0.3)

    async def prime() -> None:
        async with store.exclusive():
            pass

    run(prime())
    lock_path = store._lock_path_directory / ".lock"
    holder = subprocess.Popen(
        [sys.executable, "-c", LOCK_HOLDER, str(lock_path), "5"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "held"

        async def scenario() -> None:
            async with store.exclusive():
                pass

        assert refused(scenario()).code is ErrorCode.TIMEOUT
    finally:
        holder.kill()
        holder.wait()


# ==========================================================================
# The factory (§3, §5.2)
# ==========================================================================


def test_production_refuses_the_file_adapter() -> None:
    """§5.2, checked at the store as well as in `GatewayConfig`."""
    config = GatewayConfig(
        expected_manifest_digest=DIGEST, mode="development", credential_adapter="file_dev",
        credential_namespace="dev-rh-mcp", dev_url="http://127.0.0.1:9999/mcp",
    )
    forced = object.__new__(GatewayConfig)
    for field, value in vars(config).items():
        object.__setattr__(forced, field, value)
    object.__setattr__(forced, "mode", "production")
    object.__setattr__(forced, "credential_namespace", "rh-mcp")
    with pytest.raises(GatewayError) as caught:
        open_credential_store(forced)
    assert "plaintext" in caught.value.message


def test_production_refuses_the_in_memory_adapter() -> None:
    config = GatewayConfig(
        expected_manifest_digest=DIGEST, mode="development", credential_adapter="in_memory",
        credential_namespace="dev-rh-mcp", dev_url="http://127.0.0.1:9999/mcp",
    )
    forced = object.__new__(GatewayConfig)
    for field, value in vars(config).items():
        object.__setattr__(forced, field, value)
    object.__setattr__(forced, "mode", "production")
    object.__setattr__(forced, "credential_namespace", "rh-mcp")
    with pytest.raises(GatewayError) as caught:
        open_credential_store(forced)
    assert "test double" in caught.value.message


def test_the_factory_builds_the_development_stores(tmp_path: Path) -> None:
    file_config = dev_config(tmp_path)
    store = open_credential_store(file_config, directory=tmp_path)
    assert isinstance(store, FileCredentialStore)

    memory_config = dev_config(tmp_path, credential_adapter="in_memory")
    assert isinstance(open_credential_store(memory_config), InMemoryCredentialStore)


def test_the_factory_builds_the_keychain_store_on_macos(tmp_path: Path) -> None:
    if sys.platform != "darwin":  # pragma: no cover - the suite runs on macOS and Linux CI
        pytest.skip("the keychain adapter is macOS-only")
    config = GatewayConfig(expected_manifest_digest=DIGEST)
    store = open_credential_store(config, directory=tmp_path, runner=FakeSecurity())
    assert isinstance(store, KeychainCredentialStore)


def test_the_factory_refuses_the_keychain_adapter_off_macos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(credentials.sys, "platform", "linux")
    config = GatewayConfig(expected_manifest_digest=DIGEST)
    with pytest.raises(GatewayError) as caught:
        open_credential_store(config, directory=tmp_path)
    assert "macOS" in caught.value.message


def test_the_limits_ceiling_on_refresh_attempts_is_one() -> None:
    """§8: 'a coordinated OAuth refresh may be attempted once'."""
    assert ResourceLimits().max_refresh_attempts == 1
    with pytest.raises(GatewayError):
        ResourceLimits(max_refresh_attempts=2)
