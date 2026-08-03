"""The `rh-mcp` command line (§7.2, §7.3).

A thin shell over the gateway. It holds no policy of its own: every refusal a
user sees here originates in `manifest.py`, `transport.py`, or `auth.py`, and
this module's job is to route it to the right stream with the right exit code.

Three rules govern the output, and they exist so a consumer can parse stdout
without a second thought (§7.2):

1. Structured JSON goes to **stdout alone**.
2. Every diagnostic, prompt, and error goes to **stderr**.
3. **A failure emits nothing to stdout** — not a partial object, not an error
   object. The exit code carries the signal. A consumer that reads a byte from
   stdout is reading a complete, successful result.

`status` is the one command whose non-zero exit accompanies stdout output, and
it does not break rule 3: a readiness report saying `ready: false` is the
*successful* answer to "are you ready?", complete and safe to parse, which §7.1
requires it to produce. What rule 3 forbids is a half-written or error-shaped
payload, and this is neither. Every other command writes stdout only after its
work has fully succeeded.

Rule 3 is why every command builds its payload fully before writing any of it.
There is deliberately no `call` command and no flag that relaxes manifest
enforcement (§7.2): a CLI that could invoke an arbitrary provider tool would
make the reviewed manifest advisory, and an escape hatch that exists is an
escape hatch that gets used in an incident.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Callable, Coroutine, Mapping, Sequence
from typing import Any, Final, TextIO

from rh_mcp.auth import auth_status, login, logout, verify_discovery_metadata
from rh_mcp.config import GatewayConfig
from rh_mcp.credentials import open_credential_store
from rh_mcp.errors import (
    EXIT_CODE_CONFIGURATION_ERROR,
    ErrorCode,
    GatewayError,
    exit_code_for,
)
from rh_mcp.gateway import (
    capability_listing,
    open_admin_discovery,
    open_gateway,
    render_json,
)
from rh_mcp.manifest import load_active_manifest

PROGRAM: Final = "rh-mcp"

# `logout` deletes a credential that can only be replaced by an interactive
# browser login, so §5.2 requires explicit confirmation. Accepted answers are
# exact and lowercase-folded only; anything else is a refusal.
_CONFIRM_WORDS: Final[frozenset[str]] = frozenset({"y", "yes"})


def _emit(payload: Any, out: TextIO) -> None:
    """Write one complete structured payload to stdout. Called only on success."""
    out.write(render_json(payload) + "\n")


def _parse_input(raw: str | None) -> Mapping[str, Any]:
    """Decode `--input`, which must be a JSON object.

    A usage error rather than a protocol error: the caller typed this, not the
    provider (§7.3, exit 2).
    """
    if raw is None:
        return {}
    try:
        decoded = json.loads(raw)
    except ValueError as exc:
        raise GatewayError(
            ErrorCode.INPUT_INVALID, f"--input is not valid JSON: {exc.args[0]}"
        ) from None
    if not isinstance(decoded, dict):
        raise GatewayError(ErrorCode.INPUT_INVALID, "--input must be a JSON object")
    return decoded


def _confirm(prompt: str, err: TextIO, stdin: TextIO) -> bool:
    """Ask for confirmation on stderr, read the answer from stdin.

    Refuses rather than prompting when stdin is not a terminal: an unattended
    caller cannot meaningfully consent, and reading a stray pipe byte as
    consent to delete a credential is the wrong failure.
    """
    if not stdin.isatty():
        raise GatewayError(
            ErrorCode.INPUT_INVALID,
            "logout needs an interactive confirmation; run it from a terminal, "
            "or pass --yes if you have already decided",
        )
    err.write(f"{prompt} [y/N]: ")
    err.flush()
    return stdin.readline().strip().lower() in _CONFIRM_WORDS


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


async def _cmd_login(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    config = GatewayConfig.from_env()
    store = open_credential_store(config)
    err.write("opening a browser to authorize this gateway...\n")
    outcome = await login(config, store)
    _emit(outcome.to_json_dict(), out)
    return 0


async def _cmd_logout(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    config = GatewayConfig.from_env()
    # Consent first, store second. Opening the credential store can fail for
    # reasons that have nothing to do with the user's intent — a keychain
    # adapter on a host that has no keychain, for one — and that failure
    # arriving *before* the prompt turns "are you sure?" into an unrelated
    # error the user never gets to answer. CI caught this: on Linux the
    # confirmation was never reached at all.
    confirmed = args.yes or _confirm(
        "delete the stored Robinhood credential and client registration?", err, sys.stdin
    )
    if not confirmed:
        raise GatewayError(ErrorCode.INPUT_INVALID, "logout was not confirmed; nothing removed")
    store = open_credential_store(config)
    _emit(await logout(store, confirm=True), out)
    return 0


async def _cmd_auth_status(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    config = GatewayConfig.from_env()
    store = open_credential_store(config)
    _emit((await auth_status(store)).to_json_dict(), out)
    return 0


async def _cmd_status(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    """Readiness plus safe drift findings.

    Not ready is a *reportable* outcome, not a crash: §7.1 says readiness
    false must report safe diagnostics. So the assessment is written to stdout
    and the exit code still reflects the failure, which is the one place a
    non-zero exit accompanies stdout output — and it does so because the
    assessment *is* the successful result of asking "are you ready?".
    """
    config = GatewayConfig.from_env()
    if config.mode == "production" and not args.skip_metadata_check:
        await verify_discovery_metadata(config)
    async with open_gateway(config) as gateway:
        assessment = await gateway.readiness()
    _emit(assessment.to_json_dict(), out)
    if assessment.ready:
        return 0

    # A finding that stands in for a raised error carries its originating code
    # as a structured field, put there in step 2 precisely so this mapping does
    # not have to parse prose. Honouring it matters most for `auth_required`:
    # reporting an expired credential as a generic not-ready sends an operator
    # looking for manifest drift when the answer is `rh-mcp login`.
    originating = next((f.error_code for f in assessment.findings if f.error_code), None)
    if originating is not None:
        err.write(f"{PROGRAM}: {originating}: provider discovery failed\n")
        if originating is ErrorCode.AUTH_REQUIRED:
            err.write(f"{PROGRAM}: run `{PROGRAM} login` and try again\n")
        return exit_code_for(GatewayError(originating, "provider discovery failed"))

    err.write(f"{PROGRAM}: not_ready: the gateway is not ready; see the findings above\n")
    return EXIT_CODE_CONFIGURATION_ERROR


async def _cmd_capabilities(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    config = GatewayConfig.from_env()
    # No gateway, no credential store, no session. This command reads a file
    # that ships inside the package; opening a credential store first made it
    # fail on any host without one while the manifest sat there readable.
    manifest = load_active_manifest()
    # Both digests and an explicit comparison. This command reports the
    # *committed* manifest, so it stays exit 0 and never establishes readiness
    # — making it fail under a mismatch would break the one command that best
    # explains a mismatch. But a listing of `read_allowed: true` entries could
    # be misread as a statement about what is currently permitted, so it says
    # plainly whether the active manifest is the one the deployment pinned.
    matches = manifest.digest == config.expected_manifest_digest
    payload = {
        "manifest_version": manifest.manifest_version,
        "manifest_digest": manifest.digest,
        "expected_manifest_digest": config.expected_manifest_digest,
        "digest_matches": matches,
        "capabilities": [c.to_json_dict() for c in capability_listing(manifest)],
    }
    _emit(payload, out)
    if not matches:
        err.write(
            f"{PROGRAM}: the active manifest is not the one this deployment pinned; "
            "these capabilities are not currently permitted\n"
        )
    return 0


async def _cmd_read(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    config = GatewayConfig.from_env()
    arguments = _parse_input(args.input)
    async with open_gateway(config) as gateway:
        envelope = await gateway.invoke(args.capability, arguments)
    _emit(envelope.to_json_dict(), out)
    return 0


async def _cmd_admin_discover(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    config = GatewayConfig.from_env()
    err.write(
        "observing the provider surface. This grants nothing: every tool is written out\n"
        "as denied, and a human must review each one before it can be allowed.\n"
        "The candidate on stdout is unsanitized provider data by design (§6.1) — treat it\n"
        "as sensitive, review it before committing, and do not paste it into a log.\n"
    )
    async with open_admin_discovery(config) as admin:
        document = await admin.candidate_document()
    _emit(document, out)
    return 0


Command = Callable[[argparse.Namespace, TextIO, TextIO], Coroutine[Any, Any, int]]

_COMMANDS: Final[dict[str, Command]] = {
    "login": _cmd_login,
    "logout": _cmd_logout,
    "auth-status": _cmd_auth_status,
    "status": _cmd_status,
    "capabilities": _cmd_capabilities,
    "read": _cmd_read,
    "admin-discover": _cmd_admin_discover,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="A default-deny read gateway for Robinhood's MCP server.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("login", help="authorize this gateway in a browser")

    logout_parser = sub.add_parser("logout", help="delete the stored credential")
    logout_parser.add_argument(
        "--yes", action="store_true", help="skip the interactive confirmation"
    )

    sub.add_parser("auth-status", help="report credential state without secrets")

    status_parser = sub.add_parser("status", help="report readiness and any drift")
    status_parser.add_argument(
        "--skip-metadata-check",
        action="store_true",
        help="skip the production discovery-metadata check (development aid)",
    )

    sub.add_parser("capabilities", help="list reviewed capabilities")

    read_parser = sub.add_parser("read", help="invoke one reviewed read capability")
    read_parser.add_argument("capability")
    read_parser.add_argument("--input", help="arguments as a JSON object")

    admin = sub.add_parser("admin", help="owner-run administrative workflows")
    admin_sub = admin.add_subparsers(dest="admin_command", required=True)
    admin_sub.add_parser("discover", help="write a candidate manifest for human review")

    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Run one command and return its exit code (§7.3).

    Never raises: every failure becomes a stderr line and a code from the
    single mapping in `errors.py`. A second mapping here would be a second
    contract to keep in step, so there isn't one.
    """
    stdout = sys.stdout if out is None else out
    stderr = sys.stderr if err is None else err

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse already wrote its message
        return 2 if exc.code else 0

    name = args.command
    if name == "admin":
        name = f"admin-{args.admin_command}"

    try:
        return asyncio.run(_COMMANDS[name](args, stdout, stderr))
    except GatewayError as exc:
        stderr.write(f"{PROGRAM}: {exc.code}: {exc.message}\n")
        if exc.code is ErrorCode.AUTH_REQUIRED:
            stderr.write(f"{PROGRAM}: run `{PROGRAM} login` and try again\n")
        return exit_code_for(exc)
    except KeyboardInterrupt:
        stderr.write(f"{PROGRAM}: interrupted\n")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["PROGRAM", "build_parser", "main"]
