"""The credential store protocol and its adapters (DESIGN.md §5.2, §3, §8).

This module holds the highest-consequence object in the project. Robinhood
advertises one scope, `internal`, so the token stored here **can trade** (§2).
What this credential may be used for is a local convention enforced by the
manifest — "no trading", not "no writes" (§2.1) — and it is not a property
of this credential. Everything below is written on that assumption.

Four decisions are load-bearing enough to state up front.

**Records never serialize themselves in public — with two named exceptions.**
`models.py` gives its types a `to_json_dict()` because a `ResultEnvelope` is
meant to be printed. These types deliberately have no such method. §5.2
requires read, atomic update, and delete "without exposing serialized secrets
to callers", and the way to get that is to make the serialized form unreachable
from outside this module rather than to ask callers not to use it.
`_encode`/`_decode` are module-private for that reason.

Closed channels, each with a test that plants a known secret and greps for it:
`__repr__`, `__str__`, f-strings, `%s`/`%r`, `str.format`, exception text,
`traceback.format_exc()`, log records, `__dict__`/`vars()` (the records use
`slots=True`, so there is no instance dict), and `pickle` (`__reduce__`
refuses). `copy`/`deepcopy` still work and return the same immutable object,
and so does `weakref.ref` — `slots=True` silently drops weak-reference support,
so every record pairs it with `weakref_slot=True` rather than regressing an
unrelated part of the API as a side effect of a redaction fix.

**Open channels, stated rather than implied:** `dataclasses.asdict` and
`dataclasses.astuple` walk `fields()` and call `getattr`, and there is no hook
that intercepts them short of not being a dataclass. Anything else that walks
`__dataclass_fields__` — `rich`'s pretty printer, some structured-logging
encoders — sees the same. An earlier version of this docstring claimed these
types had "no `asdict()`-friendly shape", which was simply false; the review
that caught it was right that a docstring promising a property the code does
not have is how a real defect stays invisible. `test_credentials.py` pins the
gap explicitly so closing it later is a deliberate act rather than a surprise.

**Individual operations are atomic; multi-step sequences must ask.** A write is
a single `os.replace` or a single `security` invocation, so no reader ever sees
a half-written credential. What that does *not* give you is a safe
read-modify-write across processes — two brokers refreshing at once would each
read the old refresh token and one would win. `exclusive()` is the answer, and
it is a separate method rather than something every operation takes, because a
lock held inside `store_token()` would deadlock the moment `exclusive()` also
wanted it. The one read-modify-write sequence in the system, the coordinated
refresh in `auth.py`, wraps itself in `exclusive()`. Anything added later must
too.

**A credential file that is not exactly right is not read.** The file adapter
refuses a file that is a symlink, is not a regular file, is owned by another
user, or is readable by group or other. It refuses on *read*, not only on
write, because the interesting case is a file whose mode changed after this
process created it. Failing closed costs an operator one `rh-mcp login`;
failing open costs them the account.

**The Keychain adapter keeps the secret out of `argv`.** `security
add-generic-password -w <secret>` puts a write-capable token in the process
table. Measured behaviour of `security -i` instead: it reads commands from
stdin, and its exit status reflects **only the last command**, so this sends
exactly one command per invocation and checks the status. The payload is
base64, which has no character `security`'s tokenizer treats specially, and the
encoder is checked against that alphabet before the line is built so a newline
can never inject a second command — an independent review confirmed that
without that check, a newline plus `delete-keychain` on the second line
executes.

That same channel has a size limit, and the limit is on the whole line rather
than the payload. See `SECURITY_MAX_COMMAND_LINE_BYTES` — it is enforced before
the command is built, because the alternative is an opaque `status 1` at the
first real login.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import re
import stat
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, NoReturn, Protocol

from rh_mcp.config import GatewayConfig
from rh_mcp.errors import ErrorCode, GatewayError

try:  # pragma: no cover - exercised by whichever platform runs the suite
    import fcntl
except ImportError:  # pragma: no cover - Windows has no flock
    fcntl = None  # type: ignore[assignment]


# --------------------------------------------------------------------------
# Namespace policy (§5.2)
# --------------------------------------------------------------------------

DEV_NAMESPACE_PREFIX: Final[str] = "dev-"

# §2.5 and §5.2: "future write support must use a separate client surface,
# credential namespace, runtime identity, and deployment role". This gateway is
# the read client, so it refuses to open a namespace reserved for the write one
# in *any* mode — not just production. A read broker that can be pointed at the
# write client's credential has already erased the separation the design asks
# for, and the cheapest place to stop that is here, before a store handle
# exists.
WRITE_NAMESPACE_PREFIX: Final[str] = "write-"

MAX_SECRET_BYTES: Final[int] = 16_384
MAX_TOKEN_CHARS: Final[int] = 8_192
MAX_CLIENT_ID_CHARS: Final[int] = 512

# A stored record's serialized form. Bumping this is a migration, not an edit:
# a record written by a newer version must not be silently reinterpreted by an
# older one.
CREDENTIAL_RECORD_VERSION: Final[str] = "1"

CredentialKind = Literal["token", "client_registration"]

_KINDS: Final[tuple[CredentialKind, ...]] = ("token", "client_registration")

# Base64 (standard alphabet, padded) and nothing else. This is what makes the
# `security -i` command line safe to build by string concatenation.
_BASE64_PATTERN: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9+/]+={0,2}\Z")

# What may appear in a `security` keychain service/account name. Deliberately
# narrower than the namespace charset `config.py` already validates, because
# these strings go onto a command line read by a tokenizer.
_KEYCHAIN_ATTRIBUTE_PATTERN: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9._:-]{1,128}\Z")

# `security` exit status for "the specified item could not be found", measured
# rather than assumed (`find-generic-password` and `delete-generic-password`
# both return it).
_SECURITY_ITEM_NOT_FOUND: Final[int] = 44

# `security -i` refuses an input line past a fixed size, and the bound is on
# the **whole line**, not the payload. Bisected on Darwin 25.5.0 against an
# isolated temporary keychain, using this adapter's exact command shape:
#
#     whole line 4096 bytes -> exit 0, stored intact
#     whole line 4097 bytes -> exit 1, nothing stored
#
# and lengthening the service name by 50 characters shrank the usable payload
# by the same 50, which is what identifies the bound as line-wide. Over-limit
# writes fail closed with nothing stored — there is no silent truncation — but
# the raw failure is an opaque `status 1`, which is a terrible thing to meet
# during a first owner-assisted login. `_write` therefore measures the line it
# is about to send and refuses with an error that names the cause.
#
# The budget is set below the measured 4096 so a macOS release with a smaller
# limit degrades into this clear error rather than the opaque one.
SECURITY_MAX_COMMAND_LINE_BYTES: Final[int] = 4_000


def _fail(code: ErrorCode, message: str, *, retryable: bool = False) -> NoReturn:
    raise GatewayError(code, message, retryable=retryable)


def check_namespace(namespace: str, *, mode: str) -> None:
    """Refuse a namespace this gateway must not open (§5.2).

    `config.py` already keeps a production configuration off a `dev-`
    namespace. This is checked again at the store, and the write-client prefix
    is checked here only, because a `CredentialStore` can be constructed
    directly by a library consumer that never built a `GatewayConfig`.
    """
    if not isinstance(namespace, str) or not namespace:
        _fail(ErrorCode.CONFIGURATION_ERROR, "a credential namespace is required")
    if namespace.startswith(WRITE_NAMESPACE_PREFIX):
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            f"credential namespace {namespace!r} uses the {WRITE_NAMESPACE_PREFIX!r} prefix "
            "reserved for a future write client; a read gateway may never open it",
        )
    if mode == "production" and namespace.startswith(DEV_NAMESPACE_PREFIX):
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            f"credential namespace {namespace!r} is a development namespace and cannot be "
            "opened in production mode",
        )
    if mode == "development" and not namespace.startswith(DEV_NAMESPACE_PREFIX):
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            f"credential namespace {namespace!r} must use the {DEV_NAMESPACE_PREFIX!r} prefix "
            "in development mode so it cannot collide with a production store",
        )


# --------------------------------------------------------------------------
# The records (§5.1, §5.2)
# --------------------------------------------------------------------------


def _require_secret_string(name: str, value: object, *, limit: int) -> str:
    """Validate a credential-shaped string without ever echoing it.

    Every other validator in this package quotes the offending value. None of
    these may (§5.2, §7.3), so the messages describe the rule instead.
    """
    if not isinstance(value, str) or not value:
        _fail(ErrorCode.CONFIGURATION_ERROR, f"{name} must be a non-empty string")
    if len(value) > limit:
        _fail(ErrorCode.CONFIGURATION_ERROR, f"{name} is longer than {limit} characters")
    # A credential ends up in an `Authorization` header. A control character
    # would split the header block, and a non-ASCII one cannot be sent at all.
    # `transport.py` checks this again at the moment of use; both checks are
    # cheap and neither is the other's excuse.
    for character in value:
        if character < "\x21" or character > "\x7e":
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                f"{name} may contain only printable, non-space ASCII characters",
            )
    return value


def _require_url(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        _fail(ErrorCode.CONFIGURATION_ERROR, f"{name} must be a non-empty string")
    if len(value) > 2048:
        _fail(ErrorCode.CONFIGURATION_ERROR, f"{name} is longer than 2048 characters")
    if any(character.isspace() or ord(character) < 0x20 for character in value):
        _fail(ErrorCode.CONFIGURATION_ERROR, f"{name} must not contain whitespace")
    if not value.startswith(("https://", "http://")):
        _fail(ErrorCode.CONFIGURATION_ERROR, f"{name} must be an http(s) URL")
    return value


def _optional_seconds(name: str, value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(ErrorCode.CONFIGURATION_ERROR, f"{name} must be a number of seconds")
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        _fail(ErrorCode.CONFIGURATION_ERROR, f"{name} must be finite")
    return number


class CredentialMaterial:
    """Base class for a type that holds a secret and refuses to be serialized.

    Public, and imported by `auth.py` for `AuthorizationTransaction`. It was
    private at first, which meant the auth layer reached across a module
    boundary for a private name — a small thing, but "this type holds
    credential material" is a property worth being able to state in the API
    rather than borrow.

    Overriding `__repr__` stops a *human* printing a secret. It does nothing
    about machinery that walks an object structurally, and `pickle` is the
    member of that family that actually moves bytes off the box — into a cache,
    a queue, a crash report. So pickling is refused outright.

    **`__reduce__` alone does that, at every protocol.** An earlier version also
    defined `__getstate__`, on the theory that `dataclass(slots=True)`
    generates one and it would otherwise be "the way around `__reduce__`". That
    reasoning was wrong twice over: the generated `__getstate__` on the
    subclass *shadows* any defined here, so this one never ran, and it is not a
    way around anything, because `pickle` consults `__reduce_ex__` — which
    reaches `__reduce__` — before it ever asks for state. The dead method is
    gone. This paragraph exists because a stale rationale is what gets
    "corrected" away later, and this file has already produced one bug that way.

    `copy` and `deepcopy` are kept working and return `self`, which is sound
    because every subclass is frozen and holds only immutable values. Left to
    fall back on `__reduce_ex__` they would raise too, and breaking `deepcopy`
    on a record a consumer holds is a cost with no security benefit.

    Subclasses use `slots=True` to remove the instance `__dict__`, and must
    pair it with `weakref_slot=True`: `slots=True` silently drops
    weak-reference support, so `weakref.ref(token)` starts raising `TypeError`.
    Nothing here needs a weakref, but a consumer caching by identity does, and
    losing that is an unrelated API regression smuggled in by a redaction fix.
    """

    __slots__ = ()

    def __reduce__(self) -> tuple[Any, ...]:
        raise GatewayError(
            ErrorCode.CONFIGURATION_ERROR,
            f"{type(self).__name__} holds credential material and refuses to be serialized",
        )

    def __copy__(self) -> CredentialMaterial:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> CredentialMaterial:
        return self


@dataclass(frozen=True, slots=True, weakref_slot=True)
class TokenCredential(CredentialMaterial):
    """A stored OAuth token. Write-capable — treat every field as a secret.

    `granted_scope` is recorded rather than assumed. §5.1 leaves open whether
    Robinhood requires no explicit scope or `internal`, and §13 makes settling
    that an owner-assisted observation; storing what was actually granted is
    how that observation gets made without logging a token.
    """

    access_token: str
    refresh_token: str | None = None
    expires_at: float | None = None
    granted_scope: str | None = None
    token_type: str = "Bearer"
    issuer: str = ""
    obtained_at: float = 0.0

    def __post_init__(self) -> None:
        _require_secret_string("access_token", self.access_token, limit=MAX_TOKEN_CHARS)
        if self.refresh_token is not None:
            _require_secret_string("refresh_token", self.refresh_token, limit=MAX_TOKEN_CHARS)
        object.__setattr__(self, "expires_at", _optional_seconds("expires_at", self.expires_at))
        object.__setattr__(self, "obtained_at", _optional_seconds("obtained_at", self.obtained_at))
        if self.granted_scope is not None and not isinstance(self.granted_scope, str):
            _fail(ErrorCode.CONFIGURATION_ERROR, "granted_scope must be a string")
        if not isinstance(self.token_type, str) or not self.token_type:
            _fail(ErrorCode.CONFIGURATION_ERROR, "token_type must be a non-empty string")
        if self.token_type.lower() != "bearer":
            # §5.0 advertises `bearer_methods_supported: ["header"]`, and
            # `transport.py` attaches `Authorization: Bearer`. Storing anything
            # else would mean storing a credential this gateway cannot present.
            _fail(ErrorCode.CONFIGURATION_ERROR, "only a Bearer token can be stored")
        if not isinstance(self.issuer, str):
            _fail(ErrorCode.CONFIGURATION_ERROR, "issuer must be a string")

    @property
    def has_refresh_token(self) -> bool:
        return self.refresh_token is not None

    def is_expired(self, now: float, *, skew_s: float = 60.0) -> bool:
        """Whether this token should be refreshed before the next request.

        A token with no `expires_at` is never *known* to be expired, so it is
        used until the provider rejects it — which `transport.py` turns into
        `auth_required`. Guessing an expiry for it would either refresh
        needlessly or, worse, treat a live credential as dead.

        `skew_s` refreshes slightly early so a token cannot expire in flight
        between this check and the provider reading it.
        """
        if self.expires_at is None:
            return False
        return now >= self.expires_at - skew_s

    def __repr__(self) -> str:
        # §5.2: never in a log, an exception, or CLI output. `__repr__` is what
        # every one of those reaches for by default.
        return (
            "TokenCredential(access_token=<redacted>, "
            f"has_refresh_token={self.has_refresh_token!r}, "
            f"expires_at={self.expires_at!r}, granted_scope={self.granted_scope!r}, "
            f"token_type={self.token_type!r}, issuer={self.issuer!r})"
        )

    __str__ = __repr__


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ClientRegistration(CredentialMaterial):
    """The result of dynamic client registration (§5.1).

    Credential-shaped even though this is a public client: a `client_id` bound
    to a loopback redirect is the other half of an authorization request, and
    §5.1 says to store it under the same controls as a token. It is therefore
    redacted in `__repr__` alongside the token.

    `issuer` and `redirect_uri` are stored *with* the registration so a stale
    one is detectable. A registration made against a different issuer, or for a
    callback port that has since changed, is not reused: `auth.py` requires a
    fresh `rh-mcp login` instead of quietly authorizing against the wrong
    authorization server.
    """

    client_id: str
    issuer: str
    redirect_uri: str
    registered_at: float = 0.0
    client_id_expires_at: float | None = None

    def __post_init__(self) -> None:
        _require_secret_string("client_id", self.client_id, limit=MAX_CLIENT_ID_CHARS)
        _require_url("issuer", self.issuer)
        _require_url("redirect_uri", self.redirect_uri)
        object.__setattr__(
            self, "registered_at", _optional_seconds("registered_at", self.registered_at)
        )
        object.__setattr__(
            self,
            "client_id_expires_at",
            _optional_seconds("client_id_expires_at", self.client_id_expires_at),
        )

    def is_expired(self, now: float) -> bool:
        """Whether the authorization server has retired this registration.

        RFC 7591 uses `0` to mean "never expires", which is why this is not a
        plain `now >= expires_at`: a falsy-but-present zero must not read as
        "expired at the epoch".
        """
        if self.client_id_expires_at is None or self.client_id_expires_at == 0:
            return False
        return now >= self.client_id_expires_at

    def __repr__(self) -> str:
        return (
            "ClientRegistration(client_id=<redacted>, "
            f"issuer={self.issuer!r}, redirect_uri={self.redirect_uri!r}, "
            f"registered_at={self.registered_at!r})"
        )

    __str__ = __repr__


# --------------------------------------------------------------------------
# Serialization — private, so a caller cannot reach the secret form (§5.2)
# --------------------------------------------------------------------------


def _encode_token(token: TokenCredential) -> bytes:
    return _encode(
        {
            "version": CREDENTIAL_RECORD_VERSION,
            "kind": "token",
            "access_token": token.access_token,
            "refresh_token": token.refresh_token,
            "expires_at": token.expires_at,
            "granted_scope": token.granted_scope,
            "token_type": token.token_type,
            "issuer": token.issuer,
            "obtained_at": token.obtained_at,
        }
    )


def _decode_token(raw: bytes) -> TokenCredential:
    document = _decode(raw, kind="token")
    return TokenCredential(
        access_token=_field(document, "access_token"),
        refresh_token=_field(document, "refresh_token"),
        expires_at=_field(document, "expires_at"),
        granted_scope=_field(document, "granted_scope"),
        token_type=_field(document, "token_type", default="Bearer"),
        issuer=_field(document, "issuer", default=""),
        obtained_at=_field(document, "obtained_at", default=0.0),
    )


def _encode_registration(registration: ClientRegistration) -> bytes:
    return _encode(
        {
            "version": CREDENTIAL_RECORD_VERSION,
            "kind": "client_registration",
            "client_id": registration.client_id,
            "issuer": registration.issuer,
            "redirect_uri": registration.redirect_uri,
            "registered_at": registration.registered_at,
            "client_id_expires_at": registration.client_id_expires_at,
        }
    )


def _decode_registration(raw: bytes) -> ClientRegistration:
    document = _decode(raw, kind="client_registration")
    return ClientRegistration(
        client_id=_field(document, "client_id"),
        issuer=_field(document, "issuer"),
        redirect_uri=_field(document, "redirect_uri"),
        registered_at=_field(document, "registered_at", default=0.0),
        client_id_expires_at=_field(document, "client_id_expires_at"),
    )


def _field(document: Mapping[str, Any], name: str, *, default: Any = None) -> Any:
    return document.get(name, default)


def _encode(document: Mapping[str, Any]) -> bytes:
    payload = json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(payload) > MAX_SECRET_BYTES:
        _fail(ErrorCode.CONFIGURATION_ERROR, "a credential record is too large to store")
    return payload


def _decode(raw: bytes, *, kind: CredentialKind) -> Mapping[str, Any]:
    """Read a stored record back, refusing anything it is not.

    A stored credential is not attacker-controlled in the ordinary sense, but
    it is a file (or a keychain item) that something else on the machine may
    have written. It gets the same treatment as a provider payload: bounded,
    typed, and never quoted in an error.
    """
    if len(raw) > MAX_SECRET_BYTES:
        _fail(ErrorCode.CONFIGURATION_ERROR, "a stored credential record is too large")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "a stored credential record is unreadable; run `rh-mcp login`",
        )
    if not isinstance(document, Mapping):
        _fail(ErrorCode.CONFIGURATION_ERROR, "a stored credential record is not an object")
    if document.get("version") != CREDENTIAL_RECORD_VERSION:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "a stored credential record uses an unsupported format version; run `rh-mcp login`",
        )
    if document.get("kind") != kind:
        # A registration read as a token — or the reverse — means the store's
        # keying is wrong. Refuse rather than construct a record from the
        # fields that happen to overlap.
        _fail(ErrorCode.CONFIGURATION_ERROR, "a stored credential record has the wrong kind")
    return document


# --------------------------------------------------------------------------
# The protocol (§5.2)
# --------------------------------------------------------------------------


class CredentialStore(Protocol):
    """Read, atomic update, and delete for the two credential-shaped records.

    Narrow on purpose. There is no "list", no "read raw", no "export", and no
    way to obtain the serialized form — those are the operations that turn a
    credential store into a credential leak.

    `exclusive()` is the cross-process mutex an adapter provides when more than
    one process can share the credential. Hold it around any read-modify-write;
    the individual methods do not take it, so that a sequence inside
    `exclusive()` cannot deadlock against itself.
    """

    @property
    def namespace(self) -> str: ...

    def exclusive(self) -> AbstractAsyncContextManager[None]: ...

    async def load_token(self) -> TokenCredential | None: ...

    async def store_token(self, token: TokenCredential) -> None: ...

    async def delete_token(self) -> bool: ...

    async def load_registration(self) -> ClientRegistration | None: ...

    async def store_registration(self, registration: ClientRegistration) -> None: ...

    async def delete_registration(self) -> bool: ...


class _BytesBackedStore:
    """Shared record<->bytes plumbing for the concrete adapters.

    An adapter implements three byte operations; the record types, their
    validation, and their redaction stay in exactly one place. A second copy of
    `_decode_token` in each adapter is how one of them ends up accepting a
    record the others reject.
    """

    def __init__(self, namespace: str) -> None:
        self._namespace = namespace

    @property
    def namespace(self) -> str:
        return self._namespace

    async def _read(self, kind: CredentialKind) -> bytes | None:
        raise NotImplementedError  # pragma: no cover - abstract

    async def _write(self, kind: CredentialKind, payload: bytes) -> None:
        raise NotImplementedError  # pragma: no cover - abstract

    async def _remove(self, kind: CredentialKind) -> bool:
        raise NotImplementedError  # pragma: no cover - abstract

    def exclusive(self) -> AbstractAsyncContextManager[None]:
        return _no_lock()

    async def load_token(self) -> TokenCredential | None:
        raw = await self._read("token")
        return None if raw is None else _decode_token(raw)

    async def store_token(self, token: TokenCredential) -> None:
        if not isinstance(token, TokenCredential):
            _fail(ErrorCode.CONFIGURATION_ERROR, "store_token requires a TokenCredential")
        await self._write("token", _encode_token(token))

    async def delete_token(self) -> bool:
        return await self._remove("token")

    async def load_registration(self) -> ClientRegistration | None:
        raw = await self._read("client_registration")
        return None if raw is None else _decode_registration(raw)

    async def store_registration(self, registration: ClientRegistration) -> None:
        if not isinstance(registration, ClientRegistration):
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                "store_registration requires a ClientRegistration",
            )
        await self._write("client_registration", _encode_registration(registration))

    async def delete_registration(self) -> bool:
        return await self._remove("client_registration")


@asynccontextmanager
async def _no_lock() -> AsyncIterator[None]:
    yield


# --------------------------------------------------------------------------
# In-memory adapter — tests only (§5.2, §11)
# --------------------------------------------------------------------------


class InMemoryCredentialStore(_BytesBackedStore):
    """A store that never touches the filesystem or a keychain (§11).

    It holds the *serialized* bytes rather than the record objects, so a test
    exercises the same encode/decode path production does; a store that handed
    back the very object it was given would hide a serialization bug.

    Single-process by definition, so `exclusive()` is a plain `asyncio.Lock`:
    there is no second process to serialize against, and pretending otherwise
    with a lock file would make the tests slower and no more truthful.
    """

    def __init__(self, namespace: str = "dev-in-memory") -> None:
        super().__init__(namespace)
        self._records: dict[CredentialKind, bytes] = {}
        self._lock = asyncio.Lock()

    def exclusive(self) -> AbstractAsyncContextManager[None]:
        return self._lock

    async def _read(self, kind: CredentialKind) -> bytes | None:
        return self._records.get(kind)

    async def _write(self, kind: CredentialKind, payload: bytes) -> None:
        self._records[kind] = payload

    async def _remove(self, kind: CredentialKind) -> bool:
        return self._records.pop(kind, None) is not None


# --------------------------------------------------------------------------
# File adapter — explicit local development only (§5.2)
# --------------------------------------------------------------------------


def default_credential_directory() -> Path:
    """Where the development store lives when nothing says otherwise."""
    return Path(os.path.expanduser("~")) / ".rh-mcp" / "credentials"


class FileCredentialStore(_BytesBackedStore):
    """Plaintext credentials on disk, for local development and nothing else.

    §5.2 makes this "an explicit local-development option only", and the
    constructor enforces every clause of that sentence rather than trusting the
    caller to have read it: a `dev-` namespace, directory `0700`, file `0600`,
    atomic replacement, restrictive creation permissions, and inter-process
    locking.

    The permission checks run on read as well as write. A file this process
    created `0600` can be `0644` by the time it is read again, and that is
    precisely the state worth refusing.
    """

    def __init__(
        self,
        namespace: str,
        *,
        directory: Path | str | None = None,
        lock_timeout_s: float = 10.0,
    ) -> None:
        check_namespace(namespace, mode="development")
        if not namespace.startswith(DEV_NAMESPACE_PREFIX):  # pragma: no cover - checked above
            _fail(ErrorCode.CONFIGURATION_ERROR, "the file store requires a development namespace")
        super().__init__(namespace)
        base = default_credential_directory() if directory is None else Path(directory)
        self._directory = base / namespace
        self._lock_timeout_s = lock_timeout_s
        self._process_lock = asyncio.Lock()

    @property
    def directory(self) -> Path:
        return self._directory

    def _path(self, kind: CredentialKind) -> Path:
        return self._directory / f"{kind}.json"

    def exclusive(self) -> AbstractAsyncContextManager[None]:
        return self._exclusive()

    @asynccontextmanager
    async def _exclusive(self) -> AsyncIterator[None]:
        """In-process mutex plus an `flock` other processes respect (§5.2).

        Both are needed and neither substitutes for the other: `asyncio.Lock`
        serializes tasks in this interpreter, `flock` serializes interpreters.
        The lock file holds no credential material and is never read.
        """
        async with self._process_lock:
            await asyncio.to_thread(self._ensure_directory)
            handle = await asyncio.to_thread(self._acquire_flock)
            try:
                yield
            finally:
                await asyncio.to_thread(_release_flock, handle)

    def _acquire_flock(self) -> Any:
        return _acquire_flock(self._directory / ".lock", self._lock_timeout_s)

    # -- byte operations ---------------------------------------------------

    async def _read(self, kind: CredentialKind) -> bytes | None:
        return await asyncio.to_thread(self._read_sync, self._path(kind))

    async def _write(self, kind: CredentialKind, payload: bytes) -> None:
        await asyncio.to_thread(self._write_sync, self._path(kind), payload)

    async def _remove(self, kind: CredentialKind) -> bool:
        return await asyncio.to_thread(_unlink_sync, self._path(kind))

    def _read_sync(self, path: Path) -> bytes | None:
        # The directory is checked here as well as on write. The class
        # docstring has always claimed "the permission checks run on read as
        # well as write", and for the *file* that was true — but the directory
        # check only ever ran from `_ensure_directory`, which the read path
        # never calls. So a credential directory widened by a stray `chmod -R`
        # was refused at the next write and served happily on every read, which
        # is the high-frequency path. A missing directory is not a fault: it
        # just means nothing is stored yet.
        try:
            info = os.stat(self._directory)
        except FileNotFoundError:
            return None
        _check_directory_security(info, "the development credential directory")
        try:
            # `O_NOFOLLOW` so a symlink dropped in place of the credential file
            # cannot redirect this read — or, on a later write, cause a write
            # through it to somewhere else entirely.
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError:
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                "the development credential file could not be opened; it may be a symlink",
            )
        try:
            info = os.fstat(descriptor)
            _check_file_security(info, "the development credential file")
            if info.st_size > MAX_SECRET_BYTES:
                _fail(ErrorCode.CONFIGURATION_ERROR, "the development credential file is too large")
            return os.read(descriptor, MAX_SECRET_BYTES)
        finally:
            os.close(descriptor)

    def _write_sync(self, path: Path, payload: bytes) -> None:
        self._ensure_directory()
        # A distinct temporary name per process and per write, created
        # `O_EXCL | O_NOFOLLOW` at mode 0600, then renamed over the target.
        # `os.replace` is atomic within a filesystem, so a concurrent reader
        # sees either the old record or the new one and never a partial write.
        temporary = path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(6).hex()}.tmp")
        # The mode is the *creation* mode, which umask can only narrow, never
        # widen — so 0600 here is an upper bound and no follow-up `fchmod` is
        # needed. An earlier draft had one "in case of a permissive umask";
        # mutation testing showed removing it changed nothing, which is how the
        # misunderstanding surfaced. `O_EXCL` means this is always a fresh
        # file, so there is no pre-existing mode to inherit either.
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            written = os.write(descriptor, payload)
            if written != len(payload):  # pragma: no cover - short write on a local file
                _fail(ErrorCode.CONFIGURATION_ERROR, "the credential record was not fully written")
            os.fsync(descriptor)
        except BaseException:
            os.close(descriptor)
            _unlink_sync(temporary)
            raise
        os.close(descriptor)
        try:
            os.replace(temporary, path)
        except OSError:
            _unlink_sync(temporary)
            _fail(ErrorCode.CONFIGURATION_ERROR, "the credential record could not be replaced")
        _fsync_directory(self._directory)

    def _ensure_directory(self) -> None:
        """Create the credential directory at 0700, or refuse what is there.

        Deliberately *no* `chmod` on an existing directory. An earlier draft
        had one, with a comment claiming a pre-existing group-readable
        directory would be "refused rather than reused" — which the chmod made
        false, because it silently repaired the mode and then passed its own
        check. Mutation testing found it: removing the chmod broke nothing.

        Refusing is the right behaviour. A credential directory that is already
        group-readable may have been group-readable while a token sat in it,
        and repairing the mode does not un-read anything. An operator gets a
        clear error and decides.
        """
        self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        _check_directory_security(os.stat(self._directory), "the development credential directory")


def _check_file_security(info: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(info.st_mode):
        _fail(ErrorCode.CONFIGURATION_ERROR, f"{label} is not a regular file")
    if info.st_uid != os.getuid():
        _fail(ErrorCode.CONFIGURATION_ERROR, f"{label} is owned by another user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            f"{label} is readable or writable by group or other; it must be mode 0600",
        )


def _check_directory_security(info: os.stat_result, label: str) -> None:
    if info.st_uid != os.getuid():
        _fail(ErrorCode.CONFIGURATION_ERROR, f"{label} is owned by another user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            f"{label} is accessible by group or other; it must be mode 0700",
        )


def _unlink_sync(path: Path) -> bool:
    try:
        os.unlink(path)
    except FileNotFoundError:
        return False
    except OSError:
        _fail(ErrorCode.CONFIGURATION_ERROR, "a credential file could not be removed")
    return True


def _fsync_directory(directory: Path) -> None:
    """Make the rename durable. Best effort: not every filesystem allows it."""
    try:
        descriptor = os.open(directory, os.O_RDONLY)
    except OSError:  # pragma: no cover - platform dependent
        return
    try:
        os.fsync(descriptor)
    except OSError:  # pragma: no cover - platform dependent
        pass
    finally:
        os.close(descriptor)


def _acquire_flock(path: Path, timeout_s: float) -> Any:
    """Take an exclusive `flock`, or fail rather than wait forever.

    A blocking `flock` would hang a read broker indefinitely behind a crashed
    or wedged sibling. The public code is `timeout` and retryable: the
    condition is transient contention that a caller can reasonably retry, not a
    misconfiguration and not a reason to declare the gateway not ready.
    """
    if fcntl is None:  # pragma: no cover - Windows only
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "inter-process credential locking is unavailable on this platform",
        )
    handle = open(path, "a+b")  # noqa: SIM115 - the caller owns the lifetime
    try:
        os.fchmod(handle.fileno(), 0o600)
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return handle
            except OSError:
                if time.monotonic() >= deadline:
                    _fail(
                        ErrorCode.TIMEOUT,
                        "another process holds the credential lock",
                        retryable=True,
                    )
                time.sleep(0.02)
    except BaseException:
        handle.close()
        raise


def _release_flock(handle: Any) -> None:
    try:
        if fcntl is not None:  # pragma: no branch - None only on Windows
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


# --------------------------------------------------------------------------
# macOS Keychain adapter — the production store (§5.2)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CommandResult(CredentialMaterial):
    """What a `security` invocation returned.

    **`stdout` is the credential on the read path.** `find-generic-password -w`
    writes the base64 record — access token, refresh token and all — to stdout,
    so this type holds strictly more secret material than any other value in
    this module apart from the records themselves. It therefore gets the same
    redacted `__repr__` they do. It was missed in the first version of this
    module: `stderr` had been reasoned about carefully and `stdout` was left in
    the default dataclass repr, which is exactly the shape of oversight the
    §5.2 redaction rule exists to catch. Nothing printed it, but a single
    `logger.debug("%s", result)`, a `pytest --showlocals`, or an error reporter
    that serializes frame locals would have.

    `stderr` is deliberately absent as defence in depth: this adapter needs
    only the exit status, so it is the only thing it is given. An earlier
    version of this docstring justified that by claiming `security` echoes
    fragments of the failing command, which would put the write command's
    payload in stderr. An independent review could not reproduce that — a
    failed `add-generic-password` produces a generic usage block with no trace
    of the payload — so the claim is withdrawn. Dropping `stderr` is still
    right, on the narrower ground that a field which cannot be read cannot
    leak; it just is not defending against the thing that was written here.
    """

    returncode: int
    stdout: str

    def __repr__(self) -> str:
        return f"CommandResult(returncode={self.returncode!r}, stdout=<redacted>)"

    __str__ = __repr__


SecurityRunner = Callable[[list[str], str | None], CommandResult]
"""`(argv, stdin) -> CommandResult`. Injected so tests never touch a Keychain."""


def _run_security(argv: list[str], stdin: str | None) -> CommandResult:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        _fail(
            ErrorCode.CONFIGURATION_ERROR,
            "the macOS `security` tool was not found; the keychain adapter needs macOS",
        )
    except subprocess.TimeoutExpired:
        _fail(ErrorCode.TIMEOUT, "the macOS `security` tool did not answer in time", retryable=True)
    # `completed.stderr` is discarded here and nowhere else, on purpose.
    return CommandResult(completed.returncode, completed.stdout)


class KeychainCredentialStore(_BytesBackedStore):
    """The production store: a macOS login-keychain generic password (§5.2).

    Reads and deletes name only the service and account on the command line.
    Writes go through `security -i`, which takes its command from stdin, so the
    token never appears in `argv` and therefore never in another process's view
    of the process table.

    Two properties are enforced rather than assumed. Exactly one command is
    written per invocation, because `security -i` reports only the *last*
    command's status — a batch would silently swallow a failed write. And the
    payload is validated against the base64 alphabet before the command line is
    built, so no value can smuggle a newline and append a second command.

    `-A` is deliberately not passed. Without it the created item's ACL admits
    only the creating application, so an arbitrary other program cannot read
    the token without the user being asked.
    """

    def __init__(
        self,
        namespace: str,
        *,
        mode: str = "production",
        runner: SecurityRunner | None = None,
        lock_directory: Path | str | None = None,
        lock_timeout_s: float = 10.0,
    ) -> None:
        check_namespace(namespace, mode=mode)
        super().__init__(namespace)
        self._service = f"rh-mcp:{namespace}"
        if not _KEYCHAIN_ATTRIBUTE_PATTERN.fullmatch(self._service):
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                "the credential namespace produces an unusable keychain service name",
            )
        self._runner = _run_security if runner is None else runner
        base = default_credential_directory() if lock_directory is None else Path(lock_directory)
        self._lock_path_directory = base / namespace
        self._lock_timeout_s = lock_timeout_s
        self._process_lock = asyncio.Lock()

    # -- locking -----------------------------------------------------------

    def exclusive(self) -> AbstractAsyncContextManager[None]:
        return self._exclusive()

    @asynccontextmanager
    async def _exclusive(self) -> AsyncIterator[None]:
        """A keychain item is shared by every process of the user (§5.2).

        So this adapter needs the cross-process serialization too, and it
        cannot get it from the keychain, which offers no compare-and-swap. The
        lock is a mode-0600 file in a mode-0700 directory that holds nothing —
        no credential material touches the disk on this path.
        """
        async with self._process_lock:
            await asyncio.to_thread(self._ensure_lock_directory)
            handle = await asyncio.to_thread(
                _acquire_flock, self._lock_path_directory / ".lock", self._lock_timeout_s
            )
            try:
                yield
            finally:
                await asyncio.to_thread(_release_flock, handle)

    def _ensure_lock_directory(self) -> None:
        self._lock_path_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        _check_directory_security(
            os.stat(self._lock_path_directory), "the credential lock directory"
        )

    @property
    def max_record_bytes(self) -> int:
        """The largest serialized record this store can actually hold.

        Derived from the real `security -i` line budget minus this store's own
        command overhead, so a longer namespace correctly reports a smaller
        ceiling. Public because "how big a credential fits" is a property of
        the adapter that a caller may reasonably want before trying.
        """
        overhead = len(
            f"add-generic-password -U -a {self._account('token')} -s {self._service} -w \n"
        )
        available = max(0, SECURITY_MAX_COMMAND_LINE_BYTES - overhead)
        # Undo base64's 4-chars-per-3-bytes expansion to get the raw budget.
        return available // 4 * 3

    # -- byte operations ---------------------------------------------------

    async def _read(self, kind: CredentialKind) -> bytes | None:
        result = await asyncio.to_thread(
            self._runner,
            [
                "security",
                "find-generic-password",
                "-a",
                self._account(kind),
                "-s",
                self._service,
                "-w",
            ],
            None,
        )
        if result.returncode == _SECURITY_ITEM_NOT_FOUND:
            return None
        if result.returncode != 0:
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                f"reading the keychain credential failed with status {result.returncode}",
            )
        encoded = result.stdout.strip()
        if not encoded:
            _fail(ErrorCode.CONFIGURATION_ERROR, "the keychain returned an empty credential")
        if not _BASE64_PATTERN.fullmatch(encoded):
            _fail(ErrorCode.CONFIGURATION_ERROR, "the keychain credential is not valid base64")
        try:
            return base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            _fail(ErrorCode.CONFIGURATION_ERROR, "the keychain credential could not be decoded")

    async def _write(self, kind: CredentialKind, payload: bytes) -> None:
        encoded = base64.b64encode(payload).decode("ascii")
        # Belt and braces: `b64encode` cannot produce anything outside this
        # alphabet, and the command line below is only safe because of it. The
        # check is what makes that reasoning verifiable instead of trusted.
        if not _BASE64_PATTERN.fullmatch(encoded):  # pragma: no cover - unreachable by construction
            _fail(ErrorCode.CONFIGURATION_ERROR, "the encoded credential is not valid base64")
        account = self._account(kind)
        # Exactly one command. `security -i` reports the status of the last
        # command only, so a second line here would make a failed write look
        # like a success.
        command = f"add-generic-password -U -a {account} -s {self._service} -w {encoded}\n"
        if len(command.encode("ascii")) > SECURITY_MAX_COMMAND_LINE_BYTES:
            # Measured, not guessed — see SECURITY_MAX_COMMAND_LINE_BYTES. The
            # record's own size is not named: the limit and the remedy are the
            # actionable half, and a token's length is not this module's to
            # publish (§7.3).
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                "this credential is too large for the macOS keychain adapter: `security -i` "
                f"refuses an input line beyond {SECURITY_MAX_COMMAND_LINE_BYTES} bytes, which "
                f"caps a stored record at about {self.max_record_bytes} bytes. Use an injected "
                "secret-manager adapter for a credential this size",
            )
        result = await asyncio.to_thread(self._runner, ["security", "-i"], command)
        if result.returncode != 0:
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                f"writing the keychain credential failed with status {result.returncode}",
            )

    async def _remove(self, kind: CredentialKind) -> bool:
        result = await asyncio.to_thread(
            self._runner,
            [
                "security",
                "delete-generic-password",
                "-a",
                self._account(kind),
                "-s",
                self._service,
            ],
            None,
        )
        if result.returncode == _SECURITY_ITEM_NOT_FOUND:
            return False
        if result.returncode != 0:
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                f"deleting the keychain credential failed with status {result.returncode}",
            )
        # `delete-generic-password` prints the item's attributes on stdout. They
        # are not the password, but they are not this gateway's to echo either,
        # so `result.stdout` is dropped here without being inspected.
        return True

    def _account(self, kind: CredentialKind) -> str:
        if kind not in _KINDS:  # pragma: no cover - the Literal already constrains it
            _fail(ErrorCode.CONFIGURATION_ERROR, "unknown credential kind")
        account = f"rh-mcp-{kind}"
        if not _KEYCHAIN_ATTRIBUTE_PATTERN.fullmatch(account):  # pragma: no cover - constant
            _fail(ErrorCode.CONFIGURATION_ERROR, "unusable keychain account name")
        return account


# --------------------------------------------------------------------------
# The factory (§3, §5.2, §9)
# --------------------------------------------------------------------------


def open_credential_store(
    config: GatewayConfig,
    *,
    directory: Path | str | None = None,
    runner: SecurityRunner | None = None,
) -> CredentialStore:
    """Build the adapter this configuration names, refusing forbidden pairings.

    `GatewayConfig` already refuses `file_dev` in production. This checks it
    again, because the pairing that matters — a production-mode gateway reading
    a plaintext credential file — is the one §3 and §5.2 both single out, and a
    second check costs one comparison. It also runs the namespace policy, which
    `config.py` does not know about in full.
    """
    check_namespace(config.credential_namespace, mode=config.mode)

    if config.credential_adapter == "keychain":
        if sys.platform != "darwin":
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                "the keychain adapter requires macOS; supply an injected secret-manager "
                "adapter on another platform",
            )
        return KeychainCredentialStore(
            config.credential_namespace,
            mode=config.mode,
            runner=runner,
            lock_directory=directory,
        )
    if config.credential_adapter == "file_dev":
        if config.mode == "production":
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                "the file credential adapter stores a write-capable token in plaintext and "
                "is refused in production mode",
            )
        return FileCredentialStore(config.credential_namespace, directory=directory)
    if config.credential_adapter == "in_memory":
        if config.mode == "production":
            _fail(
                ErrorCode.CONFIGURATION_ERROR,
                "the in-memory credential adapter is a test double and is refused in "
                "production mode",
            )
        return InMemoryCredentialStore(config.credential_namespace)
    # Unreachable while `CredentialAdapter` is a closed Literal, and kept so a
    # new adapter cannot be added without deciding its production policy.
    _fail(  # pragma: no cover - defensive
        ErrorCode.CONFIGURATION_ERROR,
        f"unknown credential adapter {config.credential_adapter!r}",
    )


__all__ = [
    "CREDENTIAL_RECORD_VERSION",
    "DEV_NAMESPACE_PREFIX",
    "WRITE_NAMESPACE_PREFIX",
    "ClientRegistration",
    "CommandResult",
    "CredentialKind",
    "CredentialMaterial",
    "CredentialStore",
    "FileCredentialStore",
    "InMemoryCredentialStore",
    "KeychainCredentialStore",
    "SecurityRunner",
    "TokenCredential",
    "check_namespace",
    "default_credential_directory",
]

# `open_credential_store` is deliberately absent. It is still importable — the
# CLI and the gateway both call it, and renaming it would be churn without
# safety, since an underscore stops nobody who has already typed the module
# name. What the removal ends is the *advertisement*.
#
# On its own this factory yields a store, not a session, and a store is not a
# trading path. It became one in combination: paired with the exported
# `StoredTokenProvider` and the exported `open_provider_session`, the three
# published names assembled a write-capable MCP session with no manifest in it,
# and an independent reviewer walked exactly that chain. The chain is broken at
# `_open_provider_session`; this line removes the signpost.
