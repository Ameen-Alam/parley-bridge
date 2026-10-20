"""The assistant connection, bridge side: outbound only, reconnecting, acknowledged.

What this module does (criterion 3; stories 9.1 and 9.2; requirements 6b overnight
reliability rows; T-0007's wire protocol in :mod:`parley_relay.connection`):

- A :class:`Connection` holds one link to the relay at a time: the WebSocket
  ``/connect`` first, the long-poll fallback (``/connect/session``, ``/poll``, ``/ack``)
  when the WebSocket upgrade is refused, for instance by a proxy. The bridge opens no
  listening port: every link is opened from here towards ``PARLEY_RELAY_URL``.
- It proves the device key by signing the relay's challenge. Two payloads exist during
  the transition to T-0018: the domain-separated one, ``b"parley-connect\\0" + device_id
  + challenge bytes`` (T-0018 criterion 3, the one the relay accepts after it merges),
  and the bare challenge bytes the relay accepts until then.
  ``PARLEY_BRIDGE_CHALLENGE_PAYLOAD`` is ``auto`` (default: the domain-separated payload,
  switching to bare only when the relay closes with ``unknown-payload`` or
  ``bad-payload``, a reason that says the form is unknown; a plain ``bad-signature``
  never switches it), ``domain`` or ``bare``. Against a relay from before T-0018 set
  ``bare`` explicitly. In both forms the challenge must decode to exactly
  :data:`CHALLENGE_BYTES` bytes, so a hostile relay can never obtain a device-key
  signature over bytes of its choosing (such as an envelope).
- The WebSocket's TCP connection comes from :mod:`parley_bridge.dial`, which races the
  relay's IPv6 and IPv4 addresses, so a host without working IPv6 still connects
  (T-0053); the long poll's HTTP client does the same.
- A dropped link is reopened with a backoff of 1, 2, 4 ... 60 seconds, each wait with
  about 25 percent jitter, and the backoff resets only after a link survived
  :data:`STABLE_SECONDS` (6b). Two bridges at Gate 1 reconnecting after a relay restart
  are back within 1 to 2 seconds, and in the worst case of a relay down for a while they
  are back at most 75 seconds after it returns; held messages come in the first frame
  after the reconnect, so the 10-second rule of 6b holds from the moment the link is up.
  A relay that answers ``revoked-device`` ends the loop: the bridge is unlinked and says
  so, instead of retrying every minute.
- Every wake-up frame is acknowledged. With ``PARLEY_BRIDGE_WAKE_COMMAND`` set, the
  command runs once per frame; when it fails the frame is acknowledged ``failed`` and its
  messages stay waiting on the relay (story 9.2). Otherwise the messages wait in memory
  for ``check_inbox``, and the frame is acknowledged ``done`` once every message in it
  has been handed to the assistant. A frame resent after a drop is deduplicated by
  request ID, so the assistant never sees a message twice.
- Nothing is written to disk. Log lines (``--verbose``) carry wake-up IDs, request IDs,
  counts, codes and times; never a body, a token or a key.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from parley_bridge.config import Settings
from parley_bridge.dial import DIALER, Dialer
from parley_bridge.keys import DeviceKey
from parley_bridge.relay import (
    POLL_WAIT_SECONDS,
    RelayClient,
    RelayRefusedError,
    RelayUnreachableError,
    clean,
)
from parley_common import signing
from parley_common.clock import now_iso

log = logging.getLogger("parley_bridge.connection")

DOMAIN_PREFIX = b"parley-connect\0"
CHALLENGE_BYTES = 32
"""The relay's challenge is exactly this long (its ``CHALLENGE_BYTES``); anything else is
refused before signing, so no relay-chosen payload is ever signed with the device key."""
MIN_BACKOFF = 1.0
MAX_BACKOFF = 60.0
JITTER = 0.25
"""Each wait is scaled by a factor drawn from ``1 - JITTER`` to ``1 + JITTER``."""
STABLE_SECONDS = 5.0
"""A link that lived this long resets the backoff; a shorter one keeps doubling."""
UNLINKED = "revoked-device"
PAYLOAD_UNKNOWN = frozenset({"unknown-payload", "bad-payload"})
"""Close reasons that say the relay does not know the payload form; the only reasons
that switch ``auto`` from the domain-separated payload to the bare one."""
WAKE_TIMEOUT = 120.0
"""Seconds the wake command may run before the frame is acknowledged ``failed``."""
SEEN_LIMIT = 10_000
"""Request IDs remembered for deduplication."""
AUTH_REFUSALS = frozenset(
    {"unknown-device", "bad-signature", "bad-challenge", "not-assistant", "revoked-device"}
)
WEBSOCKET = "websocket"
POLL = "poll"


# ---------------------------------------------------------------- errors and links


class LinkError(Exception):
    """A link could not be opened or ended. Messages carry no value from the relay."""


class ChallengeError(ValueError):
    """The relay's challenge is not canonical base64url of exactly 32 bytes."""


class LinkClosedError(LinkError):
    """The link ended; ``reason`` is the relay's close reason or ``disconnect``."""

    def __init__(self, reason: str) -> None:
        super().__init__("the link closed")
        self.reason = reason


class AuthRefusedError(LinkError):
    """The relay refused the challenge answer with a stable ``code``."""

    def __init__(self, code: str) -> None:
        super().__init__("the relay refused the device key")
        self.code = code


class UpgradeRefusedError(LinkError):
    """The WebSocket upgrade did not happen (an HTTP answer instead): fall back to polling."""


class UnavailableError(LinkError):
    """The relay could not be reached or did not answer in time."""


class Link(Protocol):
    """One authenticated connection. Frames are the dicts of the wire protocol."""

    transport: str

    async def receive(self) -> dict[str, Any]: ...

    async def send(self, frame: dict[str, Any]) -> None: ...

    async def close(self) -> None: ...


Opener = Callable[[str, DeviceKey, str], Awaitable[Link]]
"""``opener(transport, key, payload_format)`` returns an authenticated :class:`Link` or
raises :class:`AuthRefusedError`, :class:`UpgradeRefusedError` or
:class:`UnavailableError`."""


def challenge_payload(device_id: str, challenge: str, payload_format: str) -> bytes:
    """The bytes the bridge signs: the domain-separated payload or the bare challenge.

    The challenge must be canonical base64url of exactly :data:`CHALLENGE_BYTES` bytes in
    both forms; anything else raises :class:`ChallengeError` and nothing is signed.
    """
    if not isinstance(challenge, str) or len(challenge) > 64:
        raise ChallengeError("the challenge is not what the relay sends")
    try:
        challenge_bytes = signing.b64url_decode(challenge)
    except ValueError as error:
        raise ChallengeError("the challenge is not canonical base64url") from error
    if len(challenge_bytes) != CHALLENGE_BYTES:
        raise ChallengeError("the challenge is not 32 bytes")
    if payload_format == "bare":
        return challenge_bytes
    return DOMAIN_PREFIX + device_id.encode("utf-8") + challenge_bytes


def sign_challenge(key: DeviceKey, challenge: str, payload_format: str) -> str:
    return signing.sign(
        challenge_payload(key.device_id, challenge, payload_format), key.private_key
    )


# ---------------------------------------------------------------- WebSocket link


class WebSocketLink:
    transport = WEBSOCKET

    def __init__(self, socket: Any) -> None:
        self._socket = socket

    async def receive(self) -> dict[str, Any]:
        import json

        from websockets.exceptions import ConnectionClosed

        try:
            raw = await self._socket.recv()
        except ConnectionClosed as error:
            raise LinkClosedError(_close_reason(error)) from error
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        try:
            frame = json.loads(raw)
        except ValueError:
            return {"type": "unparseable"}
        return frame if isinstance(frame, dict) else {"type": "unparseable"}

    async def send(self, frame: dict[str, Any]) -> None:
        import json

        from websockets.exceptions import ConnectionClosed

        try:
            await self._socket.send(json.dumps(frame))
        except ConnectionClosed as error:
            raise LinkClosedError(_close_reason(error)) from error

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            await self._socket.close()


def _close_reason(error: Any) -> str:
    received = getattr(error, "rcvd", None)
    reason = clean(getattr(received, "reason", None), 64)
    return reason or "disconnect"


async def _dial_websocket(url: str, dialer: Dialer) -> Any:
    """``connect`` over a socket the dialer raced to the first address that answered
    (T-0053). With a proxy in the environment websockets dials the proxy itself."""
    from websockets.asyncio.client import connect
    from websockets.proxy import get_proxy
    from websockets.uri import parse_uri

    uri = parse_uri(url)
    if get_proxy(uri) is not None:
        return await connect(url, open_timeout=15, max_size=2**22)
    sock = await dialer.open_socket(uri.host, uri.port)
    try:
        return await connect(url, sock=sock, open_timeout=15, max_size=2**22)
    except BaseException:
        sock.close()
        raise


async def open_websocket(
    settings: Settings, key: DeviceKey, payload_format: str, dialer: Dialer = DIALER
) -> Link:
    """Open ``WS /connect`` and answer the challenge. Outbound; no port is opened here."""
    from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidURI

    try:
        socket = await _dial_websocket(settings.websocket_url, dialer)
    except InvalidHandshake as error:
        raise UpgradeRefusedError("the relay did not accept the WebSocket upgrade") from error
    except (OSError, InvalidURI, TimeoutError) as error:
        raise UnavailableError("the relay could not be reached") from error
    link = WebSocketLink(socket)
    try:
        challenge = await asyncio.wait_for(link.receive(), 15)
        if challenge.get("type") != "challenge" or not isinstance(challenge.get("challenge"), str):
            await link.close()
            raise UnavailableError("the relay did not send a challenge")
        signature = sign_challenge(key, challenge["challenge"], payload_format)
        await link.send({"type": "auth", "device_id": key.device_id, "signature": signature})
        connected = await asyncio.wait_for(link.receive(), 15)
    except ValueError as error:
        await link.close()
        raise UnavailableError("the relay sent a challenge the bridge refuses") from error
    except LinkClosedError as error:
        await link.close()
        if error.reason in AUTH_REFUSALS:
            raise AuthRefusedError(error.reason) from error
        raise UnavailableError("the relay closed before the connection was made") from error
    except (ConnectionClosed, TimeoutError, OSError) as error:
        await link.close()
        raise UnavailableError("the relay closed before the connection was made") from error
    if connected.get("type") != "connected":
        await link.close()
        raise UnavailableError("the relay did not confirm the connection")
    return link


# ---------------------------------------------------------------- long-poll link


class PollLink:
    """The same frames over ``GET /poll`` and ``POST /ack`` with a session token.

    A poll is a reconnect on the relay: a frame left unacknowledged comes again. So while
    a wake-up frame is outstanding this link does not poll; it waits for the
    acknowledgement, then polls again.
    """

    transport = POLL

    def __init__(self, client: RelayClient, token: str) -> None:
        self._client = client
        self._token = token
        self._outstanding: str | None = None
        self._acked = asyncio.Event()
        self._acked.set()
        self._closed = False

    async def receive(self) -> dict[str, Any]:
        await self._acked.wait()
        if self._closed:
            raise LinkClosedError("closed")
        try:
            frame = await self._client.poll(self._token, POLL_WAIT_SECONDS)
        except RelayRefusedError as error:
            self._closed = True
            raise LinkClosedError(error.code) from error
        except RelayUnreachableError as error:
            self._closed = True
            raise LinkClosedError("disconnect") from error
        if frame.get("type") == "wakeup" and isinstance(frame.get("wakeup_id"), str):
            self._outstanding = clean(frame["wakeup_id"], 64)
            self._acked.clear()
        return frame

    async def send(self, frame: dict[str, Any]) -> None:
        kind = frame.get("type")
        if kind == "ack":
            wakeup_id = frame.get("wakeup_id")
            result = frame.get("result")
            if not isinstance(wakeup_id, str) or not isinstance(result, str):
                return
            try:
                answer = await self._client.ack(self._token, wakeup_id, result)
                log.info(
                    "ack answered type=%s code=%s",
                    clean(answer.get("type"), 32),
                    clean(answer.get("code"), 64),
                )
            except RelayRefusedError as error:
                log.info("ack refused wakeup_id=%s code=%s", wakeup_id, error.code)
                if error.status == 401:
                    self._closed = True
                    self._acked.set()
                    raise LinkClosedError(error.code) from error
            except RelayUnreachableError as error:
                self._closed = True
                self._acked.set()
                raise LinkClosedError("disconnect") from error
            finally:
                if wakeup_id == self._outstanding:
                    self._outstanding = None
                    self._acked.set()
        # ``ping`` and ``check`` need nothing here: the next poll is the check.

    async def close(self) -> None:
        self._closed = True
        self._acked.set()


async def open_poll(client: RelayClient, key: DeviceKey, payload_format: str) -> Link:
    """Prove the key over HTTP once and return a :class:`PollLink` with the session token."""
    try:
        challenge = await client.challenge()
        text = challenge.get("challenge")
        if not isinstance(text, str):
            raise UnavailableError("the relay did not send a challenge")
        signature = sign_challenge(key, text, payload_format)
        session = await client.open_session(key.device_id, text, signature)
    except ValueError as error:
        raise UnavailableError("the relay sent a challenge the bridge refuses") from error
    except RelayRefusedError as error:
        if error.code in AUTH_REFUSALS:
            raise AuthRefusedError(error.code) from error
        raise UnavailableError("the relay refused to open a session") from error
    except RelayUnreachableError as error:
        raise UnavailableError("the relay could not be reached") from error
    token = session.get("session")
    if not isinstance(token, str) or not token:
        raise UnavailableError("the relay did not return a session")
    return PollLink(client, token)


def default_opener(settings: Settings, client: RelayClient, dialer: Dialer = DIALER) -> Opener:
    async def opener(transport: str, key: DeviceKey, payload_format: str) -> Link:
        if transport == POLL:
            return await open_poll(client, key, payload_format)
        return await open_websocket(settings, key, payload_format, dialer)

    return opener


# ---------------------------------------------------------------- received messages


@dataclass(frozen=True, slots=True)
class Received:
    """One message as the relay delivered it. The repr shows IDs only."""

    request_id: str
    thread_id: str
    sender_device_id: str
    sender_owner_id: str
    from_other_owner: bool
    kind: str
    sent_at: str
    to: tuple[str, ...]
    addressed: bool
    """The relay's word: it wakes an assistant only with messages addressed to it (CR-10),
    so a message in a frame is addressed unless the frame says otherwise."""
    body: str = field(repr=False)
    wakeup_id: str = field(repr=False)

    @classmethod
    def from_frame(cls, wakeup_id: str, item: dict[str, Any]) -> Received | None:
        envelope = item.get("envelope")
        if not isinstance(envelope, dict):
            return None
        request_id = item.get("request_id") or envelope.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            return None
        body = envelope.get("body")
        to = envelope.get("to")
        return cls(
            request_id=request_id,
            thread_id=str(item.get("thread_id") or envelope.get("thread_id") or request_id),
            sender_device_id=str(item.get("sender_device_id") or envelope.get("sent_by") or ""),
            sender_owner_id=str(item.get("sender_owner_id") or envelope.get("owner") or ""),
            from_other_owner=bool(item.get("from_other_owner", True)),
            kind=str(item.get("kind") or envelope.get("kind") or "chat"),
            sent_at=str(item.get("sent_at") or envelope.get("sent_at") or ""),
            to=tuple(str(x) for x in to) if isinstance(to, list) else (),
            addressed=bool(item.get("addressed", item.get("mentioned", True))),
            body=body if isinstance(body, str) else "",
            wakeup_id=wakeup_id,
        )


@dataclass
class State:
    """What ``check_inbox`` reports about the link. Never a token or a key."""

    status: str = "starting"
    transport: str | None = None
    code: str | None = None
    since: str = field(default_factory=now_iso)
    reconnects: int = 0
    """Retries so far: after a dropped link and after a failed attempt alike (T-0053)."""

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "transport": self.transport,
            "code": self.code,
            "since": self.since,
            "reconnects": self.reconnects,
        }


# ---------------------------------------------------------------- the connection


def _default_jitter() -> float:
    return random.uniform(1 - JITTER, 1 + JITTER)  # noqa: S311 - timing, not security


class Connection:
    def __init__(
        self,
        key: DeviceKey,
        settings: Settings,
        opener: Opener,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        wake: Callable[[str, int], Awaitable[bool]] | None = None,
        jitter: Callable[[], float] | None = None,
    ) -> None:
        self.key = key
        self.settings = settings
        self._opener = opener
        self._sleep = sleep
        self._jitter = jitter if jitter is not None else _default_jitter
        self._wake = wake if wake is not None else self._run_wake_command
        self.state = State()
        self._link: Link | None = None
        self._stopping = asyncio.Event()
        self._inbox: list[Received] = []
        self._frames: dict[str, set[str]] = {}
        self._seen: OrderedDict[str, None] = OrderedDict()
        chosen = settings.challenge_payload
        self._payload_format = "domain" if chosen == "auto" else chosen
        self._websocket_blocked = False
        self._arrived = asyncio.Event()

    # ------------------------------------------------------------ the loop

    async def run(self) -> None:
        """Connect, serve, reconnect with backoff, until :meth:`stop` or the relay says the
        device is revoked (then the state is ``unlinked`` and the loop ends)."""
        delay = MIN_BACKOFF
        while not self._stopping.is_set():
            transport = self._transport()
            self._set_state("connecting", transport)
            try:
                link = await self._opener(transport, self.key, self._payload_format)
            except UpgradeRefusedError:
                if transport == WEBSOCKET and self.settings.transport == "auto":
                    log.info("websocket upgrade refused; falling back to long poll")
                    self._websocket_blocked = True
                self._set_state("unavailable", transport, "upgrade-refused")
            except AuthRefusedError as error:
                code = clean(error.code, 64)
                log.info("connection refused code=%s payload=%s", code, self._payload_format)
                if code == UNLINKED:
                    self._set_state("unlinked", transport, code)
                    log.info("device revoked by the relay; the bridge is unlinked and stops")
                    return
                self._set_state("refused", transport, code)
                if code in PAYLOAD_UNKNOWN and self.settings.challenge_payload == "auto":
                    self._payload_format = "bare"
            except UnavailableError:
                log.info("relay unavailable transport=%s", transport)
                self._set_state("unavailable", transport, "unreachable")
            except asyncio.CancelledError:
                raise
            except Exception as error:  # noqa: BLE001 - the loop must survive; type only
                log.info("connect failed with %s; backing off", type(error).__name__)
                self._set_state("unavailable", transport, "error")
            else:
                self._link = link
                self._set_state("connected", link.transport)
                log.info("connected transport=%s", link.transport)
                opened = asyncio.get_running_loop().time()
                reason = await self._serve(link)
                lived = asyncio.get_running_loop().time() - opened
                self._link = None
                await link.close()
                log.info("link ended reason=%s lived=%.1fs", reason, lived)
                if reason == UNLINKED:
                    self._set_state("unlinked", link.transport, reason)
                    log.info("device revoked by the relay; the bridge is unlinked and stops")
                    return
                self._set_state("reconnecting", link.transport, reason)
                if link.transport == POLL:
                    self._websocket_blocked = False
                if lived >= STABLE_SECONDS:
                    delay = MIN_BACKOFF
                if self._stopping.is_set():
                    break
            self.state.reconnects += 1  # a retry after a drop or a failed attempt alike
            await self._wait(delay * self._jitter())
            delay = min(delay * 2, MAX_BACKOFF)
        self._set_state("stopped", self.state.transport)

    async def stop(self) -> None:
        self._stopping.set()
        link, self._link = self._link, None
        if link is not None:
            await link.close()

    @property
    def payload_format(self) -> str:
        """The challenge payload form the relay accepts, ``domain`` or ``bare``: what the
        connection signs with, and what a one-off proof (``recipients``) must sign with."""
        return self._payload_format

    def _transport(self) -> str:
        if self.settings.transport == POLL:
            return POLL
        if self.settings.transport == WEBSOCKET:
            return WEBSOCKET
        return POLL if self._websocket_blocked else WEBSOCKET

    async def _wait(self, delay: float) -> None:
        if self._stopping.is_set():
            return
        waiter = asyncio.ensure_future(self._stopping.wait())
        sleeper = asyncio.ensure_future(self._sleep(delay))
        try:
            await asyncio.wait({waiter, sleeper}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (waiter, sleeper):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    def _set_state(self, status: str, transport: str | None, code: str | None = None) -> None:
        self.state.status = status
        self.state.transport = transport
        self.state.code = code
        self.state.since = now_iso()

    async def _serve(self, link: Link) -> str:
        while not self._stopping.is_set():
            try:
                frame = await link.receive()
            except LinkClosedError as error:
                return clean(error.reason, 64) or "disconnect"
            kind = frame.get("type")
            if kind == "wakeup":
                try:
                    await self._on_wakeup(link, frame)
                except LinkClosedError as error:
                    return clean(error.reason, 64) or "disconnect"
            elif kind in ("acked", "ack-refused"):
                log.info("ack answered type=%s code=%s", kind, clean(frame.get("code"), 64))
            elif kind == "error":
                log.info("relay error code=%s", clean(frame.get("code"), 64))
        return "stopped"

    # ------------------------------------------------------------ wake-ups

    async def _on_wakeup(self, link: Link, frame: dict[str, Any]) -> None:
        wakeup_id = frame.get("wakeup_id")
        items = frame.get("messages")
        if not isinstance(wakeup_id, str) or not isinstance(items, list):
            return
        wakeup_id = clean(wakeup_id, 64)
        received = [m for m in (Received.from_frame(wakeup_id, i) for i in items) if m]
        fresh = [m for m in received if m.request_id not in self._seen]
        pending = self._rekey_pending(wakeup_id, [m.request_id for m in received])
        log.info(
            "wakeup received wakeup_id=%s count=%d new=%d pending=%d resend=%s request_ids=%s",
            wakeup_id,
            len(received),
            len(fresh),
            len(pending),
            bool(frame.get("resend")),
            clean(",".join(m.request_id for m in received), 2048),
        )
        if fresh and not await self._wake(wakeup_id, len(fresh)):
            log.info("wake command failed wakeup_id=%s; acknowledged failed", wakeup_id)
            await self._ack(link, wakeup_id, "failed")
            return
        if not fresh and not pending:
            await self._ack(link, wakeup_id, "done")  # everything in it was handed over
            return
        self._frames[wakeup_id] = pending | {m.request_id for m in fresh}
        for message in fresh:
            self._remember(message.request_id)
            self._inbox.append(message)
        self._arrived.set()

    def _rekey_pending(self, wakeup_id: str, request_ids: list[str]) -> set[str]:
        """A frame resent under a new wake-up ID carries messages the assistant has not read
        yet: move them under the new ID so ``take`` acknowledges that one, never the old.
        A resend under the same ID keeps its unread IDs pending the same way. Returns the
        request IDs that are still waiting in memory."""
        wanted = set(request_ids)
        pending: set[str] = set()
        for old_id, remaining in list(self._frames.items()):
            moved = remaining & wanted
            if not moved:
                continue
            remaining -= moved
            pending |= moved
            if not remaining:
                del self._frames[old_id]
        if pending:
            self._inbox = [
                replace(m, wakeup_id=wakeup_id) if m.request_id in pending else m
                for m in self._inbox
            ]
        return pending

    async def _run_wake_command(self, wakeup_id: str, count: int) -> bool:
        command = self.settings.wake_command
        if not command:
            return True
        import os

        env = dict(os.environ, PARLEY_WAKEUP_ID=wakeup_id, PARLEY_MESSAGE_COUNT=str(count))
        try:
            process = await asyncio.create_subprocess_exec(*command, env=env)
            code = await asyncio.wait_for(process.wait(), WAKE_TIMEOUT)
        except (OSError, TimeoutError, asyncio.CancelledError):
            return False
        log.info("wake command exited code=%s wakeup_id=%s", code, wakeup_id)
        return code == 0

    def _remember(self, request_id: str) -> None:
        self._seen[request_id] = None
        while len(self._seen) > SEEN_LIMIT:
            self._seen.popitem(last=False)

    async def _ack(self, link: Link, wakeup_id: str, result: str) -> None:
        log.info("ack sent wakeup_id=%s result=%s", wakeup_id, result)
        await link.send({"type": "ack", "wakeup_id": wakeup_id, "result": result})

    # ------------------------------------------------------------ the assistant's side

    @property
    def waiting(self) -> int:
        return len(self._inbox)

    async def wait_for_messages(self, timeout: float) -> bool:
        """True when a message is waiting within ``timeout`` seconds."""
        if self._inbox:
            return True
        self._arrived.clear()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._arrived.wait(), timeout)
        return bool(self._inbox)

    async def take(self, limit: int) -> list[Received]:
        """Hand over up to ``limit`` waiting messages, oldest first, and acknowledge every
        frame whose messages have all been handed over."""
        taken, self._inbox = self._inbox[:limit], self._inbox[limit:]
        completed: list[str] = []
        for message in taken:
            remaining = self._frames.get(message.wakeup_id)
            if remaining is None:
                continue
            remaining.discard(message.request_id)
            if not remaining:
                completed.append(message.wakeup_id)
                del self._frames[message.wakeup_id]
        link = self._link
        for wakeup_id in completed:
            if link is None:
                log.info("ack deferred wakeup_id=%s: no link; the relay resends", wakeup_id)
                continue
            with contextlib.suppress(LinkClosedError):
                await self._ack(link, wakeup_id, "done")
        return taken
