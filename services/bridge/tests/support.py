"""Shared helpers and fixtures for the bridge tests (imported by name; no conftest, so
the module name does not collide with the relay tests' conftest under mypy).

Two kinds of relay stand behind the tests: a fake link that scripts frames for the
connection logic, and the real relay app started by uvicorn on an ephemeral loopback
port in a thread, so the bridge's WebSocket and long-poll code talk to the relay as it
is. Owner IDs and labels are made up; every key is generated for the test; message
bodies are harmless test strings.
"""

from __future__ import annotations

import asyncio
import os
import socket
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from parley_bridge.config import Settings
from parley_bridge.connection import (
    POLL,
    WEBSOCKET,
    AuthRefusedError,
    Link,
    LinkClosedError,
    UnavailableError,
    UpgradeRefusedError,
)
from parley_bridge.keys import DeviceKey
from parley_common import signing
from parley_common.clock import utc_now

OWNER_A = "owner-a"
OWNER_B = "owner-b"
ASSISTANT_B = "device-b-assistant"
BODY = "test body: the quarterly numbers are ready"
PRINCIPAL_HEADER = "X-Parley-Principal"


def run[T](coro: Awaitable[T]) -> T:
    return asyncio.run(_await(coro))


async def _await[T](coro: Awaitable[T]) -> T:
    return await coro


def make_settings(
    tmp_path: Path, relay_url: str = "http://127.0.0.1:9", **changes: Any
) -> Settings:
    base: dict[str, Any] = {
        "relay_url": relay_url,
        "key_path": tmp_path / "keys" / "bridge-key.json",
        "wake_command": (),
    }
    base.update(changes)
    return Settings(**base)


def make_key(device_id: str = "device-a-assistant") -> DeviceKey:
    return DeviceKey(device_id, signing.generate_keypair().private, "http://127.0.0.1:9", utc_now())


@pytest.fixture
def key() -> DeviceKey:
    return make_key()


# ---------------------------------------------------------------- the fake link


class FakeLink:
    """Frames queued by the test come out of ``receive``; what the bridge sends is kept."""

    def __init__(self, transport: str = WEBSOCKET) -> None:
        self.transport = transport
        self.incoming: asyncio.Queue[dict[str, Any] | LinkClosedError] = asyncio.Queue()
        self.sent: list[dict[str, Any]] = []
        self.closed = False

    def push(self, frame: dict[str, Any]) -> None:
        self.incoming.put_nowait(frame)

    def drop(self, reason: str = "disconnect") -> None:
        self.incoming.put_nowait(LinkClosedError(reason))

    async def receive(self) -> dict[str, Any]:
        item = await self.incoming.get()
        if isinstance(item, LinkClosedError):
            raise item
        return item

    async def send(self, frame: dict[str, Any]) -> None:
        if self.closed:
            raise LinkClosedError("closed")
        self.sent.append(frame)

    async def close(self) -> None:
        self.closed = True
        self.incoming.put_nowait(LinkClosedError("closed"))

    def acks(self) -> list[tuple[str, str]]:
        return [(f["wakeup_id"], f["result"]) for f in self.sent if f.get("type") == "ack"]


Outcome = FakeLink | Exception


@dataclass
class FakeOpener:
    """Scripted outcomes per attempt; records every attempt's transport and payload."""

    outcomes: list[Outcome] = field(default_factory=list)
    attempts: list[tuple[str, str]] = field(default_factory=list)
    links: list[FakeLink] = field(default_factory=list)

    async def __call__(self, transport: str, key: DeviceKey, payload_format: str) -> Link:
        self.attempts.append((transport, payload_format))
        outcome = self.outcomes.pop(0) if self.outcomes else FakeLink(transport)
        if isinstance(outcome, Exception):
            raise outcome
        outcome.transport = transport
        self.links.append(outcome)
        return outcome


def wakeup(
    wakeup_id: str,
    *bodies: str,
    sender_owner: str = OWNER_B,
    sender_device: str = ASSISTANT_B,
    from_other_owner: bool = True,
    thread_id: str | None = None,
    resend: bool = False,
) -> dict[str, Any]:
    """A wake-up frame as the relay sends it, one message per body."""
    messages = []
    for index, body in enumerate(bodies):
        request_id = f"{wakeup_id}-m{index}"
        envelope = {
            "request_id": request_id,
            "thread_id": thread_id or request_id,
            "to": [OWNER_A],
            "body": body,
            "sent_at": "2026-10-10T22:00:00Z",
            "kind": "chat",
            "commit_id": None,
            "expiry": None,
            "business_address": None,
            "format_version": 1,
            "owner": sender_owner,
            "sent_by": sender_device,
            "permission_ref": "perm-1",
        }
        messages.append(
            {
                "request_id": request_id,
                "thread_id": envelope["thread_id"],
                "sender_device_id": sender_device,
                "sender_owner_id": sender_owner,
                "from_other_owner": from_other_owner,
                "kind": "chat",
                "sent_at": envelope["sent_at"],
                "enqueued_at": envelope["sent_at"],
                "envelope": envelope,
            }
        )
    return {
        "type": "wakeup",
        "wakeup_id": wakeup_id,
        "sent_at": "2026-10-10T22:00:01Z",
        "resend": resend,
        "messages": messages,
    }


class FastSleep:
    """Records the delays the connection asks for and yields without waiting."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)
        await asyncio.sleep(0)


__all__ = [
    "ASSISTANT_B",
    "BODY",
    "OWNER_A",
    "OWNER_B",
    "POLL",
    "PRINCIPAL_HEADER",
    "WEBSOCKET",
    "AuthRefusedError",
    "FakeLink",
    "FakeOpener",
    "FastSleep",
    "UnavailableError",
    "UpgradeRefusedError",
    "make_key",
    "make_settings",
    "run",
    "wakeup",
]


# ---------------------------------------------------------------- the real relay


@dataclass
class RelayServer:
    url: str
    app: Any
    thread: threading.Thread
    server: Any

    @property
    def connections(self) -> Any:
        return self.app.state.connections

    @property
    def registry(self) -> Any:
        return self.app.state.connection_registry


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        assert isinstance(port, int)
        return port


@pytest.fixture(scope="module", name="relay")
def relay_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RelayServer]:
    """The relay app on an ephemeral loopback port, with the owner session stand-ins the
    relay's own tests use. Module-scoped: one relay per test file."""
    import uvicorn

    from parley_relay.app import app
    from parley_relay.connection import StaticRegistry
    from parley_relay.permissions import StaticApprovals
    from parley_relay.permissions.router import HeaderPrincipals
    from parley_relay.refusals import StaticAccountStatus

    db_path = tmp_path_factory.mktemp("relay") / "relay.db"
    names = ("PARLEY_DB_PATH", "PARLEY_ORIGIN", "PARLEY_ALLOW_EPHEMERAL_SIGNING_KEY")
    saved = {name: os.environ.get(name) for name in names}
    os.environ["PARLEY_DB_PATH"] = str(db_path)
    os.environ["PARLEY_ORIGIN"] = "https://relay.example"
    os.environ["PARLEY_ALLOW_EPHEMERAL_SIGNING_KEY"] = "1"
    app.state.pairing_principals = HeaderPrincipals()
    app.state.permissions_principals = HeaderPrincipals()
    app.state.permissions_approvals = StaticApprovals(SECRETS)
    app.state.refusals_accounts = StaticAccountStatus()
    app.state.connection_registry = StaticRegistry()
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started, "the relay did not start"
    try:
        yield RelayServer(f"http://127.0.0.1:{port}", app, thread, server)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def stamped_envelope(
    *,
    to: str = OWNER_A,
    body: str = BODY,
    sender_owner: str = OWNER_B,
    sender_device: str = ASSISTANT_B,
) -> Any:
    from parley_common.envelope import Envelope

    envelope = Envelope.from_sender(to=(to,), body=body)
    return envelope.stamped_by_relay(owner=sender_owner, sent_by=sender_device, permission_ref="p")


SECRETS = {f"owner-send-{letter}": f"lock-{letter}" for letter in "abc"}
"""Owners the send test links; the test-only approval verifier knows their secrets."""
_NONCES = iter(range(1, 10_000))


def approval(owner_id: str) -> dict[str, str]:
    return {
        "kind": "test",
        "owner_id": owner_id,
        "assertion": f"{SECRETS[owner_id]}:{next(_NONCES)}",
    }


def as_owner(owner_id: str) -> dict[str, str]:
    return {PRINCIPAL_HEADER: f"owner:{owner_id}"}


def connect_owners(relay: RelayServer, a: str, b: str) -> None:
    """Owner ``a`` asks, owner ``b`` accepts: an accepted contact on the relay."""
    import httpx

    from parley_relay.permissions import REQUEST_REASONS

    with httpx.Client(base_url=relay.url) as http:
        asked = http.post(
            "/contacts/requests", json={"to": b, "reason": REQUEST_REASONS[0]}, headers=as_owner(a)
        )
        assert asked.status_code == 201, asked.text
        accepted = http.post(
            f"/contacts/requests/{asked.json()['id']}/accept",
            json={"approval": approval(b)},
            headers=as_owner(b),
        )
        assert accepted.status_code == 200, accepted.text


def link_assistant(relay: RelayServer, owner_id: str, device_id: str, recipients: list[str]) -> str:
    """The owner approves the assistant's permission for ``recipients`` (CR-08)."""
    import httpx

    with httpx.Client(base_url=relay.url) as http:
        response = http.post(
            "/permissions",
            json={
                "assistant_device_id": device_id,
                "recipients": recipients,
                "approval": approval(owner_id),
            },
            headers=as_owner(owner_id),
        )
        assert response.status_code == 201, response.text
        permission_id: str = response.json()["id"]
        return permission_id


def deliver(relay: RelayServer, body: str = BODY, to: str = OWNER_A) -> str:
    """Queue a message for ``to`` on the relay; returns its request ID."""
    envelope = stamped_envelope(to=to, body=body)
    relay.connections.accept(envelope, to)
    request_id: str = envelope.request_id
    return request_id


def wait_until(check: Callable[[], bool], timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.05)
    return check()
