"""Criterion 3 and 6: the connection, reconnect with backoff, the fallback, the wake
command, acknowledgement, no listening port, and nothing of a body in the logs or on disk.

The scripted tests drive :class:`Connection` with a fake link; the ``relay`` tests run the
real relay on a loopback port and the bridge's real WebSocket and long-poll code.
"""

from __future__ import annotations

import asyncio
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from support import (
    BODY,
    POLL,
    WEBSOCKET,
    AuthRefusedError,
    FakeLink,
    FakeOpener,
    FastSleep,
    RelayServer,
    UnavailableError,
    UpgradeRefusedError,
    deliver,
    make_key,
    make_settings,
    relay_server,  # noqa: F401 - the relay fixture, registered by import
    run,
    wakeup,
)

from parley_bridge.connection import (
    CHALLENGE_BYTES,
    DOMAIN_PREFIX,
    JITTER,
    MAX_BACKOFF,
    MIN_BACKOFF,
    ChallengeError,
    Connection,
    challenge_payload,
    default_opener,
    open_poll,
)
from parley_bridge.keys import DeviceKey
from parley_bridge.relay import RelayClient
from parley_common import signing

SRC = Path(__file__).resolve().parents[1] / "src" / "parley_bridge"


async def started(
    connection: Connection, opener: FakeOpener
) -> tuple[asyncio.Task[None], FakeLink]:
    task = asyncio.create_task(connection.run())
    while not opener.links:
        await asyncio.sleep(0)
    return task, opener.links[-1]


async def settle() -> None:
    for _ in range(30):
        await asyncio.sleep(0)


# ---------------------------------------------------------------- the challenge payload


def test_challenge_payload_is_domain_separated_by_default_and_bare_during_transition() -> None:
    challenge = signing.b64url_encode(b"\x01" * 32)
    domain = challenge_payload("device-1", challenge, "domain")
    assert domain == DOMAIN_PREFIX + b"device-1" + b"\x01" * 32
    assert DOMAIN_PREFIX == b"parley-connect\0"
    assert challenge_payload("device-1", challenge, "bare") == b"\x01" * 32


def test_a_challenge_that_is_not_32_bytes_is_refused_in_both_payload_forms() -> None:
    """Security item 1: a relay-chosen payload is never signed, in bare mode either."""
    long = signing.b64url_encode(b"{" * 232)
    for form in ("domain", "bare"):
        with pytest.raises(ChallengeError):
            challenge_payload("device-1", long, form)
        with pytest.raises(ChallengeError):
            challenge_payload("device-1", signing.b64url_encode(b"x" * 31), form)
        with pytest.raises(ChallengeError):
            challenge_payload("device-1", "not*canonical", form)
        with pytest.raises(ChallengeError):
            challenge_payload("device-1", signing.b64url_encode(b"x" * 32) + "=", form)
    assert CHALLENGE_BYTES == 32
    good = signing.b64url_encode(b"y" * 32)
    assert challenge_payload("device-1", good, "bare") == b"y" * 32


def test_bad_signature_never_switches_the_payload_form_in_auto_mode(tmp_path: Path) -> None:
    """Security item 1: only a reason that says the form is unknown switches to bare."""

    async def scenario() -> None:
        opener = FakeOpener(
            [AuthRefusedError("bad-signature"), AuthRefusedError("bad-signature"), FakeLink()]
        )
        connection = Connection(make_key(), make_settings(tmp_path), opener, sleep=FastSleep())
        task, _ = await started(connection, opener)
        assert [payload for _, payload in opener.attempts] == ["domain", "domain", "domain"]
        await connection.stop()
        await task
        switching = FakeOpener([AuthRefusedError("unknown-payload"), FakeLink()])
        connection = Connection(make_key(), make_settings(tmp_path), switching, sleep=FastSleep())
        task, _ = await started(connection, switching)
        assert [payload for _, payload in switching.attempts] == ["domain", "bare"]
        await connection.stop()
        await task
        pinned = FakeOpener([AuthRefusedError("unknown-payload"), FakeLink()])
        settings = make_settings(tmp_path, challenge_payload="bare")
        connection = Connection(make_key(), settings, pinned, sleep=FastSleep())
        task, _ = await started(connection, pinned)
        assert [payload for _, payload in pinned.attempts] == ["bare", "bare"]
        await connection.stop()
        await task

    run(scenario())


def test_a_hostile_challenge_leads_to_a_reconnect_not_a_dead_loop(tmp_path: Path) -> None:
    """Security item 2: the openers turn a bad challenge into UnavailableError, and the
    loop survives any other exception from an opener, logging its type only."""
    import httpx

    from parley_bridge.relay import RelayClient

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if request.url.path == "/connect/challenge":
            text = "!!not base64url!!" if calls["n"] == 1 else signing.b64url_encode(b"{" * 232)
            return httpx.Response(200, json={"type": "challenge", "challenge": text})
        raise AssertionError("a session was requested with a bad challenge")

    async def scenario() -> None:
        client = RelayClient(
            httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://relay")
        )
        key = make_key()
        for _ in range(2):
            with pytest.raises(UnavailableError):
                await open_poll(client, key, "bare")
        await client.aclose()

        class HostileError(Exception):
            pass

        opener = FakeOpener([HostileError("surprise"), FakeLink()])
        sleep = FastSleep()
        connection = Connection(
            make_key(), make_settings(tmp_path), opener, sleep=sleep, jitter=lambda: 1.0
        )
        task, _ = await started(connection, opener)
        assert sleep.delays == [1] and connection.state.status == "connected"
        await connection.stop()
        await task

    run(scenario())


# ---------------------------------------------------------------- reconnect and fallback


def test_reconnect_backs_off_from_1_second_doubling_to_60(tmp_path: Path) -> None:
    async def scenario() -> None:
        failures: list[Any] = [UnavailableError("down")] * 8
        opener = FakeOpener([*failures, FakeLink()])
        sleep = FastSleep()
        connection = Connection(
            make_key(), make_settings(tmp_path), opener, sleep=sleep, jitter=lambda: 1.0
        )
        task, _ = await started(connection, opener)
        assert sleep.delays == [1, 2, 4, 8, 16, 32, 60, 60]
        assert MIN_BACKOFF == 1 and MAX_BACKOFF == 60
        assert connection.state.status == "connected"
        await connection.stop()
        await task

    run(scenario())


def test_backoff_waits_carry_about_25_percent_jitter(tmp_path: Path) -> None:
    async def scenario() -> None:
        failures: list[Any] = [UnavailableError("down")] * 6
        opener = FakeOpener([*failures, FakeLink()])
        sleep = FastSleep()
        connection = Connection(make_key(), make_settings(tmp_path), opener, sleep=sleep)
        task, _ = await started(connection, opener)
        assert JITTER == 0.25
        for delay, base in zip(sleep.delays, [1, 2, 4, 8, 16, 32], strict=True):
            assert base * 0.75 <= delay <= base * 1.25
        assert len(set(sleep.delays)) == 6
        await connection.stop()
        await task

    run(scenario())


def test_a_dropped_link_is_reopened_and_the_delay_resets_after_a_success(tmp_path: Path) -> None:
    async def scenario() -> None:
        opener = FakeOpener([FakeLink(), UnavailableError("down"), FakeLink()])
        sleep = FastSleep()
        connection = Connection(
            make_key(), make_settings(tmp_path), opener, sleep=sleep, jitter=lambda: 1.0
        )
        task, first = await started(connection, opener)
        first.drop("disconnect")
        while len(opener.links) < 2:
            await asyncio.sleep(0)
        assert sleep.delays == [1, 2]  # 1 after the drop, 2 after the failed attempt
        assert connection.state.reconnects == 1
        await connection.stop()
        await task

    run(scenario())


def test_backoff_resets_only_after_a_link_survived_a_few_seconds(tmp_path: Path) -> None:
    """A link that dies at once keeps the backoff doubling; a stable one resets it."""
    from parley_bridge import connection as module

    async def scenario(stable: float) -> list[float]:
        module_default = module.STABLE_SECONDS
        module.STABLE_SECONDS = stable
        try:
            opener = FakeOpener([FakeLink(), FakeLink(), FakeLink()])
            sleep = FastSleep()
            connection = Connection(
                make_key(), make_settings(tmp_path), opener, sleep=sleep, jitter=lambda: 1.0
            )
            task, first = await started(connection, opener)
            first.drop()
            while len(opener.links) < 2:
                await asyncio.sleep(0)
            opener.links[1].drop()
            while len(opener.links) < 3:
                await asyncio.sleep(0)
            await connection.stop()
            await task
            return sleep.delays
        finally:
            module.STABLE_SECONDS = module_default

    assert run(scenario(stable=1000.0)) == [1, 2]  # never stable: doubling
    assert run(scenario(stable=0.0)) == [1, 1]  # stable at once: reset each time


def test_websocket_upgrade_refused_falls_back_to_long_poll(tmp_path: Path) -> None:
    async def scenario() -> None:
        opener = FakeOpener([UpgradeRefusedError("proxy"), FakeLink(POLL)])
        sleep = FastSleep()
        connection = Connection(
            make_key(), make_settings(tmp_path), opener, sleep=sleep, jitter=lambda: 1.0
        )
        task, link = await started(connection, opener)
        assert [transport for transport, _ in opener.attempts] == [WEBSOCKET, POLL]
        assert sleep.delays == [1] and connection.state.transport == POLL  # the wait is kept
        link.drop()
        while len(opener.attempts) < 3:
            await asyncio.sleep(0)
        assert opener.attempts[2][0] == WEBSOCKET  # the WebSocket is tried again later
        await connection.stop()
        await task
        forced = FakeOpener([FakeLink(POLL)])
        connection = Connection(
            make_key(), make_settings(tmp_path, transport="poll"), forced, sleep=sleep
        )
        task, _ = await started(connection, forced)
        assert forced.attempts == [(POLL, "domain")]
        await connection.stop()
        await task

    run(scenario())


# ---------------------------------------------------------------- wake-ups and acks


def test_wake_command_runs_once_per_frame_and_a_failure_keeps_the_messages_waiting(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        marker = tmp_path / "woken"
        succeed = (sys.executable, "-c", f"open({str(marker)!r}, 'a').write('x')")
        settings = make_settings(tmp_path, wake_command=succeed)
        opener = FakeOpener()
        connection = Connection(make_key(), settings, opener, sleep=FastSleep())
        task, link = await started(connection, opener)
        link.push(wakeup("w1", "one", "two"))
        for _ in range(200):
            if connection.waiting == 2:
                break
            await asyncio.sleep(0.02)
        assert connection.waiting == 2 and marker.read_text() == "x"
        assert link.acks() == []
        await connection.stop()
        await task

        fail = (sys.executable, "-c", "raise SystemExit(3)")
        settings = make_settings(tmp_path, wake_command=fail)
        opener = FakeOpener()
        connection = Connection(make_key(), settings, opener, sleep=FastSleep())
        task, link = await started(connection, opener)
        link.push(wakeup("w2", "three"))
        for _ in range(200):
            if link.acks():
                break
            await asyncio.sleep(0.02)
        assert link.acks() == [("w2", "failed")] and connection.waiting == 0
        await connection.stop()
        await task

    run(scenario())


def test_a_resent_frame_after_a_drop_is_acknowledged_without_a_second_delivery(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        opener = FakeOpener([FakeLink(), FakeLink()])
        connection = Connection(make_key(), make_settings(tmp_path), opener, sleep=FastSleep())
        task, first = await started(connection, opener)
        first.push(wakeup("w1", "once"))
        await settle()
        taken = await connection.take(10)
        assert [m.body for m in taken] == ["once"]
        assert first.acks() == [("w1", "done")]
        first.drop()
        while len(opener.links) < 2:
            await asyncio.sleep(0)
        second = opener.links[1]
        second.push(wakeup("w1", "once", resend=True))  # the same ids under a new wake-up
        await settle()
        assert second.acks() == [("w1", "done")] and connection.waiting == 0
        await connection.stop()
        await task

    run(scenario())


def test_a_resend_before_check_inbox_is_acknowledged_only_when_the_assistant_reads_it(
    tmp_path: Path,
) -> None:
    """Reviewer item 9: a frame resent under a new wake-up ID with messages the assistant
    has not read yet is not acknowledged until check_inbox hands them over; a crash
    before that loses nothing (6b)."""

    async def scenario() -> None:
        opener = FakeOpener([FakeLink(), FakeLink()])
        connection = Connection(make_key(), make_settings(tmp_path), opener, sleep=FastSleep())
        task, first = await started(connection, opener)
        first.push(wakeup("w1", "unread", "also unread"))
        await settle()
        assert connection.waiting == 2 and first.acks() == []
        first.drop()
        while len(opener.links) < 2:
            await asyncio.sleep(0)
        second = opener.links[1]
        resent = wakeup("w1", "unread", "also unread", resend=True)
        resent["wakeup_id"] = "w2"  # the relay's new wake-up id, the same request ids
        second.push(resent)
        await settle()
        assert second.acks() == [] and connection.waiting == 2  # still waiting, not acked
        one = await connection.take(1)
        assert [m.body for m in one] == ["unread"] and second.acks() == []
        rest = await connection.take(10)
        assert [m.body for m in rest] == ["also unread"]
        assert second.acks() == [("w2", "done")]  # the new id, once everything was read
        await connection.stop()
        await task

    run(scenario())


def test_a_resend_under_the_same_wakeup_id_keeps_unread_messages_pending(
    tmp_path: Path,
) -> None:
    """Security item (e): the same wake-up id sent again before check_inbox is not acked."""

    async def scenario() -> None:
        opener = FakeOpener([FakeLink(), FakeLink()])
        connection = Connection(make_key(), make_settings(tmp_path), opener, sleep=FastSleep())
        task, first = await started(connection, opener)
        first.push(wakeup("w1", "unread"))
        await settle()
        first.drop()
        while len(opener.links) < 2:
            await asyncio.sleep(0)
        second = opener.links[1]
        second.push(wakeup("w1", "unread", resend=True))
        await settle()
        assert second.acks() == [] and connection.waiting == 1
        assert [m.body for m in await connection.take(10)] == ["unread"]
        assert second.acks() == [("w1", "done")]
        await connection.stop()
        await task

    run(scenario())


def test_a_poll_link_with_a_hostile_wakeup_id_does_not_stall(tmp_path: Path) -> None:
    """Security item (d): the id kept as outstanding is the cleaned one that gets acked."""
    from parley_bridge.connection import PollLink
    from parley_bridge.relay import RelayClient

    hostile = "w1\x07\x1b[2J"

    class Scripted(RelayClient):
        def __init__(self) -> None:
            self.polls = 0
            self.acks: list[tuple[str, str]] = []

        async def poll(self, token: str, wait: float = 25.0) -> dict[str, Any]:
            self.polls += 1
            if self.polls == 1:
                frame = wakeup("w1", "hello")
                frame["wakeup_id"] = hostile
                return frame
            return {"type": "idle"}

        async def ack(self, token: str, wakeup_id: str, result: str) -> dict[str, Any]:
            self.acks.append((wakeup_id, result))
            return {"type": "acked", "code": "acked"}

    async def scenario() -> None:
        client = Scripted()
        link = PollLink(client, "token")
        frame = await link.receive()
        assert frame["wakeup_id"] == hostile
        await link.send({"type": "ack", "wakeup_id": "w1[2J", "result": "done"})
        idle = await asyncio.wait_for(link.receive(), 2)  # would hang before the fix
        assert idle["type"] == "idle" and client.acks == [("w1[2J", "done")]
        opener = FakeOpener([FakeLink(POLL)])
        connection = Connection(make_key(), make_settings(tmp_path), opener, sleep=FastSleep())
        task, fake = await started(connection, opener)
        frame = wakeup("w1", "hello")
        frame["wakeup_id"] = hostile
        fake.push(frame)
        await settle()
        taken = await connection.take(10)
        assert [m.wakeup_id for m in taken] == ["w1[2J"] and fake.acks() == [("w1[2J", "done")]
        await connection.stop()
        await task

    run(scenario())


def test_open_websocket_closes_the_socket_when_the_relay_sends_no_challenge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Security item (f): no socket is left open behind an UnavailableError."""
    import json

    import websockets.asyncio.client

    from parley_bridge.connection import open_websocket

    class FakeSocket:
        def __init__(self) -> None:
            self.closed = False

        async def recv(self) -> str:
            return json.dumps({"type": "hello"})

        async def send(self, text: str) -> None:
            raise AssertionError("nothing is sent without a challenge")

        async def close(self) -> None:
            self.closed = True

    socket = FakeSocket()

    async def fake_connect(url: str, **kwargs: Any) -> FakeSocket:
        return socket

    monkeypatch.setattr(websockets.asyncio.client, "connect", fake_connect)

    async def scenario() -> None:
        with pytest.raises(UnavailableError):
            await open_websocket(make_settings(tmp_path), make_key(), "bare")
        assert socket.closed is True

    run(scenario())


def test_a_revoked_device_ends_the_loop_as_unlinked(tmp_path: Path) -> None:
    """Reviewer item 11: no retry every minute after the relay says revoked-device."""

    async def scenario() -> None:
        opener = FakeOpener([FakeLink(), FakeLink()])
        sleep = FastSleep()
        connection = Connection(make_key(), make_settings(tmp_path), opener, sleep=sleep)
        task, link = await started(connection, opener)
        link.drop("revoked-device")
        await asyncio.wait_for(task, 5)
        assert connection.state.status == "unlinked"
        assert connection.state.code == "revoked-device"
        assert len(opener.links) == 1 and sleep.delays == []
        refused = FakeOpener([AuthRefusedError("revoked-device"), FakeLink()])
        connection = Connection(make_key(), make_settings(tmp_path), refused, sleep=sleep)
        await asyncio.wait_for(connection.run(), 5)
        assert connection.state.status == "unlinked" and len(refused.attempts) == 1

    run(scenario())


def test_an_ack_with_no_link_is_left_to_the_relay_resend(tmp_path: Path) -> None:
    async def scenario() -> None:
        opener = FakeOpener([FakeLink(), UnavailableError("down"), FakeLink()])
        connection = Connection(make_key(), make_settings(tmp_path), opener, sleep=FastSleep())
        task, first = await started(connection, opener)
        first.push(wakeup("w1", "late"))
        await settle()
        first.drop()
        await settle()
        taken = await connection.take(10)  # the link is gone while the assistant reads
        assert [m.body for m in taken] == ["late"]
        await connection.stop()
        await task

    run(scenario())


# ---------------------------------------------------------------- no inbound port


def test_the_bridge_opens_no_listening_port() -> None:
    """Outbound only: no bind, listen or server socket anywhere in the package."""
    forbidden = re.compile(r"\.bind\(|\.listen\(|start_server\(|uvicorn|\.serve\(")
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not forbidden.search(text), path.name
    server_text = (SRC / "server.py").read_text(encoding="utf-8")
    assert "mcp.run()" in server_text and "transport=" not in server_text.split("def _run")[1]


# ---------------------------------------------------------------- against the real relay


def register(relay: RelayServer, key: DeviceKey) -> str:
    """Register the key as an assistant of an owner of its own; returns the owner ID."""
    owner = f"owner-of-{key.device_id}"
    relay.registry.add_assistant(owner, key.device_id, key.public_key)
    return owner


def test_websocket_to_the_relay_delivers_held_messages_within_10_seconds(
    relay: RelayServer, tmp_path: Path
) -> None:
    """The real ``WS /connect``: the message queued while the bridge was away arrives in
    the first frame after the reconnect; the next frame comes only after the ack."""
    key = make_key("ws-assistant")
    owner = register(relay, key)
    settings = make_settings(tmp_path, relay_url=relay.url)

    async def scenario() -> None:
        client = RelayClient(__import__("httpx").AsyncClient(base_url=relay.url))
        connection = Connection(key, settings, default_opener(settings, client))
        first_id = deliver(relay, "held while away", to=owner)
        start = time.monotonic()
        task = asyncio.create_task(connection.run())
        assert await connection.wait_for_messages(10)
        assert time.monotonic() - start < 10
        assert connection.state.status == "connected" and connection.state.transport == WEBSOCKET
        taken = await connection.take(10)
        assert [m.request_id for m in taken] == [first_id]
        assert taken[0].body == "held while away" and taken[0].from_other_owner is True
        second_id = deliver(relay, "after the ack", to=owner)
        assert await connection.wait_for_messages(10)
        assert [m.request_id for m in await connection.take(10)] == [second_id]
        await connection.stop()
        await asyncio.wait_for(task, 10)
        await client.aclose()

    run(scenario())


def test_long_poll_to_the_relay_delivers_and_acknowledges(
    relay: RelayServer, tmp_path: Path
) -> None:
    key = make_key("poll-assistant")
    owner = register(relay, key)
    settings = make_settings(tmp_path, relay_url=relay.url, transport="poll")

    async def scenario() -> None:
        client = RelayClient(__import__("httpx").AsyncClient(base_url=relay.url))
        connection = Connection(key, settings, default_opener(settings, client))
        task = asyncio.create_task(connection.run())
        for _ in range(100):
            if connection.state.status == "connected":
                break
            await asyncio.sleep(0.05)
        assert connection.state.transport == POLL
        first_id = deliver(relay, "by poll", to=owner)
        assert await connection.wait_for_messages(10)
        assert [m.request_id for m in await connection.take(10)] == [first_id]
        second_id = deliver(relay, "second by poll", to=owner)
        assert await connection.wait_for_messages(10)
        assert [m.request_id for m in await connection.take(10)] == [second_id]
        await connection.stop()
        await asyncio.wait_for(task, 40)
        await client.aclose()

    run(scenario())


def test_a_wrong_key_is_refused_with_the_relay_code_and_retried_with_backoff(
    relay: RelayServer, tmp_path: Path
) -> None:
    key = make_key("stranger")  # never registered
    settings = make_settings(tmp_path, relay_url=relay.url)

    async def scenario() -> None:
        client = RelayClient(__import__("httpx").AsyncClient(base_url=relay.url))
        sleep = FastSleep()
        seen: list[tuple[str, str | None]] = []

        async def recording_sleep(seconds: float) -> None:
            seen.append((connection.state.status, connection.state.code))
            await sleep(seconds)

        connection = Connection(
            key,
            settings,
            default_opener(settings, client),
            sleep=recording_sleep,
            jitter=lambda: 1.0,
        )
        task = asyncio.create_task(connection.run())
        for _ in range(200):
            if len(sleep.delays) >= 3:
                break
            await asyncio.sleep(0.05)
        assert all(status == "refused" for status, _ in seen[:3])
        assert all(code in ("unknown-device", "bad-signature") for _, code in seen[:3])
        assert sleep.delays[:3] == [1, 2, 4]
        await connection.stop()
        await asyncio.wait_for(task, 10)
        await client.aclose()

    run(scenario())


def test_the_server_lifespan_wires_the_tools_to_the_relay(
    relay: RelayServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``parley-bridge run`` end to end: key file, environment, lifespan, tool call."""
    from parley_bridge import keys, server

    key = make_key("lifespan-assistant")
    owner = register(relay, key)
    key_path = tmp_path / "bridge-key.json"
    keys.save(key_path, key)
    monkeypatch.setenv("PARLEY_RELAY_URL", relay.url)
    monkeypatch.setenv("PARLEY_BRIDGE_KEY_PATH", str(key_path))

    async def scenario() -> None:
        async with server.lifespan(server.mcp):
            request_id = deliver(relay, "through the server", to=owner)
            result = await server.mcp.call_tool("check_inbox", {"wait": 10})
            structured = result[1] if isinstance(result, tuple) else result
            assert isinstance(structured, dict)
            assert [m["id"] for m in structured["messages"]] == [request_id]
            assert structured["messages"][0]["untrusted"] is True
            assert structured["connection"]["status"] == "connected"
        with pytest.raises(RuntimeError):
            server.current_bridge()

    run(scenario())


# ---------------------------------------------------------------- criterion 6: logs and disk


def test_verbose_logs_carry_ids_and_times_but_never_a_body(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="parley_bridge")

    async def scenario() -> None:
        opener = FakeOpener()
        connection = Connection(make_key(), make_settings(tmp_path), opener, sleep=FastSleep())
        task, link = await started(connection, opener)
        link.push(wakeup("w1", BODY))
        await settle()
        await connection.take(10)
        await connection.stop()
        await task

    run(scenario())
    lines = [record.getMessage() for record in caplog.records]
    assert any("wakeup received wakeup_id=w1" in line for line in lines)
    assert any("request_ids=w1-m0" in line for line in lines)
    assert all(BODY not in line for line in lines)
    assert all("quarterly" not in line for line in lines)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert BODY not in path.read_text(encoding="utf-8", errors="ignore")
