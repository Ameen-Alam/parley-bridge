"""T-0053: the bridge reaches a relay whose first address is a dead IPv6 one.

The race itself is driven with stand-in attempts, so a silent address is silent for
certain. The criteria run the real relay on a loopback port behind a stand-in resolver
that lists ``100::1`` (the IPv6 discard prefix, RFC 6666) first and the loopback IPv4
address second, the order a resolver gives on a network without working IPv6.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
from support import (
    POLL,
    WEBSOCKET,
    FastSleep,
    RelayServer,
    make_key,
    make_settings,
    relay_server,  # noqa: F401 - the relay fixture, registered by import
    run,
)

from parley_bridge.connection import Connection, default_opener
from parley_bridge.dial import Address, Dialer, DialError, RacingTransport, http_client
from parley_bridge.keys import DeviceKey
from parley_bridge.relay import RelayClient

V6 = socket.AF_INET6
V4 = socket.AF_INET
DEAD_V6 = "100::1"
RELAY_NAME = "relay.test"


def dead_v6_first(port: int) -> Dialer:
    async def resolver(host: str, wanted: int) -> list[Address]:
        assert host == RELAY_NAME and wanted == port
        return [(V6, (DEAD_V6, port, 0, 0)), (V4, ("127.0.0.1", port))]

    return Dialer(resolver=resolver)


def register(relay: RelayServer, key: DeviceKey) -> None:
    relay.registry.add_assistant(f"owner-of-{key.device_id}", key.device_id, key.public_key)


def port_of(relay: RelayServer) -> int:
    port = urlsplit(relay.url).port
    assert port is not None
    return port


# ---------------------------------------------------------------- the race


def test_the_families_are_interleaved_and_the_one_that_worked_goes_first() -> None:
    dialer = Dialer()
    found: list[Address] = [
        (V6, ("2001:db8::1", 443, 0, 0)),
        (V6, ("2001:db8::2", 443, 0, 0)),
        (V4, ("192.0.2.1", 443)),
        (V4, ("192.0.2.1", 443)),
        (V4, ("192.0.2.2", 443)),
    ]
    assert [a[1][0] for a in dialer.order(found)] == [
        "2001:db8::1",
        "192.0.2.1",
        "2001:db8::2",
        "192.0.2.2",
    ]
    dialer.family = V4
    assert [a[0] for a in dialer.order(found)] == [V4, V6, V4, V6]


def test_a_silent_first_address_is_overtaken_after_the_stagger() -> None:
    async def resolver(host: str, port: int) -> list[Address]:
        return [(V6, ("2001:db8::1", port, 0, 0)), (V4, ("192.0.2.1", port))]

    dialer = Dialer(resolver=resolver)
    cancelled: list[int] = []
    discarded: list[str] = []

    async def attempt(address: Address) -> str:
        if address[0] == V6:
            try:
                await asyncio.Event().wait()  # never answers
            except asyncio.CancelledError:
                cancelled.append(address[0])
                raise
        return "ipv4 stream"

    async def discard(stream: str) -> None:
        discarded.append(stream)

    async def scenario() -> float:
        start = time.monotonic()
        assert await dialer.race(RELAY_NAME, 443, attempt, discard) == "ipv4 stream"
        return time.monotonic() - start

    elapsed = run(scenario())
    assert dialer.stagger - 0.05 <= elapsed < 1.0  # Windows timers return a few ms early
    assert cancelled == [V6] and discarded == []
    assert dialer.family == V4  # tried first next time


def test_a_failed_attempt_starts_the_next_address_at_once() -> None:
    async def resolver(host: str, port: int) -> list[Address]:
        return [(V6, ("2001:db8::1", port, 0, 0)), (V4, ("192.0.2.1", port))]

    dialer = Dialer(resolver=resolver, stagger=10.0)

    async def attempt(address: Address) -> int:
        if address[0] == V6:
            raise OSError("network unreachable")
        return address[0]

    async def discard(_: int) -> None:
        raise AssertionError("nothing to discard")

    async def scenario() -> float:
        start = time.monotonic()
        assert await dialer.race(RELAY_NAME, 443, attempt, discard) == V4
        return time.monotonic() - start

    assert run(scenario()) < 1.0


def test_every_address_failing_or_no_name_raises_dial_error_with_no_address() -> None:
    async def resolver(host: str, port: int) -> list[Address]:
        return [(V6, ("2001:db8::1", port, 0, 0)), (V4, ("192.0.2.1", port))]

    async def nothing(host: str, port: int) -> list[Address]:
        raise socket.gaierror("no such name")

    async def attempt(address: Address) -> int:
        await asyncio.sleep(10)
        return 0

    async def discard(_: int) -> None:
        return None

    async def scenario() -> None:
        dialer = Dialer(resolver=resolver, stagger=0.05, per_address=0.1)
        with pytest.raises(DialError) as caught:
            await dialer.race(RELAY_NAME, 443, attempt, discard)
        assert "2001:db8" not in str(caught.value) and "192.0.2" not in str(caught.value)
        assert dialer.family is None
        with pytest.raises(DialError):
            await Dialer(resolver=nothing).race(RELAY_NAME, 443, attempt, discard)

    run(scenario())


# ---------------------------------------------------------------- criteria 1 to 3


def connect_through_dead_v6(
    relay: RelayServer, tmp_path: Path, transport: str, device_id: str
) -> tuple[float, str | None, list[str]]:
    """Run a connection behind the dead-IPv6-first resolver until it is connected; returns
    the seconds it took, the transport and the dialer's log lines."""
    key = make_key(device_id)
    register(relay, key)
    port = port_of(relay)
    url = f"http://{RELAY_NAME}:{port}"
    settings = make_settings(tmp_path, relay_url=url, transport=transport)
    dialer = dead_v6_first(port)

    async def scenario() -> tuple[float, str | None]:
        client = RelayClient(http_client(url, dialer))
        connection = Connection(key, settings, default_opener(settings, client, dialer))
        start = time.monotonic()
        task = asyncio.create_task(connection.run())
        while connection.state.status != "connected" and time.monotonic() - start < 10:
            await asyncio.sleep(0.02)
        elapsed = time.monotonic() - start
        assert connection.state.status == "connected"
        transport_used = connection.state.transport
        await connection.stop()
        await asyncio.wait_for(task, 40)
        await client.aclose()
        return elapsed, transport_used

    logger = logging.getLogger("parley_bridge.dial")
    lines: list[str] = []

    class Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(record.getMessage())

    handler = Keep()
    logger.addHandler(handler)
    level = logger.level
    logger.setLevel(logging.INFO)
    try:
        elapsed, transport_used = run(scenario())
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)
    return elapsed, transport_used, lines


def assert_family_logged_never_the_address(lines: list[str]) -> None:
    assert any("relay reached family=ipv4 attempts=2 of=2" in line for line in lines), lines
    for line in lines:
        assert DEAD_V6 not in line and "127.0.0.1" not in line and RELAY_NAME not in line


def test_criterion_1_the_websocket_is_up_within_2_seconds_past_a_dead_ipv6_address(
    relay: RelayServer, tmp_path: Path
) -> None:
    elapsed, transport, lines = connect_through_dead_v6(relay, tmp_path, "websocket", "ws-v6")
    assert elapsed < 2.0, elapsed
    assert transport == WEBSOCKET
    assert_family_logged_never_the_address(lines)


def test_criterion_2_the_long_poll_is_up_within_2_seconds_past_a_dead_ipv6_address(
    relay: RelayServer, tmp_path: Path
) -> None:
    elapsed, transport, lines = connect_through_dead_v6(relay, tmp_path, "poll", "poll-v6")
    assert elapsed < 2.0, elapsed
    assert transport == POLL
    assert_family_logged_never_the_address(lines)


@pytest.mark.parametrize("transport", ["websocket", "poll"])
def test_criterion_3_every_address_failing_reads_unreachable_and_the_count_rises(
    tmp_path: Path, transport: str
) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = int(probe.getsockname()[1])  # closed again once the block ends

    async def resolver(host: str, port: int) -> list[Address]:
        return [(V6, (DEAD_V6, port, 0, 0)), (V4, ("127.0.0.1", port))]

    dialer = Dialer(resolver=resolver, stagger=0.05, per_address=0.3)
    url = f"http://{RELAY_NAME}:{closed_port}"
    settings = make_settings(tmp_path, relay_url=url, transport=transport)

    async def scenario() -> None:
        client = RelayClient(http_client(url, dialer))
        sleep = FastSleep()
        seen: list[tuple[str, str | None, int]] = []

        async def recording_sleep(seconds: float) -> None:
            state = connection.state
            seen.append((state.status, state.code, state.reconnects))
            await sleep(seconds)

        connection = Connection(
            make_key("nowhere"),
            settings,
            default_opener(settings, client, dialer),
            sleep=recording_sleep,
            jitter=lambda: 1.0,
        )
        task = asyncio.create_task(connection.run())
        deadline = time.monotonic() + 20
        while len(seen) < 3 and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        await connection.stop()
        await asyncio.wait_for(task, 10)
        await client.aclose()
        assert [(status, code) for status, code, _ in seen[:3]] == [
            ("unavailable", "unreachable")
        ] * 3
        assert [count for _, _, count in seen[:3]] == [1, 2, 3]
        assert sleep.delays[:3] == [1, 2, 4]

    run(scenario())


# ---------------------------------------------------------------- proxies


PROXY_NAMES = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY")


def no_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.request

    for name in PROXY_NAMES:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    # On Windows an empty environment falls back to the system settings; not here.
    monkeypatch.setattr(urllib.request, "getproxies_registry", dict, raising=False)


def test_the_http_client_races_when_no_proxy_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    no_proxies(monkeypatch)
    client = http_client("https://relay.example")
    transport = client._transport_for_url(httpx.URL("https://relay.example/poll"))
    assert isinstance(transport, RacingTransport)
    run(client.aclose())


def test_a_proxy_from_the_environment_is_kept_for_the_http_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With HTTPS_PROXY set, the long poll, pairing and sending go through the proxy, not
    around it; the racing applies to the direct path only."""
    no_proxies(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    client = http_client("https://relay.example")
    transport = client._transport_for_url(httpx.URL("https://relay.example/poll"))
    assert not isinstance(transport, RacingTransport)
    assert isinstance(transport, httpx.AsyncHTTPTransport)
    run(client.aclose())


def test_a_late_connection_is_closed_even_when_the_caller_is_cancelled_twice() -> None:
    async def resolver(host: str, port: int) -> list[Address]:
        return [(V6, ("2001:db8::1", port, 0, 0)), (V4, ("192.0.2.1", port))]

    dialer = Dialer(resolver=resolver, stagger=0.01)
    closed: list[str] = []
    entered = asyncio.Event()

    async def attempt(address: Address) -> str:
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.sleep(0.05)  # the connect completes while it is being cancelled
            return "late stream"
        raise AssertionError("unreachable")

    async def discard(stream: str) -> None:
        closed.append(stream)

    async def scenario() -> None:
        racing = asyncio.create_task(dialer.race(RELAY_NAME, 443, attempt, discard))
        await entered.wait()
        await asyncio.sleep(0.03)  # both attempts running
        racing.cancel()
        await asyncio.sleep(0)
        racing.cancel()  # a second cancellation while the clean-up runs
        with pytest.raises(asyncio.CancelledError):
            await racing
        for _ in range(50):
            if len(closed) == 2:
                break
            await asyncio.sleep(0.01)
        assert closed == ["late stream", "late stream"]

    run(scenario())
