"""Criterion 2: ``parley-bridge pair`` against the real relay, and its backoff rules against
a scripted relay. The code is shown once in the terminal output and never stored."""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from support import (
    PRINCIPAL_HEADER,
    FastSleep,
    RelayServer,
    link_assistant,
    make_settings,
    relay_server,  # noqa: F401 - the relay fixture, registered by import
    run,
)

from parley_bridge import keys, pairing
from parley_bridge.relay import PAIRING_HEADER, RelayClient
from parley_common import signing

CODE_LINE = re.compile(r"Pairing code: ([A-Z2-9]{4}) ([A-Z2-9]{4})")
PNG_LINE = re.compile(r"QR image: (.+?) \(removed when pairing ends\)")


OWNER = "owner-send-a"
"""An owner the relay fixture's approval stand-in knows, so the test can approve."""


async def _claim(relay: RelayServer, code: str, owner: str = OWNER) -> dict[str, Any]:
    async with httpx.AsyncClient(base_url=relay.url) as http:
        response = await http.post(
            "/pairing/claim",
            json={"code": code, "display_name": "Sara, test display name"},
            headers={PRINCIPAL_HEADER: f"owner:{owner}"},
        )
    assert response.status_code == 200, response.json()
    data: dict[str, Any] = response.json()
    return data


def _approve(relay: RelayServer, claimed: dict[str, Any], owner: str = OWNER) -> None:
    """The owner approves the sheet (T-0118: the link is made here, not at the claim). The
    fixture's permissions read devices from its stand-in directory, so the claimed device
    is put there first."""
    device = claimed["device"]
    relay.registry.add_assistant(
        owner, device["id"], signing.PublicKey.from_base64url(device["public_key"])
    )
    link_assistant(relay, owner, device["id"], [{"id": owner, "kind": "owner"}])


def test_pair_shows_code_and_qr_then_stores_the_key_owner_only(
    relay: RelayServer, tmp_path: Path
) -> None:
    settings = make_settings(tmp_path, relay_url=relay.url)
    lines: list[str] = []

    async def claim_when_shown() -> dict[str, Any]:
        for _ in range(200):
            match = next((CODE_LINE.search(line) for line in lines if CODE_LINE.search(line)), None)
            if match:
                break
            await asyncio.sleep(0.05)
        assert match, lines
        code = match.group(1) + match.group(2)
        png_match = next(m for m in (PNG_LINE.search(line) for line in lines) if m)
        png_path = Path(png_match.group(1))
        assert png_path.is_file() and png_path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
        data = await _claim(relay, code)
        # Claimed is not linked (T-0118): the bridge keeps waiting and stores nothing.
        await asyncio.sleep(pairing.POLL_INTERVAL + 0.5)
        assert not settings.key_path.exists()
        assert not any("Linked by" in line for line in lines)
        await asyncio.to_thread(_approve, relay, data)
        data["png_path"] = str(png_path)
        return data

    async def scenario() -> None:
        client = RelayClient(httpx.AsyncClient(base_url=relay.url))
        try:
            claimed, key = await asyncio.gather(
                claim_when_shown(),
                pairing.pair(client, settings, label="test label", write=lines.append),
            )
        finally:
            await client.aclose()
        assert key.device_id == claimed["device"]["id"]
        assert not Path(claimed["png_path"]).exists()
        printed = "\n".join(lines).split("\n")
        qr_lines = [line for line in printed if set(line) & {"█", "▀", "▄"}]
        assert len(qr_lines) >= 10  # the ASCII QR was printed
        assert any("Linked by Sara, test display name" in line for line in lines)

    run(scenario())
    stored = keys.load(settings.key_path)
    assert stored.relay_url == relay.url
    assert isinstance(stored.private_key, signing.PrivateKey)
    raw = json.loads(settings.key_path.read_text(encoding="utf-8"))
    assert set(raw) == {"format_version", "device_id", "private_key", "relay_url", "paired_at"}
    if sys.platform != "win32":
        assert settings.key_path.stat().st_mode & 0o777 == 0o600
        assert settings.key_path.parent.stat().st_mode & 0o777 == 0o700
    code_shown = next(CODE_LINE.search(line) for line in lines if CODE_LINE.search(line))
    assert code_shown is not None
    plain_code = code_shown.group(1) + code_shown.group(2)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert plain_code not in path.read_text(encoding="utf-8", errors="ignore")


def test_pair_refuses_when_a_key_is_already_stored(relay: RelayServer, tmp_path: Path) -> None:
    settings = make_settings(tmp_path, relay_url=relay.url)
    settings.key_path.parent.mkdir(parents=True)
    settings.key_path.write_text("{}", encoding="utf-8")
    client = RelayClient(httpx.AsyncClient(base_url=relay.url))

    async def scenario() -> None:
        try:
            with pytest.raises(pairing.PairingError, match="unlink"):
                await pairing.pair(client, settings, label=None, write=lambda _: None)
        finally:
            await client.aclose()

    run(scenario())


class ScriptedRelay:
    """``/pairing/start`` and ``/pairing/status`` answering what the test scripts."""

    def __init__(self, starts: list[tuple[int, dict[str, Any]]], statuses: list[str]) -> None:
        self.starts = starts
        self.statuses = statuses
        self.start_calls = 0
        self.status_headers: list[str] = []
        self.status_urls: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/pairing/start":
            self.start_calls += 1
            status, started_body = self.starts.pop(0)
            return httpx.Response(status, json=started_body)
        assert request.url.path == "/pairing/status"
        self.status_headers.append(request.headers.get(PAIRING_HEADER, ""))
        self.status_urls.append(str(request.url))
        state = self.statuses.pop(0)
        body: dict[str, Any] = {"type": "status", "id": "pid-1", "status": state}
        if state == "linked":
            body.update({"device_id": "dev-9", "owner_display_name": "Owner", "linked": True})
        if state.startswith("claimed"):
            # A relay from before T-0118: claimed, and linked once approved.
            body.update({"status": "claimed", "device_id": "dev-9", "linked": state.endswith("+")})
        return httpx.Response(200, json=body)


def started(code: str = "ABCDEFGH", pairing_id: str = "pid-1") -> tuple[int, dict[str, Any]]:
    return (
        201,
        {
            "type": "pairing",
            "id": pairing_id,
            "code": code,
            "qr_payload": f"https://relay.example/link?code={code}",
            "created": "2026-10-10T22:00:00Z",
            "expires": "2026-10-10T22:10:00Z",
        },
    )


def refused(status: int, code: str) -> tuple[int, dict[str, Any]]:
    return status, {"type": "refused", "code": code}


def test_start_backs_off_on_already_open_busy_and_rate_limited(tmp_path: Path) -> None:
    script = ScriptedRelay(
        [
            refused(409, "already-open"),
            refused(503, "busy"),
            refused(429, "rate-limited"),
            started(),
        ],
        ["waiting", "linked"],
    )
    client = RelayClient(
        httpx.AsyncClient(transport=httpx.MockTransport(script.handler), base_url="http://relay")
    )
    sleep = FastSleep()
    settings = make_settings(tmp_path)

    async def scenario() -> None:
        try:
            key = await pairing.pair(
                client, settings, label=None, write=lambda _: None, sleep=sleep
            )
        finally:
            await client.aclose()
        assert key.device_id == "dev-9"

    run(scenario())
    assert script.start_calls == 4
    assert sleep.delays[:3] == [1, 2, 4]


def test_the_first_code_is_kept_until_it_expires_and_the_id_is_the_poll_handle(
    tmp_path: Path,
) -> None:
    script = ScriptedRelay(
        [started("AAAABBBB", "pid-1"), started("CCCCDDDD", "pid-2")],
        ["waiting", "waiting", "waiting", "expired", "waiting", "linked"],
    )
    client = RelayClient(
        httpx.AsyncClient(transport=httpx.MockTransport(script.handler), base_url="http://relay")
    )
    sleep = FastSleep()
    settings = make_settings(tmp_path)
    lines: list[str] = []

    async def scenario() -> None:
        try:
            await pairing.pair(client, settings, label=None, write=lines.append, sleep=sleep)
        finally:
            await client.aclose()

    run(scenario())
    assert script.start_calls == 2  # one start per code; polling never re-starts
    assert script.status_headers == ["pid-1"] * 4 + ["pid-2"] * 2
    assert all("AAAABBBB" not in url and "pid" not in url for url in script.status_urls)
    assert sleep.delays.count(pairing.POLL_INTERVAL) == 4
    assert any("previous code expired" in line for line in lines)


def test_a_vanished_pairing_counts_as_expired_and_transient_errors_keep_polling(
    tmp_path: Path,
) -> None:
    calls = {"status": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/pairing/start":
            status, body = started()
            return httpx.Response(status, json=body)
        calls["status"] += 1
        if calls["status"] == 1:
            raise httpx.ConnectError("blip")
        if calls["status"] == 2:
            return httpx.Response(500, json={"type": "refused", "code": "oops"})
        body = {"type": "status", "id": "pid-1", "status": "linked", "device_id": "dev-9"}
        return httpx.Response(200, json=body)

    client = RelayClient(
        httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://relay")
    )
    sleep = FastSleep()

    async def scenario() -> None:
        try:
            key = await pairing.pair(
                client, make_settings(tmp_path), label=None, write=lambda _: None, sleep=sleep
            )
        finally:
            await client.aclose()
        assert key.device_id == "dev-9"

    run(scenario())
    assert sleep.delays == [1, 2]


def _scripted_pair(tmp_path: Path, statuses: list[str]) -> tuple[ScriptedRelay, Any, list[str]]:
    script = ScriptedRelay([started()], statuses)
    client = RelayClient(
        httpx.AsyncClient(transport=httpx.MockTransport(script.handler), base_url="http://relay")
    )
    settings = make_settings(tmp_path)
    lines: list[str] = []

    async def scenario() -> Any:
        try:
            return await pairing.pair(
                client, settings, label=None, write=lines.append, sleep=FastSleep()
            )
        finally:
            await client.aclose()

    outcome: Any
    try:
        outcome = run(scenario())
    except pairing.PairingError as error:
        outcome = error
    return script, (outcome, settings), lines


def test_a_claim_is_no_link_until_approved_and_declined_stores_nothing(tmp_path: Path) -> None:
    """T-0118: the bridge polls through the owner's sheet and stores its key only on
    ``linked``; ``declined`` (Not now, or the sheet left) ends pairing with nothing kept."""
    script, (outcome, settings), lines = _scripted_pair(
        tmp_path, ["waiting", "waiting", "declined"]
    )
    assert isinstance(outcome, pairing.PairingError)
    assert "did not approve" in str(outcome)
    assert not settings.key_path.exists()
    assert not any("Linked by" in line for line in lines)
    assert script.statuses == []


def test_an_older_relays_claim_waits_for_its_linked_flag(tmp_path: Path) -> None:
    """A relay from before T-0118 says ``claimed`` at the claim: the bridge stores nothing
    until the same status carries ``linked: true``."""
    script, (outcome, settings), lines = _scripted_pair(
        tmp_path, ["waiting", "claimed", "claimed", "claimed+"]
    )
    assert isinstance(outcome, keys.DeviceKey) and outcome.device_id == "dev-9"
    assert keys.load(settings.key_path).device_id == "dev-9"
    assert script.statuses == []
    assert any("permission is approved" in line for line in lines)
