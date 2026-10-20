"""T-0052: the ``recipients`` tool. Who the assistant may message, from the relay.

The relay tests run the real relay in process (criterion 2): the owner links the
assistant to a contact, a stranger, a group and the owner's own id, and the tool returns
the contact by name and the group, nothing else (criterion 3). The scripted tests fake
the two routes with ``httpx.MockTransport`` for the refusal and failure paths, and for
the bridge's own courtesy: a recipient is shown as id, name and kind whatever else a
relay might send.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from support import (
    FakeOpener,
    FastSleep,
    as_owner,
    connect_owners,
    link_assistant,
    make_key,
    make_settings,
    relay_server,  # noqa: F401 - the relay fixture, registered by import
    run,
)

from parley_bridge import server
from parley_bridge.bridge import Bridge
from parley_bridge.connection import Connection, challenge_payload
from parley_bridge.keys import DeviceKey
from parley_bridge.relay import (
    CHALLENGE_HEADER,
    DEVICE_HEADER,
    RECIPIENTS_PATH,
    SIGNATURE_HEADER,
    RelayClient,
)
from parley_common import signing

RECIPIENT_FIELDS = {"id", "name", "kind"}
RESULT_FIELDS = {
    "ok",
    "decided_by",
    "count",
    "recipients",
    "level",
    "permission_id",
    "messages_left",
    "wakeups_left",
    "day_end",
    "end_date",
    "paused",
}
CHALLENGE = signing.b64url_encode(bytes(range(32)))


class FakeRecipientsRoute:
    """``POST /connect/challenge`` and ``GET /devices/me/recipients`` as the relay builds
    them (T-0052): one challenge, spent by the first proof that verifies."""

    def __init__(self, key: DeviceKey) -> None:
        self.key = key
        self.answer: tuple[int, dict[str, Any]] = (200, {"type": "recipients", "recipients": []})
        self.unreachable = False
        self.challenge: Any = CHALLENGE
        self.proofs: list[dict[str, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.unreachable:
            raise httpx.ConnectError("down")
        if request.url.path == "/connect/challenge":
            return httpx.Response(200, json={"type": "challenge", "challenge": self.challenge})
        assert request.url.path == RECIPIENTS_PATH and request.method == "GET"
        headers = {
            name: request.headers.get(name, "")
            for name in (DEVICE_HEADER, CHALLENGE_HEADER, SIGNATURE_HEADER)
        }
        self.proofs.append(headers)
        payload = signing.verify(headers[SIGNATURE_HEADER], self.key.public_key)
        assert payload == challenge_payload(self.key.device_id, headers[CHALLENGE_HEADER], "domain")
        assert headers[DEVICE_HEADER] == self.key.device_id
        status, data = self.answer
        return httpx.Response(status, json=data)


class Bench:
    def __init__(self, tmp_path: Any) -> None:
        self.key = make_key()
        self.settings = make_settings(tmp_path)
        self.connection = Connection(self.key, self.settings, FakeOpener(), sleep=FastSleep())
        self.route = FakeRecipientsRoute(self.key)
        transport = httpx.MockTransport(self.route.handler)
        self.client = RelayClient(httpx.AsyncClient(transport=transport, base_url="http://relay"))
        self.bridge = Bridge(self.key, self.settings, self.connection, self.client)


# ---------------------------------------------------------------- criterion 2: the real relay


def test_recipients_through_the_real_relay_lists_who_the_owner_picked(
    relay: Any, tmp_path: Any
) -> None:
    """Criteria 2 and 3 against the in-process relay: the tool signs the relay's challenge
    with the device key and returns the recipients the owner picked as the owner's own
    screen shows them, the contact by the name the contact gave and the group unnamed;
    the stranger and the owner's own id are not on it (ruling 11), and no recipient
    carries anything beyond id, name and kind (product rule 5). The refusals come back
    verbatim: ``ended`` before the link and after the unlink, ``bad-signature`` for a
    wrong key, ``revoked-device`` once the device is retired."""
    owner_a, owner_b, owner_c = "owner-send-a", "owner-send-b", "owner-send-c"
    key = make_key("recipients-assistant")
    registry = relay.registry
    registry.add_person_device(owner_a, "recipients-phone-a")
    registry.add_assistant(owner_a, key.device_id, key.public_key)
    registry.add_person_device(owner_b, "recipients-phone-b")
    registry.add_person_device(owner_c, "recipients-phone-c")
    connect_owners(relay, owner_a, owner_b)
    settings = make_settings(tmp_path, relay_url=relay.url)

    async def scenario() -> None:
        client = RelayClient(httpx.AsyncClient(base_url=relay.url))
        connection = Connection(key, settings, FakeOpener(), sleep=FastSleep())
        bridge = Bridge(key, settings, connection, client)
        try:
            before = await bridge.recipients()
            assert before == {
                "ok": False,
                "reason": "ended",
                "status": "refused",
                "decided_by": "relay",
            }
            permission_id = link_assistant(
                relay,
                owner_a,
                key.device_id,
                [owner_b, owner_c, owner_a, {"id": "group-recipients", "kind": "group"}],
            )
            listed = await bridge.recipients()
            assert set(listed) == RESULT_FIELDS, listed
            assert listed["ok"] is True and listed["decided_by"] == "relay"
            assert listed["recipients"] == [
                {"id": "group-recipients", "name": None, "kind": "group"},
                {"id": owner_b, "name": "Owner Send B", "kind": "owner"},
            ]
            assert all(set(item) == RECIPIENT_FIELDS for item in listed["recipients"])
            assert listed["count"] == 2 and listed["permission_id"] == permission_id
            assert listed["level"] == "default" and listed["paused"] is False
            assert (listed["messages_left"], listed["wakeups_left"]) == (20, 10)
            assert listed["day_end"] and listed["end_date"]
            server.set_bridge(bridge)
            try:
                result = await server.mcp.call_tool("recipients", {})
            finally:
                server.set_bridge(None)
            structured = result[1] if isinstance(result, tuple) else result
            assert isinstance(structured, dict)
            assert structured["recipients"] == listed["recipients"]
            wrong = Bridge(make_key(key.device_id), settings, connection, client)
            bad = await wrong.recipients()
            assert bad["ok"] is False and bad["reason"] == "bad-signature"
            with httpx.Client(base_url=relay.url) as http:
                unlinked = http.delete(f"/permissions/{permission_id}", headers=as_owner(owner_a))
                assert unlinked.status_code == 200, unlinked.text
            after = await bridge.recipients()
            assert after["ok"] is False and after["reason"] == "ended"
            registry.retire(key.device_id)
            revoked = await bridge.recipients()
            assert revoked["ok"] is False and revoked["reason"] == "revoked-device"
        finally:
            await client.aclose()

    run(scenario())


def test_the_three_tools_are_registered(tmp_path: Any) -> None:
    async def scenario() -> None:
        tools = {tool.name for tool in await server.mcp.list_tools()}
        assert tools == {"check_inbox", "send", "recipients"}
        [tool] = [t for t in await server.mcp.list_tools() if t.name == "recipients"]
        assert "before your first message" in (tool.description or "").lower()
        assert "before your first message" in server.INSTRUCTIONS.lower()

    run(scenario())


# ---------------------------------------------------------------- the scripted routes


def test_recipients_signs_the_relay_challenge_and_returns_the_list_verbatim(
    tmp_path: Any,
) -> None:
    async def scenario() -> None:
        bench = Bench(tmp_path)
        bench.route.answer = (
            200,
            {
                "type": "recipients",
                "permission_id": "perm-1",
                "level": "medium",
                "recipients": [
                    {"id": "owner-b", "name": "Owner B", "kind": "owner"},
                    {"id": "group-1", "name": None, "kind": "group"},
                ],
                "count": 2,
                "messages_left": 49,
                "wakeups_left": 20,
                "day_end": "2026-10-11T19:00:00Z",
                "end_date": "2026-10-24T22:00:00Z",
                "paused": False,
            },
        )
        listed = await bench.bridge.recipients()
        assert listed == {
            "ok": True,
            "decided_by": "relay",
            "count": 2,
            "recipients": [
                {"id": "owner-b", "name": "Owner B", "kind": "owner"},
                {"id": "group-1", "name": None, "kind": "group"},
            ],
            "level": "medium",
            "permission_id": "perm-1",
            "messages_left": 49,
            "wakeups_left": 20,
            "day_end": "2026-10-11T19:00:00Z",
            "end_date": "2026-10-24T22:00:00Z",
            "paused": False,
        }
        [proof] = bench.route.proofs
        assert proof[CHALLENGE_HEADER] == CHALLENGE and proof[DEVICE_HEADER] == bench.key.device_id
        await bench.client.aclose()

    run(scenario())


def test_recipients_shows_three_fields_whatever_the_relay_adds(tmp_path: Any) -> None:
    """Product rule 5 on the bridge's side too: a recipient is id, name and kind, so a
    field a relay might add about someone never reaches the assistant; a control
    character in a name is removed; an item without an id is dropped."""

    async def scenario() -> None:
        bench = Bench(tmp_path)
        bench.route.answer = (
            200,
            {
                "type": "recipients",
                "recipients": [
                    {"id": "owner-b", "name": "Owner\u0007 B", "kind": "owner", "phone": "x"},
                    {"name": "nobody", "kind": "owner"},
                    "owner-c",
                ],
                "messages_left": "20",
                "paused": "yes",
            },
        )
        listed = await bench.bridge.recipients()
        assert listed["recipients"] == [{"id": "owner-b", "name": "Owner B", "kind": "owner"}]
        assert listed["count"] == 1 and listed["messages_left"] is None
        assert listed["paused"] is False and listed["level"] is None
        assert "phone" not in json.dumps(listed)
        await bench.client.aclose()

    run(scenario())


def test_recipients_refusals_and_failures_say_who_decided(tmp_path: Any) -> None:
    async def scenario() -> None:
        bench = Bench(tmp_path)
        for status, code in ((403, "ended"), (403, "revoked-device"), (401, "bad-challenge")):
            bench.route.answer = (status, {"type": "refused", "code": code})
            refused = await bench.bridge.recipients()
            assert refused == {
                "ok": False,
                "reason": code,
                "status": "refused",
                "decided_by": "relay",
            }
        bench.route.challenge = "not a challenge"
        malformed = await bench.bridge.recipients()
        assert malformed["ok"] is False and malformed["reason"] == "malformed"
        assert malformed["decided_by"] == "bridge"
        bench.route.challenge = None
        assert (await bench.bridge.recipients())["reason"] == "malformed"
        bench.route.unreachable = True
        down = await bench.bridge.recipients()
        assert down["ok"] is False and down["reason"] == "relay-unreachable"
        assert down["decided_by"] == "bridge"
        assert len(bench.route.proofs) == 3  # nothing was signed for a bad challenge
        await bench.client.aclose()

    run(scenario())
