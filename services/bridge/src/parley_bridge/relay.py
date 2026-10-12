"""The bridge's HTTP side of the relay: pairing, the long-poll fallback and sending.

One :class:`RelayClient` wraps an :class:`httpx.AsyncClient` whose base URL is
``PARLEY_RELAY_URL``, the bridge's only network destination. Tests hand it a client on
``httpx.ASGITransport`` over the in-process relay. Every call returns the relay's JSON
as data; a refusal is a :class:`RelayRefusedError` carrying the relay's stable code and HTTP
status, and a network failure is a :class:`RelayUnreachableError`. Nothing here logs, and no
exception message carries a body, a code, a token or an ID.

Routes used, all built by earlier tasks except the send:

- ``POST /pairing/start``, ``GET /pairing/status`` with the ID in ``X-Parley-Pairing``
  (T-0008).
- ``POST /connect/challenge``, ``POST /connect/session``, ``GET /poll``, ``POST /ack``
  (T-0007's long-poll fallback).
- ``POST /messages`` (T-0005 builds it; this is the contract the bridge speaks):
  ``{"device_id": <id>, "envelope": <wire envelope>, "signature": <JWS>}`` where the JWS
  payload is exactly the envelope's canonical JSON (:meth:`Envelope.to_json`), signed by
  the device key. The answer is ``{"type": "accepted" | "held", "request_id": <id>,
  "code": <code>?, "retry_at": <time>?}`` or a 4xx ``{"type": "refused", "code": <code>,
  "retry_at": <time>?}`` with the record's codes (``not-connected``, ``blocked``,
  ``over-limit``, ``ended``, ``paused``, ``bounce-limit``, ``recipient-cap``,
  ``rate-limited``; ``held`` for a hold).
"""

from __future__ import annotations

import unicodedata
from typing import Any

import httpx

PAIRING_HEADER = "X-Parley-Pairing"
MESSAGES_PATH = "/messages"
POLL_WAIT_SECONDS = 25.0
"""The relay's longest poll (its ``MAX_WAIT_SECONDS``)."""


def clean(value: object, limit: int = 200) -> str:
    """A relay-supplied string made safe for a terminal or a log line: control and format
    characters removed, length capped at ``limit``. Anything that is not a string is
    the empty string."""
    if not isinstance(value, str):
        return ""
    kept = "".join(c for c in value if unicodedata.category(c) not in ("Cc", "Cf", "Zl", "Zp"))
    return kept[:limit]


class RelayError(Exception):
    """Base class. Messages never carry a value from the relay."""


class RelayUnreachableError(RelayError):
    """No usable answer came back: connection refused, timeout, or a body that is not JSON."""


class RelayRefusedError(RelayError):
    """The relay answered with a refusal: a stable ``code`` and the HTTP ``status``."""

    def __init__(self, code: str, status: int, data: dict[str, Any] | None = None) -> None:
        super().__init__("the relay refused the request")
        self.code = code
        self.status = status
        self.data = data or {}


class RelayClient:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------ pairing (T-0008)

    async def pairing_start(self, public_key: str, label: str | None) -> dict[str, Any]:
        body: dict[str, Any] = {"public_key": public_key}
        if label:
            body["label"] = label
        return await self._call("POST", "/pairing/start", json=body)

    async def pairing_status(self, pairing_id: str) -> dict[str, Any]:
        return await self._call("GET", "/pairing/status", headers={PAIRING_HEADER: pairing_id})

    # ------------------------------------------------------------ long poll (T-0007)

    async def challenge(self) -> dict[str, Any]:
        return await self._call("POST", "/connect/challenge")

    async def open_session(self, device_id: str, challenge: str, signature: str) -> dict[str, Any]:
        return await self._call(
            "POST",
            "/connect/session",
            json={"device_id": device_id, "challenge": challenge, "signature": signature},
        )

    async def poll(self, token: str, wait: float = POLL_WAIT_SECONDS) -> dict[str, Any]:
        return await self._call(
            "GET",
            "/poll",
            params={"wait": wait},
            headers=_bearer(token),
            timeout=wait + 10.0,
        )

    async def ack(self, token: str, wakeup_id: str, result: str) -> dict[str, Any]:
        return await self._call(
            "POST",
            "/ack",
            json={"wakeup_id": wakeup_id, "result": result},
            headers=_bearer(token),
        )

    # ------------------------------------------------------------ send (T-0005's door)

    async def send_message(
        self, device_id: str, envelope: dict[str, Any], signature: str
    ) -> dict[str, Any]:
        return await self._call(
            "POST",
            MESSAGES_PATH,
            json={"device_id": device_id, "envelope": envelope, "signature": signature},
        )

    # ------------------------------------------------------------ the one request path

    async def _call(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 20.0,
    ) -> dict[str, Any]:
        try:
            response = await self._http.request(
                method, path, json=json, params=params, headers=headers, timeout=timeout
            )
        except httpx.HTTPError as error:
            raise RelayUnreachableError("the relay did not answer") from error
        data = _json_of(response)
        if 200 <= response.status_code < 300:
            if data is None:
                raise RelayUnreachableError("the relay answered with something that is not JSON")
            return data
        code = _code_of(data, response.status_code)
        raise RelayRefusedError(code, response.status_code, data)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _json_of(response: httpx.Response) -> dict[str, Any] | None:
    try:
        data = response.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _code_of(data: dict[str, Any] | None, status: int) -> str:
    """The relay's stable code, or a bridge-side stand-in named after the HTTP status."""
    if data is not None:
        for key in ("code", "reason_code"):
            value = clean(data.get(key), 64)
            if value:
                return value
    return f"http-{status}"
