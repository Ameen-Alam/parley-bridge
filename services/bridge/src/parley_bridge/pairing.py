"""``parley-bridge pair``: a code and a QR, then the key file once the owner claims it.

The flow (criterion 2; bridge operations 1 and 2; T-0008's rules from its review):

1. A fresh Ed25519 key pair is made in memory. Pairing refuses to start when a key file
   already exists: ``unlink`` first.
2. ``POST /pairing/start`` with the public key and the reported label. ``409
   already-open``, ``503 busy``, ``429 rate-limited`` and an unreachable relay are
   retried with a backoff from 1 to 60 seconds, for at most :data:`START_PATIENCE`.
3. The eight-character code is printed with its QR code (half blocks in the terminal,
   and a PNG written to a private temporary directory whose path is printed; it is
   removed when pairing ends). The code is shown once and never logged.
4. ``GET /pairing/status`` is polled with the pairing ID in the ``X-Parley-Pairing``
   header, every :data:`POLL_INTERVAL` seconds. The ID is the handle, never the code.
   The first code is kept for its whole ten minutes; only ``expired`` starts a new one,
   at most :data:`MAX_CODES` times. A transient failure backs off and keeps polling.
5. On ``claimed`` the device ID and the private key are written to
   ``PARLEY_BRIDGE_KEY_PATH`` with owner-only permissions (story 9.3). Nothing else is
   stored.

Output goes through a writer callable (stdout in the CLI); nothing here logs.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from parley_bridge import keys, qr
from parley_bridge.config import Settings
from parley_bridge.relay import RelayClient, RelayRefusedError, RelayUnreachableError, clean
from parley_common import clock, signing

POLL_INTERVAL = 2.0
START_PATIENCE = 600.0
"""Seconds the start is retried for when the relay is busy or unreachable."""
MAX_CODES = 3
"""Codes asked for in one ``pair`` run; each lives ten minutes on the relay."""
MIN_BACKOFF = 1.0
MAX_BACKOFF = 60.0
RETRIED_START_CODES = frozenset({"already-open", "busy", "rate-limited"})

Writer = Callable[[str], None]
Sleep = Callable[[float], Awaitable[None]]


class PairingError(Exception):
    """Pairing did not end with a claim. The message says why in plain words, no code."""


async def pair(
    client: RelayClient,
    settings: Settings,
    *,
    label: str | None,
    write: Writer,
    sleep: Sleep = asyncio.sleep,
    unicode: bool | None = None,
) -> keys.DeviceKey:
    """Run the pairing flow to its end and return the key that was stored."""
    if keys.exists(settings.key_path):
        raise PairingError("already paired: run 'parley-bridge unlink' first to pair again")
    pair_keys = signing.generate_keypair()
    public = pair_keys.public.to_base64url()
    for attempt in range(MAX_CODES):
        started = await _start_with_patience(client, public, label, sleep)
        pairing_id = clean(started.get("id"), 128)
        if not pairing_id:
            raise PairingError("the relay started a pairing without an ID")
        png_dir = Path(tempfile.mkdtemp(prefix="parley-pairing-"))
        try:
            _show(started, png_dir, write, unicode)
            if attempt:
                write("The previous code expired. This is a new one.")
            status = await _wait_for_claim(client, pairing_id, sleep)
        finally:
            shutil.rmtree(png_dir, ignore_errors=True)
        if status.get("status") == "claimed":
            device_id = status.get("device_id")
            if not isinstance(device_id, str) or not device_id:
                raise PairingError("the relay reported a claim without a device ID")
            key = keys.DeviceKey(device_id, pair_keys.private, settings.relay_url, clock.utc_now())
            keys.save(settings.key_path, key)
            owner = clean(status.get("owner_display_name"), 80) or "the owner"
            write(f"Linked by {owner}. Key stored at {settings.key_path}.")
            if status.get("linked"):
                write("The permission is approved; start the bridge with 'parley-bridge run'.")
            else:
                write("Waiting for the owner to approve the permission in the app.")
            return key
    raise PairingError(f"no claim after {MAX_CODES} codes; run pair again when the owner is ready")


async def _start_with_patience(
    client: RelayClient, public_key: str, label: str | None, sleep: Sleep
) -> dict[str, Any]:
    waited = 0.0
    delay = MIN_BACKOFF
    while True:
        try:
            return await client.pairing_start(public_key, label)
        except RelayRefusedError as error:
            if error.code not in RETRIED_START_CODES:
                raise PairingError(f"the relay refused to start pairing ({error.code})") from error
        except RelayUnreachableError:
            pass
        if waited >= START_PATIENCE:
            raise PairingError("the relay stayed busy or unreachable; try again later")
        await sleep(delay)
        waited += delay
        delay = min(delay * 2, MAX_BACKOFF)


async def _wait_for_claim(client: RelayClient, pairing_id: str, sleep: Sleep) -> dict[str, Any]:
    delay = MIN_BACKOFF
    while True:
        try:
            status = await client.pairing_status(pairing_id)
        except RelayRefusedError as error:
            if error.status in (404, 410):
                return {"status": "expired"}
            await sleep(delay)
            delay = min(delay * 2, MAX_BACKOFF)
            continue
        except RelayUnreachableError:
            await sleep(delay)
            delay = min(delay * 2, MAX_BACKOFF)
            continue
        delay = MIN_BACKOFF
        state = status.get("status")
        if state in ("claimed", "expired"):
            return status
        await sleep(POLL_INTERVAL)


def _show(started: dict[str, Any], png_dir: Path, write: Writer, unicode: bool | None) -> None:
    code = clean(started.get("code"), 16)
    payload = clean(started.get("qr_payload"), 512)
    expires = clean(started.get("expires"), 32)
    write("")
    write(f"Pairing code: {_spaced(code)}")
    write(f"Expires at {expires} (UTC). Open the app, choose Link an assistant, enter the code")
    write("or scan this:")
    write("")
    try:
        picture = qr.encode(payload)
    except qr.QrError:
        write(f"(the link is too long for the QR encoder; use the code or {payload})")
        return
    write(qr.render_ascii(picture, unicode=_use_unicode(unicode)))
    write("")
    png_path = png_dir / "parley-pairing.png"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(png_path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(qr.render_png(picture))
    write(f"QR image: {png_path} (removed when pairing ends)")
    write("")


def _spaced(code: str) -> str:
    return " ".join((code[:4], code[4:])) if len(code) == 8 else code


def _use_unicode(unicode: bool | None) -> bool:
    if unicode is not None:
        return unicode
    encoding = getattr(sys.stdout, "encoding", None) or ""
    return encoding.lower().replace("-", "") in ("utf8", "utf16", "utf32")
