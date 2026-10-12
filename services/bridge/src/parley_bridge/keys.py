"""The device key file: the one thing the bridge keeps on disk (story 9.3).

The file at ``PARLEY_BRIDGE_KEY_PATH`` is a small JSON object with the device ID the
relay gave at pairing, the Ed25519 private key seed (base64url), the relay URL it was
paired with and the time of pairing. It is created with owner-only permissions
(``0600``; a directory the bridge itself creates gets ``0700``, an existing one is left
as it is; on Windows the inherited rights are replaced by a grant to the current user,
best effort) and never overwritten in place: pairing refuses when it exists, and
:func:`delete` is what ``parley-bridge unlink`` runs.

No message text, no code and no label is ever written here; nothing logs the content.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from parley_common import clock, signing

FORMAT_VERSION = 1


class KeyFileError(Exception):
    """The key file is missing, unreadable or not what the bridge wrote."""


@dataclass(frozen=True, slots=True)
class DeviceKey:
    """What the file holds. The repr shows the device ID only, never the seed."""

    device_id: str
    private_key: signing.PrivateKey
    relay_url: str
    paired_at: datetime

    def __repr__(self) -> str:
        return f"DeviceKey(device_id={self.device_id!r})"

    @property
    def public_key(self) -> signing.PublicKey:
        return self.private_key.public_key()


def exists(path: Path) -> bool:
    return path.is_file()


def load(path: Path) -> DeviceKey:
    """Read the key file. Raises :class:`KeyFileError` when it is absent or malformed."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise KeyFileError("not paired: the key file does not exist") from error
    except OSError as error:
        raise KeyFileError("the key file cannot be read") from error
    try:
        data = json.loads(text)
    except ValueError as error:
        raise KeyFileError("the key file is not JSON") from error
    if not isinstance(data, dict) or data.get("format_version") != FORMAT_VERSION:
        raise KeyFileError("the key file has an unknown format")
    device_id = data.get("device_id")
    seed = data.get("private_key")
    relay_url = data.get("relay_url")
    paired_at = data.get("paired_at")
    if (
        not isinstance(device_id, str)
        or not isinstance(seed, str)
        or not isinstance(relay_url, str)
        or not (device_id and seed and relay_url)
    ):
        raise KeyFileError("the key file is missing a field")
    try:
        private = signing.PrivateKey.from_base64url(seed)
        moment = clock.from_iso(paired_at) if isinstance(paired_at, str) else clock.utc_now()
    except (signing.SigningError, ValueError) as error:
        raise KeyFileError("the key file holds a key the bridge cannot use") from error
    return DeviceKey(device_id, private, relay_url, moment)


def save(path: Path, key: DeviceKey) -> None:
    """Write the key file, owner-only, refusing to replace an existing one."""
    if not path.parent.exists():
        path.parent.mkdir(parents=True)
        _restrict(path.parent, directory=True)  # only a directory the bridge made
    payload = {
        "format_version": FORMAT_VERSION,
        "device_id": key.device_id,
        "private_key": key.private_key.to_base64url(),
        "relay_url": key.relay_url,
        "paired_at": clock.to_iso(key.paired_at),
    }
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise KeyFileError("already paired: unlink first to pair again") from error
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    _restrict(path, directory=False)


def delete(path: Path) -> bool:
    """Remove the key file (``unlink``). True when a file was removed."""
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


def _restrict(path: Path, *, directory: bool) -> None:
    """Owner-only rights. POSIX: chmod. Windows: replace inherited rights with a grant to
    the current user, best effort; a failure leaves the file where the user's profile
    protection applies."""
    if os.name != "nt":
        os.chmod(path, 0o700 if directory else 0o600)
        return
    user = os.environ.get("USERNAME")
    icacls = shutil.which("icacls")
    if not user or not icacls:
        return
    try:
        subprocess.run(  # noqa: S603 - fixed program, arguments are the path and the user
            [icacls, str(path), "/inheritance:r", "/grant:r", f"{user}:(F)"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return
