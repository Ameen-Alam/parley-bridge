"""The bridge's end-to-end tests start the relay, which is not part of the public bridge
repository: those tests are skipped here (they ran in the private repository before this
tree was built). Every other test runs exactly as it does there.

A test needs the relay when it asks for the ``relay`` fixture of the bridge's test
support; this hook marks such tests skipped unless ``parley_relay`` is importable.
"""

from __future__ import annotations

import importlib.util

import pytest

RELAY_PRESENT = importlib.util.find_spec("parley_relay") is not None
NEEDS_RELAY = pytest.mark.skip(
    reason="needs the relay, which is not part of the public bridge repository"
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if RELAY_PRESENT:
        return
    for item in items:
        if "relay" in getattr(item, "fixturenames", ()):
            item.add_marker(NEEDS_RELAY)
