"""The Parley bridge: an MCP server that gives any assistant ``check_inbox`` and ``send``.

Started from ``reference/c2chat/c2chat.py`` (T-0009; stories 9.1 to 9.5, 9.7, 4.13 and
4.14; the standards table's MCP row; the OpenClaw maintainer condition, untrusted label
and outbound only; the power user condition, source public, no inbound ports, reason
code; ruling 6). The local store of c2chat is replaced by the relay: pairing with a code
(T-0008), the assistant connection (T-0007) for what comes in, and a signed envelope
(T-0001) posted to the relay for what goes out.

The pieces: :mod:`parley_bridge.config` (environment only), :mod:`parley_bridge.keys`
(the one file on disk: the device key), :mod:`parley_bridge.qr` (the pairing QR without a
dependency), :mod:`parley_bridge.pairing` (``parley-bridge pair``),
:mod:`parley_bridge.relay` (the HTTP side, the only network destination),
:mod:`parley_bridge.connection` (WebSocket with long-poll fallback, reconnect, wake
command, acknowledgement), :mod:`parley_bridge.bridge` (the two tools) and
:mod:`parley_bridge.server` (the MCP server and the command line).

Rules kept everywhere: no message text on disk or in a log line; every limit is the
relay's and the bridge's guards are courtesies; messages from other owners are labelled
untrusted in every tool result; message bodies are data and are never interpreted.
"""

__version__ = "0.1.0"
