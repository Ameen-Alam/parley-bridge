"""Reach the relay the way a browser does: every address, both families, staggered.

What this module does (T-0053; requirement 6b, the relay reachable from every tester
network): the relay's name has an A and an AAAA record. On a network without working
IPv6 the resolver still lists the IPv6 address first, and a plain connect waits on it
until the opening handshake expires, so the bridge used to read a reachable relay as
``unreachable``. A :class:`Dialer` instead

- resolves the host once per connect and interleaves the two families, starting with the
  family that worked last time in this process, otherwise the resolver's first;
- starts the first attempt at once and the next one :data:`STAGGER_SECONDS` later, or at
  once when the previous attempt failed (happy eyeballs, RFC 8305), each attempt bounded
  by :data:`PER_ADDRESS_SECONDS`;
- keeps the first connection that answers, closes every other one, and remembers its
  family;
- raises :class:`DialError` only when every address failed.

:meth:`Dialer.open_socket` hands a connected socket to the WebSocket client
(:func:`parley_bridge.connection.open_websocket`); :func:`http_transport` gives httpx a
transport whose connections are raced the same way, for the long poll, pairing and
sending (:mod:`parley_bridge.relay`). Both share :data:`DIALER`, so the family learned on
one transport is tried first on the other. The relay's address is not private, but log
lines carry only the family and the attempt counts.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

import httpcore
import httpx

log = logging.getLogger("parley_bridge.dial")

STAGGER_SECONDS = 0.3
"""How long an attempt runs alone before the next address is tried alongside it."""
PER_ADDRESS_SECONDS = 5.0
"""The longest one attempt may take; the race as a whole ends sooner when one answers."""

Address = tuple[int, tuple[Any, ...]]
"""``(family, sockaddr)`` as :func:`socket.getaddrinfo` returns them."""
Resolver = Callable[[str, int], Awaitable[list[Address]]]


class DialError(OSError):
    """Every address of the relay failed, or the name did not resolve. No address in it."""


async def resolve(host: str, port: int) -> list[Address]:
    """The system resolver, TCP addresses only, in the order it returned them."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [(family, sockaddr) for family, _, _, _, sockaddr in infos]


def family_name(family: int) -> str:
    if family == socket.AF_INET6:
        return "ipv6"
    if family == socket.AF_INET:
        return "ipv4"
    return "other"


_SETTLING: set[asyncio.Future[None]] = set()
"""Clean-ups still running after their race ended, held so none is collected early."""


async def _settle[T](tasks: list[asyncio.Task[T]], discard: Callable[[T], Awaitable[None]]) -> None:
    """Wait for cancelled attempts and close any connection one made before it stopped."""
    for late in await asyncio.gather(*tasks, return_exceptions=True):
        if not isinstance(late, BaseException):
            await discard(late)


class Dialer:
    def __init__(
        self,
        *,
        stagger: float = STAGGER_SECONDS,
        per_address: float = PER_ADDRESS_SECONDS,
        resolver: Resolver = resolve,
    ) -> None:
        self.stagger = stagger
        self.per_address = per_address
        self._resolver = resolver
        self.family: int | None = None
        """The family of the last connection that answered; tried first next time."""

    def order(self, addresses: Iterable[Address]) -> list[Address]:
        """Distinct addresses, the two families interleaved, the remembered family first."""
        unique = list(dict.fromkeys((family, tuple(addr)) for family, addr in addresses))
        if not unique:
            return []
        families = list(dict.fromkeys(family for family, _ in unique))
        if self.family in families:
            families.remove(self.family)
            families.insert(0, self.family)
        groups = [[a for a in unique if a[0] == family] for family in families]
        ordered: list[Address] = []
        for index in range(max(len(group) for group in groups)):
            ordered.extend(group[index] for group in groups if index < len(group))
        return ordered

    async def race[T](
        self,
        host: str,
        port: int,
        attempt: Callable[[Address], Awaitable[T]],
        discard: Callable[[T], Awaitable[None]],
    ) -> T:
        """Run ``attempt`` over the host's addresses, staggered, and return the first result.

        Every other result that still arrives is handed to ``discard``. Raises
        :class:`DialError` when the name does not resolve or every attempt failed.
        """
        try:
            candidates = self.order(await self._resolver(host, port))
        except OSError as error:
            log.info("relay name did not resolve")
            raise DialError("the relay's name did not resolve") from error
        if not candidates:
            raise DialError("the relay's name has no address")

        async def bounded(address: Address) -> T:
            return await asyncio.wait_for(attempt(address), self.per_address)

        running: dict[asyncio.Task[T], Address] = {}
        started = failed = 0
        won: tuple[T, Address] | None = None
        try:
            while won is None:
                if started < len(candidates):
                    address = candidates[started]
                    running[asyncio.create_task(bounded(address))] = address
                    started += 1
                if not running:
                    break
                more = started < len(candidates)
                done, _ = await asyncio.wait(
                    running,
                    timeout=self.stagger if more else None,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    address = running.pop(task)
                    if task.exception() is not None:
                        failed += 1
                    elif won is None:
                        won = (task.result(), address)
                    else:
                        await discard(task.result())
        finally:
            for task in running:
                task.cancel()
            if running:
                # Shielded and held: a second cancellation of the caller still lets every
                # late connection be closed.
                settling = asyncio.ensure_future(_settle(list(running), discard))
                _SETTLING.add(settling)
                settling.add_done_callback(_SETTLING.discard)
                await asyncio.shield(settling)
        if won is None:
            log.info("relay not reached attempts=%d failed=%d", started, failed)
            raise DialError("no address of the relay answered")
        result, (family, _) = won
        self.family = family
        log.info(
            "relay reached family=%s attempts=%d of=%d",
            family_name(family),
            started,
            len(candidates),
        )
        return result

    async def open_socket(self, host: str, port: int) -> socket.socket:
        """A connected, non-blocking TCP socket to the first address that answers."""

        async def attempt(address: Address) -> socket.socket:
            family, sockaddr = address
            sock = socket.socket(family, socket.SOCK_STREAM)
            try:
                sock.setblocking(False)
                await asyncio.get_running_loop().sock_connect(sock, sockaddr)
            except BaseException:
                sock.close()
                raise
            return sock

        async def discard(sock: socket.socket) -> None:
            sock.close()

        return await self.race(host, port, attempt, discard)


DIALER = Dialer()
"""The process's dialer: one bridge or test assistant is one session."""


# ---------------------------------------------------------------- httpx


class _RacingBackend(httpcore.AnyIOBackend):
    """httpcore's own backend, given one address at a time by the :class:`Dialer`.

    TLS still verifies the relay's name: httpcore starts TLS with the request's host as
    the server name, whatever address the stream was opened to.
    """

    def __init__(self, dialer: Dialer) -> None:
        self._dialer = dialer

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        connect = super().connect_tcp
        options = list(socket_options or [])

        async def attempt(address: Address) -> httpcore.AsyncNetworkStream:
            return await connect(
                str(address[1][0]),
                port,
                timeout=self._dialer.per_address,
                local_address=local_address,
                socket_options=options,
            )

        async def discard(stream: httpcore.AsyncNetworkStream) -> None:
            await stream.aclose()

        try:
            return await self._dialer.race(host, port, attempt, discard)
        except DialError as error:
            raise httpcore.ConnectError("the relay could not be reached") from error


class RacingTransport(httpx.AsyncHTTPTransport):
    """:class:`httpx.AsyncHTTPTransport` whose direct connections go through a Dialer."""

    def __init__(self, dialer: Dialer | None = None) -> None:
        super().__init__()
        # httpx takes no network backend, so the pool it built is replaced with the same
        # one over the racing backend; the request mapping above it stays httpx's own.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(),
            max_connections=100,  # httpx's default limits
            max_keepalive_connections=20,
            keepalive_expiry=5.0,
            network_backend=_RacingBackend(dialer or DIALER),
        )


def http_client(relay_url: str, dialer: Dialer | None = None) -> httpx.AsyncClient:
    """The bridge's HTTP client for ``PARLEY_RELAY_URL``, connecting through the Dialer.

    The racing transport is a mount for every URL, not the client's ``transport``, so
    httpx still reads ``HTTPS_PROXY``, ``HTTP_PROXY`` and ``ALL_PROXY``: their mounts are
    more specific and win, and through a proxy the proxy is dialled as before. A host that
    matches ``NO_PROXY`` while a proxy is set gets httpx's default transport, which
    connects without the racing.
    """
    return httpx.AsyncClient(base_url=relay_url, mounts={"all://": RacingTransport(dialer)})
