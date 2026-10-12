"""A small QR code encoder for the pairing link (criterion 2), with no dependency.

The bridge shows the pairing code's URL as a QR code in the terminal and writes it as a
PNG. No QR library is a dependency of the workspace and a dependency is a founder
decision, so this module implements the part of ISO/IEC 18004 the bridge needs: byte
mode, error correction level M, versions 1 to 6 (up to 106 bytes of text, which covers
``<origin>/link?code=XXXXXXXX`` with room to spare), the eight masks with the standard
penalty scoring, and a PNG writer over :mod:`zlib`.

:func:`encode` returns the module matrix (``True`` is dark); :func:`render_ascii` draws
it with half-block characters (or ``#`` when the terminal cannot show them) and
:func:`render_png` returns the PNG bytes. Nothing here logs or touches the network.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Sequence
from dataclasses import dataclass

# Error correction level M only: data codewords, EC codewords per block, block count.
_VERSIONS: dict[int, tuple[int, int, int]] = {
    1: (16, 10, 1),
    2: (28, 16, 1),
    3: (44, 26, 1),
    4: (64, 18, 2),
    5: (86, 24, 2),
    6: (108, 16, 4),
}
_ALIGNMENT: dict[int, tuple[int, ...]] = {
    1: (),
    2: (6, 18),
    3: (6, 22),
    4: (6, 26),
    5: (6, 30),
    6: (6, 34),
}
_REMAINDER_BITS = {1: 0, 2: 7, 3: 7, 4: 7, 5: 7, 6: 7}
_FORMAT_LEVEL_M = 0
_FORMAT_MASK = 0x5412
_FORMAT_GENERATOR = 0x537
MAX_VERSION = 6
QUIET_ZONE = 4

Matrix = list[list[bool]]


class QrError(ValueError):
    """The text does not fit a version this module supports."""


@dataclass(frozen=True, slots=True)
class QrCode:
    version: int
    mask: int
    modules: Matrix

    @property
    def size(self) -> int:
        return len(self.modules)


# ---------------------------------------------------------------- GF(256) and Reed-Solomon

_EXP = [0] * 512
_LOG = [0] * 256


def _build_tables() -> None:
    value = 1
    for i in range(255):
        _EXP[i] = value
        _LOG[value] = i
        value <<= 1
        if value & 0x100:
            value ^= 0x11D
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _generator(degree: int) -> list[int]:
    poly = [1]
    for i in range(degree):
        root = _EXP[i]
        poly = [
            (poly[j] if j < len(poly) else 0) ^ _mul(poly[j - 1] if j > 0 else 0, root)
            for j in range(len(poly) + 1)
        ]
    return poly


def _ec_codewords(data: Sequence[int], degree: int) -> list[int]:
    generator = _generator(degree)
    remainder = [0] * degree
    for byte in data:
        factor = byte ^ remainder.pop(0)
        remainder.append(0)
        for j, coefficient in enumerate(generator[1:]):
            remainder[j] ^= _mul(coefficient, factor)
    return remainder


# ---------------------------------------------------------------- data bits


def _version_for(length: int) -> int:
    for version, (data_codewords, _, _) in _VERSIONS.items():
        if length <= data_codewords - 2:
            return version
    raise QrError(f"text longer than {_VERSIONS[MAX_VERSION][0] - 2} bytes is not supported")


def _data_codewords(data: bytes, version: int) -> list[int]:
    capacity, _, _ = _VERSIONS[version]
    bits: list[int] = []

    def put(value: int, width: int) -> None:
        bits.extend((value >> (width - 1 - i)) & 1 for i in range(width))

    put(0b0100, 4)
    put(len(data), 8)
    for byte in data:
        put(byte, 8)
    put(0, min(4, capacity * 8 - len(bits)))
    while len(bits) % 8:
        bits.append(0)
    codewords = [int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = (0xEC, 0x11)
    index = 0
    while len(codewords) < capacity:
        codewords.append(pad[index % 2])
        index += 1
    return codewords


def _interleave(codewords: list[int], version: int) -> list[int]:
    _, ec_per_block, blocks = _VERSIONS[version]
    size = len(codewords) // blocks
    data_blocks = [codewords[i * size : (i + 1) * size] for i in range(blocks)]
    ec_blocks = [_ec_codewords(block, ec_per_block) for block in data_blocks]
    out: list[int] = []
    for i in range(size):
        out.extend(block[i] for block in data_blocks)
    for i in range(ec_per_block):
        out.extend(block[i] for block in ec_blocks)
    return out


# ---------------------------------------------------------------- the matrix


def _function_patterns(version: int) -> tuple[Matrix, Matrix]:
    """The matrix with every function pattern drawn, and which modules are function."""
    size = 17 + 4 * version
    modules = [[False] * size for _ in range(size)]
    function = [[False] * size for _ in range(size)]

    def set_module(row: int, col: int, dark: bool) -> None:
        modules[row][col] = dark
        function[row][col] = True

    for i in range(size):
        set_module(6, i, i % 2 == 0)
        set_module(i, 6, i % 2 == 0)
    for row_centre, col_centre in ((3, 3), (3, size - 4), (size - 4, 3)):
        for dr in range(-4, 5):
            for dc in range(-4, 5):
                row, col = row_centre + dr, col_centre + dc
                if 0 <= row < size and 0 <= col < size:
                    distance = max(abs(dr), abs(dc))
                    set_module(row, col, distance not in (2, 4))
    centres = _ALIGNMENT[version]
    for i, row_centre in enumerate(centres):
        for j, col_centre in enumerate(centres):
            if (i == 0 and j == 0) or (i == 0 and j == len(centres) - 1):
                continue
            if i == len(centres) - 1 and j == 0:
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    set_module(row_centre + dr, col_centre + dc, max(abs(dr), abs(dc)) != 1)
    _draw_format(modules, function, 0, reserve_only=True)
    return modules, function


def _format_bits(mask: int) -> int:
    data = _FORMAT_LEVEL_M << 3 | mask
    remainder = data
    for _ in range(10):
        remainder = (remainder << 1) ^ ((remainder >> 9) * _FORMAT_GENERATOR)
    return ((data << 10) | remainder) ^ _FORMAT_MASK


def _draw_format(modules: Matrix, function: Matrix, mask: int, *, reserve_only: bool) -> None:
    size = len(modules)
    bits = 0 if reserve_only else _format_bits(mask)

    def set_module(row: int, col: int, index: int) -> None:
        modules[row][col] = bool((bits >> index) & 1)
        function[row][col] = True

    for i in range(6):
        set_module(i, 8, i)
    set_module(7, 8, 6)
    set_module(8, 8, 7)
    set_module(8, 7, 8)
    for i in range(9, 15):
        set_module(8, 14 - i, i)
    for i in range(8):
        set_module(8, size - 1 - i, i)
    for i in range(8, 15):
        set_module(size - 15 + i, 8, i)
    modules[size - 8][8] = True
    function[size - 8][8] = True


def _place_data(modules: Matrix, function: Matrix, codewords: Sequence[int], version: int) -> None:
    size = len(modules)
    bits: list[int] = []
    for byte in codewords:
        bits.extend((byte >> (7 - i)) & 1 for i in range(8))
    bits.extend([0] * _REMAINDER_BITS[version])
    index = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if not function[row][c] and index < len(bits):
                    modules[row][c] = bits[index] == 1
                    index += 1
        upward = not upward
        col -= 2


def _mask_bit(mask: int, row: int, col: int) -> bool:
    if mask == 0:
        return (row + col) % 2 == 0
    if mask == 1:
        return row % 2 == 0
    if mask == 2:
        return col % 3 == 0
    if mask == 3:
        return (row + col) % 3 == 0
    if mask == 4:
        return (row // 2 + col // 3) % 2 == 0
    if mask == 5:
        return (row * col) % 2 + (row * col) % 3 == 0
    if mask == 6:
        return ((row * col) % 2 + (row * col) % 3) % 2 == 0
    return ((row + col) % 2 + (row * col) % 3) % 2 == 0


def _apply_mask(modules: Matrix, function: Matrix, mask: int) -> None:
    size = len(modules)
    for row in range(size):
        for col in range(size):
            if not function[row][col] and _mask_bit(mask, row, col):
                modules[row][col] = not modules[row][col]


def _penalty(modules: Matrix) -> int:
    size = len(modules)
    score = 0
    columns = [[modules[r][c] for r in range(size)] for c in range(size)]
    lines = [list(row) for row in modules] + columns
    finder = [True, False, True, True, True, False, True]
    light = [False] * 4
    for line in lines:
        run = 1
        for i in range(1, size):
            if line[i] == line[i - 1]:
                run += 1
                if run == 5:
                    score += 3
                elif run > 5:
                    score += 1
            else:
                run = 1
        for i in range(size - 6):
            if line[i : i + 7] == finder:
                before = line[max(0, i - 4) : i]
                after = line[i + 7 : i + 11]
                if before == light or after == light:
                    score += 40
    for row in range(size - 1):
        for col in range(size - 1):
            value = modules[row][col]
            if (
                value == modules[row][col + 1]
                and value == modules[row + 1][col]
                and value == modules[row + 1][col + 1]
            ):
                score += 3
    dark = sum(sum(1 for cell in row if cell) for row in modules)
    total = size * size
    k = (abs(dark * 20 - total * 10) + total - 1) // total - 1
    return score + k * 10


def encode(text: str | bytes) -> QrCode:
    """The QR code of ``text`` (UTF-8 when a string), level M, best of the eight masks."""
    data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    version = _version_for(len(data))
    codewords = _interleave(_data_codewords(data, version), version)
    modules, function = _function_patterns(version)
    _place_data(modules, function, codewords, version)
    best_mask = 0
    best_score: int | None = None
    for mask in range(8):
        _apply_mask(modules, function, mask)
        _draw_format(modules, function, mask, reserve_only=False)
        score = _penalty(modules)
        if best_score is None or score < best_score:
            best_mask, best_score = mask, score
        _apply_mask(modules, function, mask)
    _apply_mask(modules, function, best_mask)
    _draw_format(modules, function, best_mask, reserve_only=False)
    return QrCode(version, best_mask, modules)


# ---------------------------------------------------------------- rendering


def render_ascii(code: QrCode, *, unicode: bool = True) -> str:
    """The code as text, two module rows per line with half blocks, a quiet zone around.

    With ``unicode=False`` every dark module is ``##`` and every light one two spaces,
    one module row per line, for a terminal that cannot show block characters.
    """
    size = code.size
    width = size + 2 * QUIET_ZONE

    def dark(row: int, col: int) -> bool:
        row -= QUIET_ZONE
        col -= QUIET_ZONE
        return 0 <= row < size and 0 <= col < size and code.modules[row][col]

    lines: list[str] = []
    if not unicode:
        for row in range(width):
            lines.append("".join("##" if dark(row, col) else "  " for col in range(width)))
        return "\n".join(lines)
    blocks = {(False, False): " ", (True, False): "▀", (False, True): "▄"}
    for row in range(0, width, 2):
        line = []
        for col in range(width):
            top = dark(row, col)
            bottom = dark(row + 1, col)
            line.append(blocks.get((top, bottom), "█"))
        lines.append("".join(line))
    return "\n".join(lines)


def render_png(code: QrCode, *, scale: int = 8) -> bytes:
    """The code as an 8-bit greyscale PNG, ``scale`` pixels a module, a quiet zone around."""
    if scale < 1:
        raise ValueError("scale must be at least 1")
    size = code.size + 2 * QUIET_ZONE
    pixels = size * scale
    rows = bytearray()
    for row in range(size):
        line = bytearray([0])
        for col in range(size):
            inside = QUIET_ZONE <= row < size - QUIET_ZONE and QUIET_ZONE <= col < size - QUIET_ZONE
            dark = inside and code.modules[row - QUIET_ZONE][col - QUIET_ZONE]
            line.extend([0 if dark else 255] * scale)
        for _ in range(scale):
            rows.extend(line)
    header = struct.pack(">IIBBBBB", pixels, pixels, 8, 0, 0, 0, 0)
    return b"".join(
        [
            b"\x89PNG\r\n\x1a\n",
            _chunk(b"IHDR", header),
            _chunk(b"IDAT", zlib.compress(bytes(rows), 9)),
            _chunk(b"IEND", b""),
        ]
    )


def _chunk(kind: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(kind + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)
