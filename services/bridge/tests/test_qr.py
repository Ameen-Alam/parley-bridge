"""The QR encoder behind criterion 2: structure checks on the matrix, the format bits
against the standard's known value, and the PNG container. The images were also decoded
with an independent reader (jsQR in a browser) for versions 1, 3 and 6 during the build;
the handoff asks for one scan with a phone."""

from __future__ import annotations

import struct
import zlib

import pytest

from parley_bridge import qr
from parley_bridge.qr import QUIET_ZONE, _format_bits


def finder_at(code: qr.QrCode, row: int, col: int) -> bool:
    expected = [
        "1111111",
        "1000001",
        "1011101",
        "1011101",
        "1011101",
        "1000001",
        "1111111",
    ]
    return all(
        code.modules[row + r][col + c] == (expected[r][c] == "1")
        for r in range(7)
        for c in range(7)
    )


@pytest.mark.parametrize(
    ("text", "version"),
    [("A", 1), ("https://relay.example/link?code=ABCDEFGH", 3), ("x" * 106, 6)],
)
def test_encode_picks_the_smallest_version_and_draws_the_function_patterns(
    text: str, version: int
) -> None:
    code = qr.encode(text)
    assert code.version == version and code.size == 17 + 4 * version
    assert 0 <= code.mask <= 7
    size = code.size
    assert finder_at(code, 0, 0) and finder_at(code, 0, size - 7) and finder_at(code, size - 7, 0)
    assert all(code.modules[6][i] == (i % 2 == 0) for i in range(8, size - 8))  # timing row
    assert all(code.modules[i][6] == (i % 2 == 0) for i in range(8, size - 8))  # timing column
    assert code.modules[size - 8][8] is True  # the dark module


def test_format_bits_match_the_standard_for_level_m() -> None:
    assert _format_bits(0) == 0b101010000010010  # ISO/IEC 18004 table: M, mask 0
    assert _format_bits(7) == 0b100101010100000  # M, mask 7
    assert len({_format_bits(mask) for mask in range(8)}) == 8


def test_text_too_long_for_version_6_is_refused() -> None:
    with pytest.raises(qr.QrError):
        qr.encode("x" * 107)


def test_ascii_rendering_has_a_quiet_zone_and_a_plain_fallback() -> None:
    code = qr.encode("A")
    width = code.size + 2 * QUIET_ZONE
    half = qr.render_ascii(code).split("\n")
    assert len(half) == width // 2 + width % 2
    assert all(len(line) == width for line in half)
    assert half[0].strip() == "" and half[1].strip() == ""  # the quiet zone
    plain = qr.render_ascii(code, unicode=False).split("\n")
    assert len(plain) == width and all(len(line) == 2 * width for line in plain)
    assert plain[QUIET_ZONE][2 * QUIET_ZONE : 2 * QUIET_ZONE + 14] == "##############"


def test_png_is_a_valid_greyscale_image_of_the_matrix() -> None:
    code = qr.encode("A")
    scale = 3
    png = qr.render_png(code, scale=scale)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    length, kind = struct.unpack(">I4s", png[8:16])
    assert kind == b"IHDR" and length == 13
    width, height, depth, colour = struct.unpack(">IIBB", png[16:26])
    pixels = (code.size + 2 * QUIET_ZONE) * scale
    assert width == height == pixels and depth == 8 and colour == 0
    offset = 16 + length + 4
    idat_length, idat = struct.unpack(">I4s", png[offset : offset + 8])
    assert idat == b"IDAT"
    raw = zlib.decompress(png[offset + 8 : offset + 8 + idat_length])
    assert len(raw) == pixels * (pixels + 1)
    row = (QUIET_ZONE + 3) * scale  # the middle of the top-left finder: dark
    line = raw[row * (pixels + 1) + 1 :][:pixels]
    assert line[QUIET_ZONE * scale] == 0 and line[0] == 255
    assert png.endswith(b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF))
