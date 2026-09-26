"""RGB565 thumbnail decode tests: exact pixels, hostile buffers, hashing."""

import io

import pytest
from PIL import Image

from hyperv_mcp.console import ConsoleError, _decode_rgb565, _frame_hash

W, H = 4, 3


def _encode_buffer(rgb_pixels: list[tuple[int, int, int]], prefix: bytes = b"\x00\x00\x96\x04") -> bytes:
    """RGB pixels -> opaque 4-byte prefix + little-endian RGB565 payload."""
    out = bytearray(prefix)
    for r, g, b in rgb_pixels:
        v = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
        out.append(v & 0xFF)
        out.append((v >> 8) & 0xFF)
    return bytes(out)


def test_decode_roundtrip_exact_pixels():
    source = [(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 255),
              (0, 0, 0), (255, 255, 0), (0, 255, 255), (255, 0, 255),
              (128, 128, 128), (64, 32, 16), (200, 100, 50), (1, 2, 3)]
    raw = _encode_buffer(source)
    png = _decode_rgb565(raw, W, H)
    img = Image.open(io.BytesIO(png))
    assert img.size == (W, H)
    px = img.convert("RGB").load()
    for idx, (r, g, b) in enumerate(source):
        got = px[idx % W, idx // W]
        # RGB565 quantization: 5-bit red/blue (8px steps), 6-bit green (4px)
        assert abs(got[0] - r) <= 8, (idx, got, (r, g, b))
        assert abs(got[1] - g) <= 4, (idx, got, (r, g, b))
        assert abs(got[2] - b) <= 8, (idx, got, (r, g, b))


def test_decode_white_frame():
    raw = _encode_buffer([(255, 255, 255)] * (W * H))
    img = Image.open(io.BytesIO(_decode_rgb565(raw, W, H))).convert("RGB")
    extrema = img.getextrema()
    assert all(lo > 240 for lo, _ in extrema)


def test_prefix_is_skipped():
    raw_a = _encode_buffer([(0, 0, 0)] * (W * H), prefix=b"\x00\x00\x00\x00")
    raw_b = _encode_buffer([(0, 0, 0)] * (W * H), prefix=b"\xDE\xAD\xBE\xEF")
    # The prefix is opaque: only the pixel payload matters for the image.
    assert _decode_rgb565(raw_a, W, H) == _decode_rgb565(raw_b, W, H)


def test_truncated_buffer_rejected():
    raw = _encode_buffer([(0, 0, 0)] * (W * H))
    with pytest.raises(ConsoleError, match="length mismatch"):
        _decode_rgb565(raw[:-6], W, H)


def test_oversized_buffer_rejected():
    raw = _encode_buffer([(0, 0, 0)] * (W * H))
    with pytest.raises(ConsoleError, match="length mismatch"):
        _decode_rgb565(raw + b"\x00\x00", W, H)


def test_tiny_buffer_rejected():
    with pytest.raises(ConsoleError, match="too short"):
        _decode_rgb565(b"\x00\x00", W, H)


def test_empty_buffer_rejected():
    with pytest.raises(ConsoleError, match="too short"):
        _decode_rgb565(b"", W, H)


def test_odd_payload_rejected():
    raw = _encode_buffer([(0, 0, 0)] * (W * H)) + b"\x00"
    assert len(raw) != W * H * 2 + 4
    with pytest.raises(ConsoleError, match="length mismatch"):
        _decode_rgb565(raw, W, H)


def test_frame_hash_stable_and_discriminating():
    raw_a = _encode_buffer([(0, 0, 0)] * (W * H))
    raw_b = _encode_buffer([(255, 255, 255)] * (W * H))
    assert _frame_hash(raw_a) == _frame_hash(raw_a)
    assert _frame_hash(raw_a) != _frame_hash(raw_b)
    # prefix participates in the hash (raw capture identity)
    assert _frame_hash(raw_a) != _frame_hash(raw_a[:4] + b"\x01\x02\x03\x04" + raw_a[4:])
