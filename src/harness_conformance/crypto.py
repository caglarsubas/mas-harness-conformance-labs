from __future__ import annotations

import base64
import hashlib
from typing import Any

from .canonical import canonical_bytes
from .errors import ConformanceError

Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
I = pow(2, (Q - 1) // 4, Q)
IDENTITY = (0, 1)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, Q - 2, Q)
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = x * I % Q
    if x & 1:
        x = Q - x
    return x


BY = 4 * pow(5, Q - 2, Q) % Q
BX = _xrecover(BY)
BASE = (BX, BY)


def _add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    denominator_x = pow(1 + D * x1 * x2 * y1 * y2, Q - 2, Q)
    denominator_y = pow(1 - D * x1 * x2 * y1 * y2, Q - 2, Q)
    return (
        (x1 * y2 + x2 * y1) * denominator_x % Q,
        (y1 * y2 + x1 * x2) * denominator_y % Q,
    )


def _scalar_mult(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode_point(data: bytes) -> tuple[int, int]:
    if len(data) != 32:
        raise ConformanceError("INVALID_ED25519_POINT", "Ed25519 point must be 32 bytes")
    encoded = int.from_bytes(data, "little")
    y = encoded & ((1 << 255) - 1)
    sign = encoded >> 255
    if y >= Q:
        raise ConformanceError("NON_CANONICAL_ED25519_POINT", "Ed25519 y coordinate is non-canonical")
    x = _xrecover(y)
    if (x & 1) != sign:
        x = Q - x
    point = (x, y)
    if _encode_point(point) != data:
        raise ConformanceError("NON_CANONICAL_ED25519_POINT", "Ed25519 point encoding is non-canonical")
    if _scalar_mult(8, point) == IDENTITY:
        raise ConformanceError("SMALL_ORDER_ED25519_POINT", "small-order Ed25519 points are forbidden")
    return point


def _clamped_scalar(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    return int.from_bytes(scalar_bytes, "little"), digest[32:]


def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ConformanceError("INVALID_PRIVATE_KEY", "Ed25519 seed must be 32 bytes")
    scalar, _ = _clamped_scalar(seed)
    return _encode_point(_scalar_mult(scalar, BASE))


def sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _clamped_scalar(seed)
    encoded_public = public_key(seed)
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    encoded_r = _encode_point(_scalar_mult(nonce, BASE))
    challenge = int.from_bytes(hashlib.sha512(encoded_r + encoded_public + message).digest(), "little") % L
    s = (nonce + challenge * scalar) % L
    return encoded_r + int.to_bytes(s, 32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if len(public) != 32 or len(signature) != 64:
            return False
        point_a = _decode_point(public)
        point_r = _decode_point(signature[:32])
        scalar_s = int.from_bytes(signature[32:], "little")
        if scalar_s >= L:
            return False
        challenge = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
        return _scalar_mult(scalar_s, BASE) == _add(point_r, _scalar_mult(challenge, point_a))
    except ConformanceError:
        return False


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value: Any, *, expected_length: int) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise ConformanceError("INVALID_BASE64URL", "value must be unpadded base64url")
    try:
        decoded = base64.b64decode(value + "=" * ((4 - len(value) % 4) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise ConformanceError("INVALID_BASE64URL", "value must be unpadded base64url") from exc
    if len(decoded) != expected_length or b64url_encode(decoded) != value:
        raise ConformanceError("INVALID_BASE64URL", "base64url length or canonical encoding is invalid")
    return decoded


def signature_payload(domain: str, document: dict[str, Any], fields: tuple[str, ...]) -> bytes:
    unsigned = {key: value for key, value in document.items() if key not in fields}
    return domain.encode("utf-8") + b"\x00" + canonical_bytes(unsigned)
