from __future__ import annotations

import hashlib
import json
import os
import stat
import unicodedata
from pathlib import Path
from typing import Any

from .errors import ConformanceError

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_COLLECTION_ITEMS = 4096
MAX_DEPTH = 32
MAX_SAFE_INTEGER = (1 << 53) - 1


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConformanceError("DUPLICATE_JSON_MEMBER", f"duplicate member {key!r}")
        result[key] = value
    return result


def _reject_float(_: str) -> None:
    raise ConformanceError("NON_CANONICAL_NUMBER", "floating-point values are not permitted")


def load_json_bytes(data: bytes) -> Any:
    if len(data) > MAX_FILE_BYTES:
        raise ConformanceError("DOCUMENT_TOO_LARGE", "document exceeds the local size bound")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConformanceError("INVALID_UTF8", "document is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except ConformanceError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ConformanceError("INVALID_JSON", "document is not valid strict JSON") from exc
    _validate_value(value)
    return value


def load_json(path: Path, *, require_absolute: bool = False) -> Any:
    return load_json_bytes(secure_read(path, require_absolute=require_absolute))


def secure_read(path: Path, *, require_absolute: bool = False) -> bytes:
    if require_absolute and not path.is_absolute():
        raise ConformanceError("PATH_NOT_ABSOLUTE", "authority reference must be absolute")
    if ".." in path.parts:
        raise ConformanceError("PATH_TRAVERSAL", "parent traversal is forbidden")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ConformanceError("REFERENCE_UNAVAILABLE", "local reference is unavailable") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ConformanceError("REFERENCE_NOT_REGULAR", "local reference is not a regular file")
        if info.st_size > MAX_FILE_BYTES:
            raise ConformanceError("DOCUMENT_TOO_LARGE", "local reference exceeds the size bound")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        if len(data) != info.st_size:
            raise ConformanceError("REFERENCE_CHANGED", "local reference changed while open")
        return data
    finally:
        os.close(descriptor)


def _validate_value(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ConformanceError("DOCUMENT_TOO_DEEP", "document nesting exceeds the bound")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ConformanceError("INTEGER_OUT_OF_RANGE", "integer exceeds the canonical safe range")
        return
    if isinstance(value, float):
        raise ConformanceError("NON_CANONICAL_NUMBER", "floating-point values are not permitted")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ConformanceError("NON_NORMALIZED_STRING", "strings must use Unicode NFC")
        if len(value.encode("utf-8")) > MAX_FILE_BYTES:
            raise ConformanceError("STRING_TOO_LARGE", "string exceeds the local size bound")
        return
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ConformanceError("COLLECTION_TOO_LARGE", "array exceeds the item bound")
        for item in value:
            _validate_value(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ConformanceError("COLLECTION_TOO_LARGE", "object exceeds the member bound")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ConformanceError("INVALID_OBJECT_KEY", "object keys must be strings")
            _validate_value(key, depth + 1)
            _validate_value(item, depth + 1)
        return
    raise ConformanceError("UNSUPPORTED_JSON_TYPE", f"unsupported JSON value {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _validate_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: Any, domain: str | None = None) -> str:
    prefix = b"" if domain is None else domain.encode("utf-8") + b"\x00"
    return "sha256:" + hashlib.sha256(prefix + canonical_bytes(value)).hexdigest()


def byte_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def require_canonical_document(data: bytes) -> Any:
    value = load_json_bytes(data)
    if canonical_bytes(value) + b"\n" != data and canonical_bytes(value) != data:
        raise ConformanceError("NON_CANONICAL_JSON", "document bytes are not canonical JSON")
    return value
