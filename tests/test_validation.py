"""
Unit tests for backend.validators module.
"""

import io
import pytest
from backend.validators import (
    validate_extension,
    validate_magic_bytes,
    validate_file_size,
    validate_image_integrity,
    ValidationError,
)


def test_validate_allowed_extensions():
    assert validate_extension("evidence.jpg") == "jpg"
    assert validate_extension("photo.JPEG") == "jpeg"
    assert validate_extension("sample.png") == "png"
    assert validate_extension("document.tiff") == "tiff"
    assert validate_extension("web_image.webp") == "webp"


def test_validate_disallowed_extension():
    with pytest.raises(ValidationError, match="not supported"):
        validate_extension("malicious.exe")

    with pytest.raises(ValidationError, match="not supported"):
        validate_extension("payload.py")

    with pytest.raises(ValidationError, match="no extension"):
        validate_extension("no_extension_file")


def test_magic_bytes_detection():
    # JPEG
    assert validate_magic_bytes(b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01") == "jpeg"
    # PNG
    assert validate_magic_bytes(b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D") == "png"
    # TIFF little-endian
    assert validate_magic_bytes(b"II*\x00\x08\x00\x00\x00\x00\x00\x00\x00") == "tiff"
    # WebP
    assert validate_magic_bytes(b"RIFF\x24\x00\x00\x00WEBPVP8 \x18\x00") == "webp"


def test_invalid_magic_bytes():
    with pytest.raises(ValidationError, match="does not match any authorized image signature"):
        validate_magic_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00")  # Windows PE binary


def test_file_size_validation():
    # Under limit
    stream = io.BytesIO(b"A" * 1024)
    size = validate_file_size(stream, max_bytes=2048)
    assert size == 1024

    # Empty file
    empty_stream = io.BytesIO(b"")
    with pytest.raises(ValidationError, match="empty"):
        validate_file_size(empty_stream, max_bytes=2048)

    # Exceeding limit
    large_stream = io.BytesIO(b"A" * 5000)
    with pytest.raises(ValidationError, match="exceeds maximum"):
        validate_file_size(large_stream, max_bytes=2048)


def test_image_integrity_corrupt_file(corrupt_image_file):
    with pytest.raises(ValidationError, match="Corrupt or unreadable"):
        validate_image_integrity(corrupt_image_file)
