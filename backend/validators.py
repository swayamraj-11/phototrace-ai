"""
Validation and Security Module for PhotoTrace AI.

Enforces:
- File size restrictions
- Magic byte file signature verification
- Protection against path traversal
- Pillow decompression bomb protection
- Safe temporary file creation and lifecycle management
"""

import os
import uuid
import tempfile
from pathlib import Path
from werkzeug.utils import secure_filename
from PIL import Image, ImageFile

# Safeguards against decompression bombs (pixel flood attack)
# Maximum pixels allowed: ~50 MegaPixels (e.g. 7000 x 7000)
Image.MAX_IMAGE_PIXELS = 50_000_000
ImageFile.LOAD_TRUNCATED_IMAGES = False

# Maximum upload size: 32MB default
DEFAULT_MAX_FILE_SIZE = 32 * 1024 * 1024

# Allowed file extensions and corresponding magic bytes (signatures)
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "tiff", "tif", "webp"}

MAGIC_SIGNATURES = {
    "jpeg": [
        b"\xFF\xD8\xFF\xDB",
        b"\xFF\xD8\xFF\xE0",
        b"\xFF\xD8\xFF\xE1",
        b"\xFF\xD8\xFF\xEE",
        b"\xFF\xD8\xFF\xED",
    ],
    "png": [b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"],
    "tiff": [
        b"II*\x00",  # Little-endian
        b"MM\x00*",  # Big-endian
    ],
    "webp": [b"RIFF"],  # Further validated with 'WEBP' at offset 8
}


class ValidationError(Exception):
    """Raised when an uploaded file fails validation."""
    pass


def validate_file_size(file_stream, max_bytes: int = DEFAULT_MAX_FILE_SIZE) -> int:
    """
    Validate that the file stream does not exceed the allowed byte limit.
    Restores the stream position after checking.
    """
    file_stream.seek(0, os.SEEK_END)
    size = file_stream.tell()
    file_stream.seek(0)
    
    if size == 0:
        raise ValidationError("The uploaded file is empty (0 bytes).")
    
    if size > max_bytes:
        raise ValidationError(
            f"File size ({size / (1024 * 1024):.2f} MB) exceeds maximum allowed limit ({max_bytes / (1024 * 1024):.2f} MB)."
        )
    return size


def validate_extension(filename: str) -> str:
    """
    Ensure filename contains an allowed extension and is safe against traversal.
    """
    if not filename or "." not in filename:
        raise ValidationError("File has no extension or invalid filename.")
    
    clean_name = secure_filename(filename)
    if not clean_name:
        raise ValidationError("Invalid filename characters.")
    
    ext = clean_name.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(
            f"File format '.{ext}' is not supported. Supported formats: JPEG, PNG, TIFF, WebP."
        )
    return ext


def validate_magic_bytes(header: bytes) -> str:
    """
    Validate file binary signature against recognized image formats.
    Returns detected format name ('jpeg', 'png', 'tiff', 'webp').
    """
    if len(header) < 12:
        raise ValidationError("File header is too small to be a valid image.")
    
    # Check JPEG
    if header.startswith(b"\xFF\xD8\xFF"):
        return "jpeg"
    
    # Check PNG
    if header.startswith(b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"):
        return "png"
    
    # Check TIFF
    if header.startswith(b"II*\x00") or header.startswith(b"MM\x00*"):
        return "tiff"
    
    # Check WebP (RIFF....WEBP)
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return "webp"
    
    raise ValidationError("File content does not match any authorized image signature (Magic Byte check failed).")


def validate_image_integrity(file_path: str) -> dict:
    """
    Attempts to open and verify the image with Pillow.
    Guards against decompression bombs, truncated/corrupted files, and malformed headers.
    """
    try:
        with Image.open(file_path) as img:
            img.verify()
            width, height = img.size
            format_name = img.format
            mode = img.mode
            
            # Additional bounds check
            if width <= 0 or height <= 0:
                raise ValidationError("Image dimensions are invalid.")
            
            return {
                "width": width,
                "height": height,
                "format": format_name,
                "mode": mode,
            }
    except Image.DecompressionBombError:
        raise ValidationError("Image exceeds maximum pixel bounds (Decompression bomb risk).")
    except Exception as e:
        raise ValidationError(f"Corrupt or unreadable image file: {str(e)}")


def create_safe_temp_file(file_storage, target_dir: str = None) -> tuple[str, str, int]:
    """
    Securely saves an uploaded Werkzeug FileStorage object to a temporary location
    with a random UUID filename. Never executes or puts files in public paths.
    
    Returns:
        (temp_file_path, original_filename_sanitized, file_size)
    """
    original_name = secure_filename(file_storage.filename or "unknown_evidence")
    ext = validate_extension(file_storage.filename)
    
    # Check size
    file_size = validate_file_size(file_storage.stream)
    
    # Read first 32 bytes for signature verification
    header = file_storage.stream.read(32)
    file_storage.stream.seek(0)
    detected_format = validate_magic_bytes(header)
    
    # Map tiff extensions
    if detected_format == "tiff" and ext in ("tif", "tiff"):
        pass
    elif detected_format == "jpeg" and ext in ("jpg", "jpeg"):
        pass
    elif detected_format != ext:
        # Warning/error if extension mismatches true format
        pass  # We allow common interchange, but the true format is verified

    # Generate unique non-predictable filename
    random_id = uuid.uuid4().hex
    safe_filename = f"pt_{random_id}.{ext}"
    
    if target_dir is None:
        target_dir = tempfile.gettempdir()
    
    temp_path = os.path.join(target_dir, safe_filename)
    file_storage.save(temp_path)
    
    # Final Pillow integrity verification on the written file
    try:
        validate_image_integrity(temp_path)
    except Exception:
        # Cleanup immediately if invalid
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise
        
    return temp_path, original_name, file_size


def cleanup_temp_file(file_path: str):
    """Safely remove a temporary file if it exists."""
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError:
            pass
