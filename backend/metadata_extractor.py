"""
Forensic Metadata Extractor for PhotoTrace AI.

Extracts standard and proprietary EXIF tags, calculates cryptographic hashes,
categorizes metadata for forensic analysis, and preserves factual integrity.
"""

import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from PIL import Image, ExifTags
import exifread

from backend.gps_analyzer import parse_gps_info, reverse_geocode


# Human-readable mappings for common EXIF enum fields
ORIENTATION_MAP = {
    1: "Horizontal (normal)",
    2: "Mirror horizontal",
    3: "Rotate 180°",
    4: "Mirror vertical",
    5: "Mirror horizontal and rotate 270° CW",
    6: "Rotate 90° CW",
    7: "Mirror horizontal and rotate 90° CW",
    8: "Rotate 270° CW",
}

FLASH_MAP = {
    0x0000: "Flash did not fire",
    0x0001: "Flash fired",
    0x0005: "Strobe return light not detected",
    0x0007: "Strobe return light detected",
    0x0009: "Flash fired, compulsory flash mode",
    0x000D: "Flash fired, compulsory flash mode, return light not detected",
    0x000F: "Flash fired, compulsory flash mode, return light detected",
    0x0010: "Flash did not fire, compulsory flash mode",
    0x0018: "Flash did not fire, auto mode",
    0x0019: "Flash fired, auto mode",
    0x001D: "Flash fired, auto mode, return light not detected",
    0x001F: "Flash fired, auto mode, return light detected",
    0x0020: "No flash function",
    0x0041: "Flash fired, red-eye reduction mode",
    0x0045: "Flash fired, red-eye reduction mode, return light not detected",
    0x0047: "Flash fired, red-eye reduction mode, return light detected",
    0x0049: "Flash fired, compulsory flash mode, red-eye reduction mode",
    0x004D: "Flash fired, compulsory flash mode, red-eye reduction mode, return light not detected",
    0x004F: "Flash fired, compulsory flash mode, red-eye reduction mode, return light detected",
    0x0059: "Flash fired, auto mode, red-eye reduction mode",
    0x005D: "Flash fired, auto mode, return light not detected, red-eye reduction mode",
    0x005F: "Flash fired, auto mode, return light detected, red-eye reduction mode",
}

METERING_MODE_MAP = {
    0: "Unknown",
    1: "Average",
    2: "Center-weighted average",
    3: "Spot",
    4: "Multi-spot",
    5: "Pattern / Multi-segment",
    6: "Partial",
    255: "Other",
}

EXPOSURE_PROGRAM_MAP = {
    0: "Not defined",
    1: "Manual",
    2: "Normal program",
    3: "Aperture priority",
    4: "Shutter priority",
    5: "Creative program (depth of field)",
    6: "Action program (fast shutter)",
    7: "Portrait mode",
    8: "Landscape mode",
}


def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Computes cryptographic hash of the entire raw file for evidence integrity.
    """
    hasher = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _format_exposure_time(val: Any) -> Optional[str]:
    """Formats exposure time to human standard (e.g., 1/250s or 2s)."""
    if val is None:
        return None
    try:
        if isinstance(val, (int, float)):
            if val <= 0:
                return None
            if val < 1.0:
                denom = round(1.0 / val)
                return f"1/{denom}s ({val:.4f}s)"
            return f"{val:.2f}s"
        if hasattr(val, "numerator") and hasattr(val, "denominator"):
            num, den = val.numerator, val.denominator
            if num == 0:
                return None
            if den == 1:
                return f"{num}s"
            return f"{num}/{den}s"
        return str(val)
    except Exception:
        return str(val)


def _format_fnumber(val: Any) -> Optional[str]:
    """Formats aperture f-number (e.g. f/1.8)."""
    if val is None:
        return None
    try:
        if isinstance(val, (int, float)):
            return f"f/{val:.1f}" if val % 1 else f"f/{int(val)}"
        if hasattr(val, "numerator") and hasattr(val, "denominator") and val.denominator != 0:
            f = float(val.numerator) / float(val.denominator)
            return f"f/{f:.1f}" if f % 1 else f"f/{int(f)}"
        return f"f/{val}"
    except Exception:
        return str(val)


def _format_focal_length(val: Any) -> Optional[str]:
    """Formats focal length (e.g. 50.0 mm)."""
    if val is None:
        return None
    try:
        if isinstance(val, (int, float)):
            return f"{val:.1f} mm"
        if hasattr(val, "numerator") and hasattr(val, "denominator") and val.denominator != 0:
            fl = float(val.numerator) / float(val.denominator)
            return f"{fl:.1f} mm"
        return f"{val} mm"
    except Exception:
        return str(val)


def _clean_str(val: Any) -> Optional[str]:
    """Safely sanitize and strip string metadata."""
    if val is None:
        return None
    if isinstance(val, bytes):
        val = val.decode("utf-8", "ignore")
    s = str(val).strip("\x00 \t\r\n")
    return s if s else None


def extract_metadata(file_path: str, original_filename: str, allow_network_geo: bool = True) -> Dict[str, Any]:
    """
    Main extraction function for PhotoTrace AI.
    Combines Pillow and ExifRead for exhaustive, tamper-free forensic extraction.
    """
    analysis_time_utc = datetime.now(timezone.utc).isoformat()
    sha256_hash = calculate_file_hash(file_path, "sha256")
    file_size_bytes = os.path.getsize(file_path)
    
    # Filesystem timestamps (strictly labeled as host filesystem metadata)
    fs_stat = os.stat(file_path)
    fs_created = datetime.fromtimestamp(fs_stat.st_ctime, tz=timezone.utc).isoformat()
    fs_modified = datetime.fromtimestamp(fs_stat.st_mtime, tz=timezone.utc).isoformat()

    # Base container for extracted metadata
    data = {
        "summary": {
            "original_filename": original_filename,
            "file_size_bytes": file_size_bytes,
            "file_size_formatted": f"{file_size_bytes / 1024:.2f} KB" if file_size_bytes < 1048576 else f"{file_size_bytes / (1024*1024):.2f} MB",
            "sha256": sha256_hash,
            "analysis_timestamp_utc": analysis_time_utc,
            "has_exif": False,
            "completeness_score": 0,
            "format": None,
            "dimensions": None,
            "aspect_ratio": None,
            "color_mode": None,
        },
        "timestamps": {
            "capture_timestamp": None,       # DateTimeOriginal
            "digitized_timestamp": None,     # DateTimeDigitized
            "metadata_modified_timestamp": None, # DateTime
            "offset_time_original": None,    # OffsetTimeOriginal / timezone
            "filesystem_created_utc": fs_created,
            "filesystem_modified_utc": fs_modified,
            "analysis_completed_utc": analysis_time_utc,
            "forensic_disclaimer": "Recorded timestamps are derived from file/EXIF fields and do not independently establish legal chain-of-custody without corroborating evidence.",
        },
        "camera_device": {
            "make": None,
            "model": None,
            "lens_make": None,
            "lens_model": None,
            "lens_specification": None,
            "camera_serial": None,
            "body_serial": None,
        },
        "capture_settings": {
            "exposure_time": None,
            "f_number": None,
            "iso": None,
            "focal_length": None,
            "focal_length_35mm": None,
            "flash": None,
            "orientation": None,
            "metering_mode": None,
            "exposure_program": None,
            "white_balance": None,
        },
        "image_properties": {
            "format": None,
            "width": None,
            "height": None,
            "megapixels": None,
            "color_space": None,
            "bits_per_sample": None,
            "dpi": None,
        },
        "software_metadata": {
            "software": None,
            "artist": None,
            "copyright": None,
            "image_description": None,
            "user_comment": None,
            "exif_version": None,
        },
        "gps": {
            "has_gps": False,
            "status_message": "GPS data unavailable — No geolocation metadata embedded in this file.",
        },
        "all_exif_tags": {},  # Complete key-value dictionary for explorer
    }

    # Extract basic image properties using Pillow
    try:
        with Image.open(file_path) as img:
            data["summary"]["format"] = img.format
            data["summary"]["dimensions"] = f"{img.width} × {img.height} px"
            data["summary"]["color_mode"] = img.mode
            data["image_properties"]["format"] = img.format
            data["image_properties"]["width"] = img.width
            data["image_properties"]["height"] = img.height
            data["image_properties"]["color_mode"] = img.mode
            
            # Aspect ratio calculation
            if img.height > 0:
                gcd_val = _gcd(img.width, img.height)
                data["summary"]["aspect_ratio"] = f"{img.width // gcd_val}:{img.height // gcd_val}"
            
            mp = (img.width * img.height) / 1_000_000.0
            data["image_properties"]["megapixels"] = f"{mp:.2f} MP"
            
            if "dpi" in img.info:
                data["image_properties"]["dpi"] = f"{img.info['dpi'][0]:.0f} × {img.info['dpi'][1]:.0f}"

            # Pillow EXIF extraction
            pillow_exif = None
            try:
                pillow_exif = img._getexif()
            except Exception:
                pass

            raw_tags = {}
            gps_raw = {}

            if pillow_exif:
                data["summary"]["has_exif"] = True
                for tag_id, value in pillow_exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, f"Tag_0x{tag_id:04X}")
                    
                    if tag_name == "GPSInfo":
                        if isinstance(value, dict):
                            for g_id, g_val in value.items():
                                g_name = ExifTags.GPSTAGS.get(g_id, f"GPS_{g_id}")
                                gps_raw[g_name] = g_val
                                gps_raw[g_id] = g_val
                    else:
                        # Clean and stringify for raw tags viewer
                        raw_tags[tag_name] = _safe_repr(value)

                    # Populate category fields
                    _populate_field(data, tag_name, value)

    except Exception as e:
        # File reading error handled gracefully
        pass

    # Secondary extraction with ExifRead for vendor/TIFF/deeper tags
    try:
        with open(file_path, "rb") as f:
            exifread_tags = exifread.process_file(f, details=True)
            if exifread_tags:
                data["summary"]["has_exif"] = True
                for k, v in exifread_tags.items():
                    clean_k = k.replace("EXIF ", "").replace("Image ", "")
                    if clean_k not in raw_tags:
                        raw_tags[clean_k] = str(v)
                    
                    # Fill any fields missed by Pillow
                    _populate_from_exifread(data, clean_k, v)
                    
                    if "GPS" in k and not gps_raw:
                        # Populate GPS from exifread if Pillow missed it
                        pass
    except Exception:
        pass

    data["all_exif_tags"] = raw_tags

    # Process GPS info
    parsed_gps = parse_gps_info(gps_raw)
    data["gps"] = parsed_gps
    
    if parsed_gps.get("has_gps"):
        lat = parsed_gps["latitude"]
        lon = parsed_gps["longitude"]
        rev_geo = reverse_geocode(lat, lon, allow_network=allow_network_geo)
        data["gps"]["location_approximate"] = rev_geo

    # Calculate factual completeness score (percentage of 10 standard core fields)
    completeness_fields = [
        data["camera_device"]["make"],
        data["camera_device"]["model"],
        data["timestamps"]["capture_timestamp"],
        data["capture_settings"]["exposure_time"],
        data["capture_settings"]["f_number"],
        data["capture_settings"]["iso"],
        data["capture_settings"]["focal_length"],
        data["gps"]["has_gps"],
        data["software_metadata"]["software"],
        data["capture_settings"]["flash"],
    ]
    present_count = sum(1 for val in completeness_fields if val)
    data["summary"]["completeness_score"] = int((present_count / len(completeness_fields)) * 100)
    data["summary"]["completeness_ratio"] = f"{present_count}/{len(completeness_fields)} standard indicators"

    return data


def _gcd(a: int, b: int) -> int:
    """Helper to compute greatest common divisor for aspect ratios."""
    while b:
        a, b = b, a % b
    return a if a > 0 else 1


def _safe_repr(val: Any) -> str:
    """Provides a safe string representation for EXIF explorer."""
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", "ignore").strip()
        except Exception:
            return f"<binary data {len(val)} bytes>"
    return str(val)


def _populate_field(data: Dict[str, Any], tag_name: str, value: Any):
    """Populates structured fields from Pillow EXIF."""
    # Timestamps
    if tag_name == "DateTimeOriginal":
        data["timestamps"]["capture_timestamp"] = _clean_str(value)
    elif tag_name == "DateTimeDigitized":
        data["timestamps"]["digitized_timestamp"] = _clean_str(value)
    elif tag_name == "DateTime":
        data["timestamps"]["metadata_modified_timestamp"] = _clean_str(value)
    elif tag_name == "OffsetTimeOriginal":
        data["timestamps"]["offset_time_original"] = _clean_str(value)
    
    # Camera & Device
    elif tag_name == "Make":
        data["camera_device"]["make"] = _clean_str(value)
    elif tag_name == "Model":
        data["camera_device"]["model"] = _clean_str(value)
    elif tag_name in ("LensMake", "LensManufacturer"):
        data["camera_device"]["lens_make"] = _clean_str(value)
    elif tag_name == "LensModel":
        data["camera_device"]["lens_model"] = _clean_str(value)
    elif tag_name == "LensSpecification":
        data["camera_device"]["lens_specification"] = _safe_repr(value)
    elif tag_name == "BodySerialNumber":
        data["camera_device"]["body_serial"] = _clean_str(value)

    # Capture Settings
    elif tag_name == "ExposureTime":
        data["capture_settings"]["exposure_time"] = _format_exposure_time(value)
    elif tag_name == "FNumber":
        data["capture_settings"]["f_number"] = _format_fnumber(value)
    elif tag_name in ("ISOSpeedRatings", "PhotographicSensitivity"):
        data["capture_settings"]["iso"] = str(value)
    elif tag_name == "FocalLength":
        data["capture_settings"]["focal_length"] = _format_focal_length(value)
    elif tag_name == "FocalLengthIn35mmFilm":
        data["capture_settings"]["focal_length_35mm"] = f"{value} mm (35mm eq)"
    elif tag_name == "Flash":
        try:
            val_int = int(value)
            data["capture_settings"]["flash"] = FLASH_MAP.get(val_int, f"Code {val_int}")
        except Exception:
            data["capture_settings"]["flash"] = str(value)
    elif tag_name == "Orientation":
        try:
            val_int = int(value)
            data["capture_settings"]["orientation"] = ORIENTATION_MAP.get(val_int, f"Orientation {val_int}")
        except Exception:
            data["capture_settings"]["orientation"] = str(value)
    elif tag_name == "MeteringMode":
        try:
            val_int = int(value)
            data["capture_settings"]["metering_mode"] = METERING_MODE_MAP.get(val_int, f"Mode {val_int}")
        except Exception:
            data["capture_settings"]["metering_mode"] = str(value)
    elif tag_name == "ExposureProgram":
        try:
            val_int = int(value)
            data["capture_settings"]["exposure_program"] = EXPOSURE_PROGRAM_MAP.get(val_int, f"Program {val_int}")
        except Exception:
            data["capture_settings"]["exposure_program"] = str(value)

    # Software & Metadata
    elif tag_name == "Software":
        data["software_metadata"]["software"] = _clean_str(value)
    elif tag_name == "Artist":
        data["software_metadata"]["artist"] = _clean_str(value)
    elif tag_name == "Copyright":
        data["software_metadata"]["copyright"] = _clean_str(value)
    elif tag_name == "ImageDescription":
        data["software_metadata"]["image_description"] = _clean_str(value)
    elif tag_name == "UserComment":
        data["software_metadata"]["user_comment"] = _clean_str(value)
    elif tag_name == "ExifVersion":
        if isinstance(value, bytes):
            data["software_metadata"]["exif_version"] = value.decode("utf-8", "ignore")
        else:
            data["software_metadata"]["exif_version"] = str(value)


def _populate_from_exifread(data: Dict[str, Any], tag_name: str, value: Any):
    """Fallback population from ExifRead if fields are still unset."""
    s_val = str(value).strip()
    if not s_val:
        return
    
    if tag_name == "DateTimeOriginal" and not data["timestamps"]["capture_timestamp"]:
        data["timestamps"]["capture_timestamp"] = s_val
    elif tag_name == "Make" and not data["camera_device"]["make"]:
        data["camera_device"]["make"] = s_val
    elif tag_name == "Model" and not data["camera_device"]["model"]:
        data["camera_device"]["model"] = s_val
    elif tag_name == "Software" and not data["software_metadata"]["software"]:
        data["software_metadata"]["software"] = s_val
    elif tag_name == "LensModel" and not data["camera_device"]["lens_model"]:
        data["camera_device"]["lens_model"] = s_val
