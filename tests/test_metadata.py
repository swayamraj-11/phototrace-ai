"""
Unit tests for metadata extraction, GPS parsing, and integrity checks.
"""

from backend.metadata_extractor import extract_metadata
from backend.integrity_checker import check_integrity
from backend.gps_analyzer import _convert_dms_to_decimal, parse_gps_info


def test_metadata_extraction_with_exif_and_gps(image_with_exif_and_gps):
    meta = extract_metadata(image_with_exif_and_gps, "sample_with_exif_gps.jpg", allow_network_geo=False)
    
    # Summary
    assert meta["summary"]["has_exif"] is True
    assert meta["summary"]["dimensions"] == "640 × 480 px"
    assert len(meta["summary"]["sha256"]) == 64

    # Camera & Settings
    assert meta["camera_device"]["make"] == "Nikon Corp"
    assert meta["camera_device"]["model"] == "NIKON D850"
    assert meta["capture_settings"]["iso"] == "200"
    assert meta["capture_settings"]["f_number"] == "f/2.8"
    assert "1/250" in meta["capture_settings"]["exposure_time"]
    assert "50" in meta["capture_settings"]["focal_length"]

    # Timestamps
    assert meta["timestamps"]["capture_timestamp"] == "2024:06:15 10:15:30"

    # GPS
    assert meta["gps"]["has_gps"] is True
    # 37 deg 46 min 29.76 sec ~ 37.774933
    assert abs(meta["gps"]["latitude"] - 37.7749) < 0.01
    # 122 deg 25 min 9.84 sec W ~ -122.4194
    assert abs(meta["gps"]["longitude"] - (-122.4194)) < 0.01

    # Integrity
    integrity = check_integrity(meta)
    assert integrity["findings"]
    # Photoshop tag was embedded
    has_editor_check = any("Photoshop" in f["detected_fact"] for f in integrity["findings"])
    assert has_editor_check


def test_metadata_extraction_stripped_image(image_without_exif):
    meta = extract_metadata(image_without_exif, "sample_stripped.png", allow_network_geo=False)

    assert meta["summary"]["has_exif"] is False
    assert meta["summary"]["completeness_score"] == 0
    # Values must be None, never fabricated!
    assert meta["camera_device"]["make"] is None
    assert meta["camera_device"]["model"] is None
    assert meta["timestamps"]["capture_timestamp"] is None
    assert meta["gps"]["has_gps"] is False
    assert "unavailable" in meta["gps"]["status_message"].lower()

    # Integrity
    integrity = check_integrity(meta)
    exif_finding = next(f for f in integrity["findings"] if f["check"] == "EXIF Metadata Presence")
    assert exif_finding["status"] == "Not Available"


def test_gps_dms_conversion():
    # 34° 3' 8.04" N
    dms_lat = ((34, 1), (3, 1), (804, 100))
    lat = _convert_dms_to_decimal(dms_lat, "N")
    assert round(lat, 4) == 34.0522

    # 118° 14' 37.28" W
    dms_lon = ((118, 1), (14, 1), (3728, 100))
    lon = _convert_dms_to_decimal(dms_lon, "W")
    assert round(lon, 4) == -118.2437


def test_gps_null_handling():
    res = parse_gps_info({})
    assert res["has_gps"] is False
    assert res["latitude"] is None
    assert res["longitude"] is None
    assert "unavailable" in res["status_message"].lower()
