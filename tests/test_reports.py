"""
Unit tests for PDF and JSON forensic report generators.
"""

import json
from backend.metadata_extractor import extract_metadata
from backend.integrity_checker import check_integrity
from backend.report_generator import generate_json_report, generate_pdf_report


def test_json_report_generation(image_with_exif_and_gps):
    meta = extract_metadata(image_with_exif_and_gps, "test_file.jpg", allow_network_geo=False)
    meta["integrity"] = check_integrity(meta)
    meta["report_id"] = "PT-TEST-001"

    json_str = generate_json_report(meta)
    assert isinstance(json_str, str)
    
    parsed = json.loads(json_str)
    assert parsed["report_metadata"]["report_id"] == "PT-TEST-001"
    assert parsed["report_metadata"]["version"] == "1.0.0"
    assert parsed["analysis_results"]["summary"]["sha256"] == meta["summary"]["sha256"]
    assert parsed["analysis_results"]["camera_device"]["make"] == "Nikon Corp"


def test_pdf_report_generation(image_with_exif_and_gps, image_without_exif):
    # Test 1: Image with full EXIF & GPS
    meta1 = extract_metadata(image_with_exif_and_gps, "full_exif.jpg", allow_network_geo=False)
    meta1["integrity"] = check_integrity(meta1)
    meta1["report_id"] = "PT-FULL-001"

    pdf_bytes1 = generate_pdf_report(meta1)
    assert isinstance(pdf_bytes1, bytes)
    assert len(pdf_bytes1) > 1000
    assert pdf_bytes1.startswith(b"%PDF-")  # Valid PDF signature

    # Test 2: Image with missing EXIF (graceful handling of empty/None fields)
    meta2 = extract_metadata(image_without_exif, "stripped.png", allow_network_geo=False)
    meta2["integrity"] = check_integrity(meta2)
    meta2["report_id"] = "PT-STRIPPED-002"

    pdf_bytes2 = generate_pdf_report(meta2)
    assert isinstance(pdf_bytes2, bytes)
    assert len(pdf_bytes2) > 1000
    assert pdf_bytes2.startswith(b"%PDF-")
