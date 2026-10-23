"""
Unit tests for multi-image comparator and Origin & Sharing investigation.
"""

from backend.metadata_extractor import extract_metadata
from backend.image_comparator import compare_images


def test_comparison_identical_copies(image_with_exif_and_gps):
    meta1 = extract_metadata(image_with_exif_and_gps, "copy_A.jpg", allow_network_geo=False)
    meta2 = extract_metadata(image_with_exif_and_gps, "copy_B.jpg", allow_network_geo=False)

    comp = compare_images([meta1, meta2])

    assert comp["copies_count"] == 2
    assert len(comp["identical_groups"]) == 1
    assert comp["identical_groups"][0]["copies"] == [1, 2]
    assert comp["has_resizing"] is False
    assert "cannot establish who first sent it" in comp["critical_forensic_disclaimer"]


def test_comparison_differing_copies(image_with_exif_and_gps, image_without_exif):
    meta1 = extract_metadata(image_with_exif_and_gps, "camera_original.jpg", allow_network_geo=False)
    meta2 = extract_metadata(image_without_exif, "whatsapp_export.png", allow_network_geo=False)

    comp = compare_images([meta1, meta2])

    assert comp["copies_count"] == 2
    assert len(comp["identical_groups"]) == 0
    assert comp["has_resizing"] is True  # 640x480 vs 320x240
    assert comp["has_stripping"] is True # One has EXIF, other doesn't

    # Earliest supplied copy check
    assert comp["earliest_copy"] is not None
    assert comp["earliest_copy"]["filename"] == "camera_original.jpg"
    assert "Earliest supplied copy" in comp["earliest_copy"]["label"]
    assert "CRITICAL FORENSIC LIMITATION" in comp["earliest_copy"]["warning"]
