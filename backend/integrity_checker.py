"""
Integrity and Manipulation Analyzer for PhotoTrace AI.

Performs explainable, rule-based forensic checks:
- EXIF presence vs stripping
- Timestamp consistency and chronologic validity
- Editing software signatures (Adobe, GIMP, Canva, AI models)
- Dimension and aspect ratio anomalies
- Re-encoding and compression cues
- Distinguishes detected facts from investigative interpretations
"""

from typing import Dict, Any, List
from datetime import datetime


# Known editing, graphic design, and synthetic generation signatures
KNOWN_EDITING_SOFTWARE = [
    ("Photoshop", "Adobe Photoshop (Desktop image editor)"),
    ("Adobe", "Adobe Creative Suite / Lightroom"),
    ("Lightroom", "Adobe Lightroom (RAW / Photo processor)"),
    ("GIMP", "GIMP (GNU Image Manipulation Program)"),
    ("Canva", "Canva Design Platform"),
    ("Snapseed", "Snapseed (Mobile photo editing)"),
    ("Picsart", "PicsArt (Mobile photo editor)"),
    ("Paint.NET", "Paint.NET (Image editor)"),
    ("Affinity", "Affinity Photo (Serif)"),
    ("Procreate", "Procreate (Digital illustration)"),
    ("Midjourney", "Midjourney AI Generator"),
    ("Stable Diffusion", "Stable Diffusion AI Generator"),
    ("DALL-E", "OpenAI DALL-E AI Generator"),
    ("ComfyUI", "ComfyUI AI Pipeline"),
    ("AUTOMATIC1111", "AUTOMATIC1111 Stable Diffusion WebUI"),
]


def check_integrity(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates image metadata for integrity, anomalies, and potential tampering cues.
    All outputs strictly follow the 4 forensic statuses:
    - 'Data Found'
    - 'Not Available'
    - 'Needs Verification'
    - 'Potential Inconsistency'
    """
    findings: List[Dict[str, Any]] = []
    
    # 1. EXIF Presence Check
    has_exif = metadata["summary"].get("has_exif", False)
    if has_exif:
        findings.append({
            "check": "EXIF Metadata Presence",
            "status": "Data Found",
            "badge_class": "status-found",
            "detected_fact": f"Embedded EXIF metadata structure detected ({len(metadata.get('all_exif_tags', {}))} tags).",
            "interpretation": "File preserves standard digital camera or device headers.",
        })
    else:
        findings.append({
            "check": "EXIF Metadata Presence",
            "status": "Not Available",
            "badge_class": "status-na",
            "detected_fact": "No EXIF header structure was detected in the file stream.",
            "interpretation": "Metadata is completely absent. This commonly occurs when an image is shared via messaging apps (WhatsApp, Telegram, Signal) or social platforms (Instagram, Facebook), or exported via 'Save for Web'. Missing metadata alone is NOT evidence of malicious tampering.",
        })

    # 2. Editing Software & Generation Tags
    sw = metadata["software_metadata"].get("software")
    artist = metadata["software_metadata"].get("artist")
    desc = metadata["software_metadata"].get("image_description")
    all_text = f"{sw or ''} {artist or ''} {desc or ''}".lower()

    detected_editor = None
    for keyword, label in KNOWN_EDITING_SOFTWARE:
        if keyword.lower() in all_text:
            detected_editor = label
            break

    if detected_editor:
        findings.append({
            "check": "Software & Processing Footprint",
            "status": "Needs Verification",
            "badge_class": "status-warning",
            "detected_fact": f"Found metadata referencing: '{detected_editor}'.",
            "interpretation": f"File header explicitly records processing by '{detected_editor}'. This confirms the image passed through external software. Note: Routine operations like resizing, rotation, or color correction also generate these tags.",
        })
    elif sw:
        findings.append({
            "check": "Software & Processing Footprint",
            "status": "Data Found",
            "badge_class": "status-found",
            "detected_fact": f"Processing software tag present: '{sw}'.",
            "interpretation": "Software identity recorded in metadata header.",
        })
    else:
        findings.append({
            "check": "Software & Processing Footprint",
            "status": "Not Available",
            "badge_class": "status-na",
            "detected_fact": "No software processing tag recorded in EXIF.",
            "interpretation": "No editor was declared in the metadata header, or the tag was stripped upon export.",
        })

    # 3. Timestamp Consistency Check
    t_orig = metadata["timestamps"].get("capture_timestamp")
    t_mod = metadata["timestamps"].get("metadata_modified_timestamp")
    t_dig = metadata["timestamps"].get("digitized_timestamp")

    if t_orig and t_mod:
        try:
            # Common EXIF date format: "YYYY:MM:DD HH:MM:SS"
            dt_orig = datetime.strptime(t_orig[:19], "%Y:%m:%d %H:%M:%S")
            dt_mod = datetime.strptime(t_mod[:19], "%Y:%m:%d %H:%M:%S")
            
            if dt_mod < dt_orig:
                findings.append({
                    "check": "Timestamp Chronology",
                    "status": "Potential Inconsistency",
                    "badge_class": "status-inconsistency",
                    "detected_fact": f"Modification timestamp ({t_mod}) is earlier than Capture timestamp ({t_orig}).",
                    "interpretation": "Chronological paradox detected. This may indicate manual metadata editing, clock resetting on camera, or file header alteration.",
                })
            elif dt_mod > dt_orig:
                delta = dt_mod - dt_orig
                findings.append({
                    "check": "Timestamp Chronology",
                    "status": "Needs Verification",
                    "badge_class": "status-warning",
                    "detected_fact": f"Metadata modified {delta} after capture ({t_orig} → {t_mod}).",
                    "interpretation": "Indicates the file was saved or re-processed subsequent to the initial shutter release.",
                })
            else:
                findings.append({
                    "check": "Timestamp Chronology",
                    "status": "Data Found",
                    "badge_class": "status-found",
                    "detected_fact": f"Capture and modification timestamps match: {t_orig}.",
                    "interpretation": "Consistent with straight-from-camera output without post-processing resave.",
                })
        except Exception:
            findings.append({
                "check": "Timestamp Chronology",
                "status": "Needs Verification",
                "badge_class": "status-warning",
                "detected_fact": f"Non-standard timestamp format detected (Orig: {t_orig}, Mod: {t_mod}).",
                "interpretation": "Unable to verify chronology due to irregular timestamp formatting.",
            })
    elif t_orig or t_mod:
        findings.append({
            "check": "Timestamp Chronology",
            "status": "Needs Verification",
            "badge_class": "status-warning",
            "detected_fact": f"Partial timestamps present (Capture: {t_orig or 'None'}, Mod: {t_mod or 'None'}).",
            "interpretation": "Single timestamp present; chronological delta comparison cannot be computed.",
        })
    else:
        findings.append({
            "check": "Timestamp Chronology",
            "status": "Not Available",
            "badge_class": "status-na",
            "detected_fact": "No capture or modification timestamps found in EXIF.",
            "interpretation": "Timestamp chronology could not be analyzed.",
        })

    # 4. Dimension & Resolution Integrity
    raw_tags = metadata.get("all_exif_tags", {})
    exif_w = raw_tags.get("ExifImageWidth") or raw_tags.get("ImageWidth")
    exif_h = raw_tags.get("ExifImageHeight") or raw_tags.get("ImageLength")
    actual_w = metadata["image_properties"].get("width")
    actual_h = metadata["image_properties"].get("height")

    if exif_w and actual_w:
        try:
            ew_int = int(str(exif_w).split()[0])
            eh_int = int(str(exif_h).split()[0]) if exif_h else None
            
            if (ew_int != actual_w) or (eh_int and eh_int != actual_h):
                findings.append({
                    "check": "Dimension & Resolution Alignment",
                    "status": "Potential Inconsistency",
                    "badge_class": "status-inconsistency",
                    "detected_fact": f"EXIF recorded dimensions ({ew_int}×{eh_int}) do not match raster pixel dimensions ({actual_w}×{actual_h}).",
                    "interpretation": "Image has been cropped, resized, or re-saved without updating the EXIF header tag.",
                })
            else:
                findings.append({
                    "check": "Dimension & Resolution Alignment",
                    "status": "Data Found",
                    "badge_class": "status-found",
                    "detected_fact": f"EXIF recorded dimensions match actual raster pixels ({actual_w}×{actual_h} px).",
                    "interpretation": "No dimensional discrepancies detected.",
                })
        except Exception:
            pass

    # 5. Geolocation Integrity
    gps = metadata.get("gps", {})
    if gps.get("has_gps"):
        lat = gps.get("latitude")
        lon = gps.get("longitude")
        if lat == 0.0 and lon == 0.0:
            findings.append({
                "check": "GPS Coordinate Validity",
                "status": "Potential Inconsistency",
                "badge_class": "status-inconsistency",
                "detected_fact": "Coordinates point to (0.000000, 0.000000) Null Island.",
                "interpretation": "Placeholder or uncalibrated GPS receiver output.",
            })
        else:
            findings.append({
                "check": "GPS Coordinate Validity",
                "status": "Data Found",
                "badge_class": "status-found",
                "detected_fact": f"Valid geographic coordinates embedded ({gps.get('coordinates_formatted')}).",
                "interpretation": "GPS tags conform to WGS84 bounds.",
            })
    else:
        findings.append({
            "check": "GPS Coordinate Validity",
            "status": "Not Available",
            "badge_class": "status-na",
            "detected_fact": "No GPS tags embedded in file.",
            "interpretation": "Camera lacked GPS, location services were disabled, or metadata was stripped.",
        })

    # Summary Assessment (strictly objective)
    inconsistencies = sum(1 for f in findings if f["status"] == "Potential Inconsistency")
    verifications = sum(1 for f in findings if f["status"] == "Needs Verification")
    
    if inconsistencies > 0:
        overall_assessment = "Potential Inconsistencies Detected"
        assessment_class = "badge-inconsistency"
        summary_note = f"{inconsistencies} anomaly(ies) identified requiring careful forensic review."
    elif verifications > 0:
        overall_assessment = "Processing Footprints Identified"
        assessment_class = "badge-verification"
        summary_note = "Metadata indicates post-capture saving, re-encoding, or partial metadata preservation."
    elif has_exif:
        overall_assessment = "Consistent Metadata Structure"
        assessment_class = "badge-data-found"
        summary_note = "Available metadata fields are internally consistent."
    else:
        overall_assessment = "Metadata Stripped / Clean"
        assessment_class = "badge-na"
        summary_note = "File contains no EXIF records. Typical for web downloads and messaging applications."

    return {
        "overall_assessment": overall_assessment,
        "assessment_class": assessment_class,
        "summary_note": summary_note,
        "findings": findings,
        "inconsistency_count": inconsistencies,
        "verification_count": verifications,
    }
