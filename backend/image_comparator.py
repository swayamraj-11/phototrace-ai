"""
Origin & Sharing Investigation Comparator for PhotoTrace AI.

Compares multiple supplied copies of an image to detect:
- Identical vs modified files (via SHA-256)
- Resizing, compression, and dimension variations
- Metadata stripping across platforms
- Earliest recorded timestamps among supplied files
- Strictly preserves investigative ethics and limitations
"""

from typing import List, Dict, Any
from datetime import datetime


def compare_images(analyzed_items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Takes a list of analyzed image metadata dicts (from extract_metadata)
    and produces an Origin & Sharing forensic comparison matrix.
    """
    if not analyzed_items or len(analyzed_items) < 2:
        return {
            "error": "At least two image files are required for comparison.",
            "comparison_matrix": [],
        }

    copies_summary = []
    hashes = {}
    timestamps_found = []

    for idx, item in enumerate(analyzed_items):
        summary = item.get("summary", {})
        ts = item.get("timestamps", {})
        props = item.get("image_properties", {})
        camera = item.get("camera_device", {})
        sw = item.get("software_metadata", {})
        gps = item.get("gps", {})

        sha = summary.get("sha256", "")
        hashes.setdefault(sha, []).append(idx + 1)

        # Track timestamps for earliest supplied copy timeline
        cap_time = ts.get("capture_timestamp")
        mod_time = ts.get("metadata_modified_timestamp")
        
        parsed_dt = None
        for cand in [cap_time, mod_time]:
            if cand:
                try:
                    parsed_dt = datetime.strptime(cand[:19], "%Y:%m:%d %H:%M:%S")
                    break
                except Exception:
                    pass

        copies_summary.append({
            "index": idx + 1,
            "filename": summary.get("original_filename", f"Copy #{idx+1}"),
            "sha256": sha,
            "file_size": summary.get("file_size_formatted"),
            "file_size_bytes": summary.get("file_size_bytes"),
            "dimensions": summary.get("dimensions", "Unknown"),
            "width": props.get("width"),
            "height": props.get("height"),
            "format": props.get("format"),
            "has_exif": summary.get("has_exif", False),
            "capture_timestamp": cap_time,
            "modified_timestamp": mod_time,
            "parsed_dt": parsed_dt,
            "camera_model": f"{camera.get('make') or ''} {camera.get('model') or ''}".strip() or "None",
            "software": sw.get("software") or "None",
            "has_gps": gps.get("has_gps", False),
        })

    # Find identical files (hash collisions / exact matches)
    identical_groups = []
    for sha, copy_indices in hashes.items():
        if len(copy_indices) > 1:
            names = [copies_summary[i - 1]["filename"] for i in copy_indices]
            identical_groups.append({
                "sha256": sha,
                "copies": copy_indices,
                "filenames": names,
                "message": f"Exact binary duplicates ({len(copy_indices)} files match byte-for-byte).",
            })

    # Determine "Earliest supplied copy"
    valid_dt_copies = [c for c in copies_summary if c["parsed_dt"] is not None]
    earliest_copy = None
    if valid_dt_copies:
        valid_dt_copies.sort(key=lambda x: x["parsed_dt"])
        earliest_copy = {
            "index": valid_dt_copies[0]["index"],
            "filename": valid_dt_copies[0]["filename"],
            "timestamp": valid_dt_copies[0]["capture_timestamp"] or valid_dt_copies[0]["modified_timestamp"],
            "label": "Earliest supplied copy (based strictly on recorded EXIF date)",
            "warning": "CRITICAL FORENSIC LIMITATION: This file is labeled 'Earliest supplied copy' among user-provided files only. It cannot be legally claimed to be the absolute original photo without primary evidence from the originating camera or storage card.",
        }

    # Build forensic timeline
    timeline = []
    for c in copies_summary:
        time_str = c["capture_timestamp"] or c["modified_timestamp"] or "No timestamp embedded"
        timeline.append({
            "copy_index": c["index"],
            "filename": c["filename"],
            "recorded_time": time_str,
            "exif_status": "EXIF Intact" if c["has_exif"] else "Metadata Stripped",
            "resolution": c["dimensions"],
            "software": c["software"],
            "note": "Earliest in dataset" if earliest_copy and c["index"] == earliest_copy["index"] else "Subsequent or untimed copy",
        })

    # Dimensional variance analysis
    resolutions = set(c["dimensions"] for c in copies_summary)
    has_resizing = len(resolutions) > 1

    # Metadata stripping analysis
    exif_states = set(c["has_exif"] for c in copies_summary)
    has_stripping = len(exif_states) > 1

    return {
        "copies_count": len(copies_summary),
        "copies": copies_summary,
        "identical_groups": identical_groups,
        "earliest_copy": earliest_copy,
        "timeline": timeline,
        "has_resizing": has_resizing,
        "has_stripping": has_stripping,
        "critical_forensic_disclaimer": (
            "FORENSIC PRINCIPLE: A digital photograph file alone cannot establish who first sent it, "
            "who originally owned it, the transmission medium (e.g. WhatsApp, AirDrop, Signal, Email), "
            "or actual author identity. This analysis is limited to comparing the digital artifacts provided."
        ),
    }
