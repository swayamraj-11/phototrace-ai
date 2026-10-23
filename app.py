"""
PhotoTrace AI — Digital Photo Forensics & Metadata Analyzer
Main Application Server (Flask)
"""

import os
import uuid
import secrets
from datetime import datetime, timezone
from typing import Dict, Any

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    send_file,
    redirect,
    url_for,
    abort,
    Response,
    make_response,
)
from dotenv import load_dotenv
import io

from backend.validators import (
    create_safe_temp_file,
    cleanup_temp_file,
    ValidationError,
    DEFAULT_MAX_FILE_SIZE,
)
from backend.metadata_extractor import extract_metadata
from backend.integrity_checker import check_integrity
from backend.image_comparator import compare_images
from backend.ela_analyzer import generate_ela
from backend.report_generator import generate_pdf_report, generate_json_report

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Security & Session Configuration
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH", DEFAULT_MAX_FILE_SIZE))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# In-memory storage for active session analyses (cleaned or managed per session)
# Key: analysis_id -> analysis dict
ANALYSIS_STORE: Dict[str, Dict[str, Any]] = {}
# Key: session_id -> list of analysis_ids
SESSION_HISTORY: Dict[str, list] = {}


def _get_session_id() -> str:
    """Ensures each client has a unique secure session identifier."""
    if "uid" not in session:
        session["uid"] = secrets.token_urlsafe(16)
    return session["uid"]


@app.after_request
def apply_security_headers(response: Response):
    """Enforce defense-in-depth HTTP security headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Allow OpenStreetMap tiles, Leaflet CDN, FontAwesome, inline styles/scripts for dashboard
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "img-src 'self' data: blob: https://*.tile.openstreetmap.org https://unpkg.com; "
        "connect-src 'self' https://nominatim.openstreetmap.org; "
        "frame-ancestors 'self';"
    )
    response.headers["Content-Security-Policy"] = csp
    return response


# ==========================================
# Frontend Page Routes
# ==========================================

@app.route("/")
def index():
    """Landing page introducing PhotoTrace AI capabilities."""
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    """Main interactive forensic workspace."""
    return render_template("dashboard.html")


@app.route("/analysis/<analysis_id>")
def view_analysis(analysis_id: str):
    """View saved analysis report."""
    record = ANALYSIS_STORE.get(analysis_id)
    if not record:
        return render_template("dashboard.html", error_message="Analysis report not found or expired."), 404
    return render_template("analysis.html", data=record)


@app.route("/compare")
def compare_page():
    """Origin & Sharing Investigation workspace."""
    return render_template("compare.html")


@app.route("/history")
def history_page():
    """User analysis history page."""
    uid = _get_session_id()
    history_ids = SESSION_HISTORY.get(uid, [])
    records = [ANALYSIS_STORE[aid] for aid in history_ids if aid in ANALYSIS_STORE]
    return render_template("history.html", history=records)


@app.route("/privacy")
def privacy_page():
    """Privacy Policy, Local Processing, and Forensic Limitations documentation."""
    return render_template("privacy.html")


# ==========================================
# REST API Endpoints
# ==========================================

@app.route("/api/health")
def api_health():
    """Health check endpoint."""
    return jsonify({
        "status": "online",
        "service": "PhotoTrace AI",
        "version": "1.0.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Primary image analysis endpoint.
    Safely receives image, validates signatures, runs forensic extraction,
    integrity checks, ELA, and cleans up temporary files.
    """
    if "image" not in request.files:
        return jsonify({"error": "No image file provided in upload request."}), 400

    file = request.files["image"]
    if not file or not file.filename:
        return jsonify({"error": "Empty filename submitted."}), 400

    temp_path = None
    try:
        # Secure validation & temp file generation (UUID-based name)
        temp_path, safe_orig_name, file_size = create_safe_temp_file(file)

        # 1. Forensic Metadata Extraction
        metadata = extract_metadata(temp_path, safe_orig_name, allow_network_geo=True)

        # 2. Rule-based Integrity & Manipulation Checks
        integrity = check_integrity(metadata)
        metadata["integrity"] = integrity

        # 3. Error Level Analysis (ELA)
        ela_data = generate_ela(temp_path)
        metadata["ela"] = ela_data

        # 4. Generate persistent analysis record
        analysis_id = f"PT-{uuid.uuid4().hex[:12].upper()}"
        metadata["report_id"] = analysis_id
        metadata["analysis_id"] = analysis_id

        # Store in session memory
        ANALYSIS_STORE[analysis_id] = metadata
        uid = _get_session_id()
        SESSION_HISTORY.setdefault(uid, []).insert(0, analysis_id)

        # Return full structured analysis
        return jsonify({
            "success": True,
            "analysis_id": analysis_id,
            "data": metadata,
        })

    except ValidationError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": f"Forensic processing failed: {str(e)}"}), 500
    finally:
        # Crucial: Always clean up temporary uploaded evidence from disk
        if temp_path:
            cleanup_temp_file(temp_path)


@app.route("/api/compare", methods=["POST"])
def api_compare():
    """
    Origin & Sharing Investigation endpoint.
    Compares 2 or more uploaded copies of an image.
    """
    files = request.files.getlist("images")
    if not files or len(files) < 2:
        return jsonify({"error": "Please provide at least 2 image files to compare."}), 400

    if len(files) > 6:
        return jsonify({"error": "Maximum 6 images can be compared simultaneously."}), 400

    analyzed_items = []
    temp_paths = []

    try:
        for f in files:
            if not f or not f.filename:
                continue
            temp_path, safe_name, size = create_safe_temp_file(f)
            temp_paths.append(temp_path)
            
            # Extract metadata for comparison
            item_meta = extract_metadata(temp_path, safe_name, allow_network_geo=False)
            analyzed_items.append(item_meta)

        if len(analyzed_items) < 2:
            return jsonify({"error": "Failed to validate at least 2 valid image copies."}), 400

        comparison_results = compare_images(analyzed_items)
        return jsonify({
            "success": True,
            "comparison": comparison_results,
        })

    except ValidationError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": f"Comparison analysis failed: {str(e)}"}), 500
    finally:
        for p in temp_paths:
            cleanup_temp_file(p)


@app.route("/api/export/<analysis_id>/json")
def export_json(analysis_id: str):
    """Download analysis as JSON report."""
    record = ANALYSIS_STORE.get(analysis_id)
    if not record:
        abort(404, description="Analysis record not found.")

    json_str = generate_json_report(record)
    response = make_response(json_str)
    response.headers["Content-Type"] = "application/json"
    response.headers["Content-Disposition"] = f"attachment; filename=PhotoTrace_{analysis_id}.json"
    return response


@app.route("/api/export/<analysis_id>/pdf")
def export_pdf(analysis_id: str):
    """Download analysis as high-fidelity PDF forensic report."""
    record = ANALYSIS_STORE.get(analysis_id)
    if not record:
        abort(404, description="Analysis record not found.")

    try:
        pdf_bytes = generate_pdf_report(record)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"PhotoTrace_{analysis_id}.pdf",
        )
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500


@app.route("/api/history/delete/<analysis_id>", methods=["POST"])
def delete_history_item(analysis_id: str):
    """Safely delete a single record from history."""
    uid = _get_session_id()
    if analysis_id in ANALYSIS_STORE:
        del ANALYSIS_STORE[analysis_id]
    if uid in SESSION_HISTORY and analysis_id in SESSION_HISTORY[uid]:
        SESSION_HISTORY[uid].remove(analysis_id)
    return jsonify({"success": True, "message": "Record removed from history."})


@app.route("/api/history/clear", methods=["POST"])
def clear_history():
    """Safely clear entire history for current session."""
    uid = _get_session_id()
    ids = SESSION_HISTORY.get(uid, [])
    for aid in ids:
        if aid in ANALYSIS_STORE:
            del ANALYSIS_STORE[aid]
    SESSION_HISTORY[uid] = []
    return jsonify({"success": True, "message": "History cleared."})


# ==========================================
# Error Handlers
# ==========================================

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        "error": "The uploaded file exceeds the maximum allowed server limit (32 MB)."
    }), 413


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "API route or resource not found."}), 404
    return render_template("dashboard.html", error_message="Requested page not found."), 404


@app.errorhandler(500)
def internal_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal forensic processing exception."}), 500
    return render_template("dashboard.html", error_message="Internal server error occurred."), 500


if __name__ == "__main__":
    # Render dynamically assigns the PORT env var and requires 0.0.0.0 host binding
    default_host = "0.0.0.0" if (os.getenv("PORT") or os.getenv("RENDER")) else "127.0.0.1"
    host = os.getenv("HOST", default_host)
    port = int(os.getenv("PORT", 5000))
    print(f"\n========================================================")
    print(f"  PhotoTrace AI — Digital Photo Forensics Server")
    print(f"  Listening on: http://{host}:{port}")
    print(f"  Mode: {'Cloud/Render (0.0.0.0)' if host == '0.0.0.0' else 'Local (127.0.0.1)'}")
    print(f"========================================================\n")
    app.run(host=host, port=port, debug=False)
