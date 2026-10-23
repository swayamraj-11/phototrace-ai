# PhotoTrace AI — Digital Photo Forensics & Metadata Analyzer

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask 3.0+](https://img.shields.io/badge/framework-Flask%203.0%2B-green.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/tests-20%20passed-brightgreen.svg)]()
[![Forensics](https://img.shields.io/badge/forensics-tamper%20detection-cyan.svg)]()

**PhotoTrace AI** (CyberLens Engine) is a professional, high-performance web platform designed for cybersecurity researchers, digital investigators, and forensic analysts. It enables rigorous inspection of image metadata, cryptographic hashing, geolocation decoding, multi-copy origin comparison, and compression artifact visualization.

---

## ⚡ Core Features

1. **Exhaustive EXIF Metadata Extraction**
   - Extracts camera manufacturer, model, lens, aperture, shutter speed, ISO, focal length, flash state, and orientation.
   - Non-destructive processing: never modifies or overwrites uploaded evidence.
   - Strictly reports `"Not available in this file"` when metadata is missing—never fabricates data.

2. **Forensic Geolocation & Interactive Map**
   - Decodes GPS DMS (Degrees, Minutes, Seconds) and hemisphere references to decimal coordinates.
   - Validates coordinate bounds against WGS84 standards.
   - Embeds interactive Leaflet map using OpenStreetMap tiles.
   - Includes rate-limited, approximate reverse geocoding via OpenStreetMap Nominatim.

3. **Origin & Sharing Comparative Investigation**
   - Cross-analyzes 2 to 6 user-provided copies of an image.
   - Identifies byte-for-byte duplicate files using SHA-256 cryptographic hashes.
   - Detects downscaling, cropping, and social media metadata stripping across platforms.
   - Builds an evidence timeline identifying the **"Earliest supplied copy"** (strictly distinguished from certified original capture).

4. **Explainable Integrity & Tamper Checks**
   - Rules-based classification: `Data Found`, `Not Available`, `Needs Verification`, `Potential Inconsistency`.
   - Detects footprints of editing tools (Adobe Photoshop, Lightroom, GIMP, Canva, Snapseed, AI models).
   - Flags chronological paradoxes (e.g., modification date preceding capture date).
   - Detects resolution discrepancies between raster pixels and EXIF header declarations.

5. **Experimental Error Level Analysis (ELA)**
   - Resaves images at 92% quality and computes pixel error variance to identify potential localized re-encoding or composite additions.

6. **Forensic PDF & JSON Reports**
   - Generates audit-ready PDF reports via ReportLab with cryptographic SHA-256 seals, structured metadata tables, and legal disclaimers.
   - Full JSON export for SIEM / forensic pipeline ingestion.

7. **Hardened Security Architecture**
   - Real binary file signature (magic byte) verification (rejects renamed scripts/executables).
   - Pillow decompression bomb protection (`MAX_IMAGE_PIXELS` capped at 50 MP).
   - Ephemeral file lifecycle: uploaded temporary files are automatically deleted after processing.
   - Defense-in-depth HTTP security headers (`nosniff`, `SAMEORIGIN`, CSP).

---

## 🗂️ Project Structure

```
PhotoTrace-AI/
├── app.py                      # Flask main server & API endpoints
├── requirements.txt            # Python dependencies
├── .env.example                # Sample environment configuration
├── README.md                   # Complete documentation
├── generate_sample_evidence.py # Utility to generate test forensic images
├── backend/
│   ├── __init__.py
│   ├── validators.py           # Magic bytes, size limits, decompression bomb guards
│   ├── metadata_extractor.py   # EXIF tag decoding, SHA-256 hashing, categorization
│   ├── gps_analyzer.py         # DMS-to-decimal conversion, range checks, OSM map
│   ├── integrity_checker.py    # Rule-based tamper & timestamp anomaly checks
│   ├── image_comparator.py     # Multi-image comparator & timeline builder
│   ├── ela_analyzer.py         # Error Level Analysis visualization generator
│   └── report_generator.py     # PDF (ReportLab) & JSON export engine
├── templates/
│   ├── base.html               # Cyberpunk dark layout with ambient glows
│   ├── index.html              # Landing page & feature showcase
│   ├── dashboard.html          # Drag-and-drop workspace with laser scanner
│   ├── analysis.html           # Full forensic telemetry report with tabs
│   ├── compare.html            # Origin & Sharing Investigation workspace
│   ├── history.html            # Session analysis history & management
│   └── privacy.html            # Privacy policy & forensic limitations
├── static/
│   ├── css/
│   │   └── style.css           # Custom cybersecurity dark theme styles
│   └── js/
│       ├── app.js              # Upload, tabs, copy-to-clipboard, toasts
│       ├── map.js              # Leaflet.js GPS map integration
│       └── compare.js          # Multi-image comparative matrix handler
├── tests/
│   ├── conftest.py             # Programmatic test fixtures (EXIF, GPS, corrupt)
│   ├── test_validation.py      # Magic byte and file size validation tests
│   ├── test_hashing.py         # SHA-256 cryptographic tests
│   ├── test_metadata.py        # EXIF, GPS, and completeness score tests
│   ├── test_comparator.py      # Multi-image duplicate & timeline tests
│   ├── test_reports.py         # PDF and JSON export tests
│   └── test_routes.py          # Flask endpoint integration tests
└── sample_evidence/            # Generated sample forensic images for testing
```

---

## 🚀 Windows 10/11 Setup Guide

Follow these exact PowerShell steps to run PhotoTrace AI on your machine:

### 1. Check Python Installation
Open PowerShell in the `PhotoTrace-AI` folder and verify Python 3.10+:
```powershell
python --version
```

### 2. Create a Virtual Environment
```powershell
python -m venv .venv
```

### 3. Activate the Virtual Environment
```powershell
.venv\Scripts\Activate.ps1
```

> **Note for PowerShell execution policy:**  
> If PowerShell displays an error stating that script execution is disabled on this system, you can safely activate the environment for your current PowerShell window without altering system-wide security:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .venv\Scripts\Activate.ps1
> ```
> *Alternative:* Run all commands directly using the environment's Python binary:
> ```powershell
> .venv\Scripts\python.exe -m pip install -r requirements.txt
> .venv\Scripts\python.exe app.py
> ```

### 4. Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### 5. Generate Sample Evidence Images (Optional)
Generate 3 realistic sample images (camera original with GPS, social media stripped copy, and Photoshop edited copy):
```powershell
python generate_sample_evidence.py
```

### 6. Run Automated Test Suite
Verify that all 20 unit and integration tests pass:
```powershell
python -m pytest -v
```

### 7. Launch the Application Server
```powershell
python app.py
```

### 8. Open the Web Application
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🛡️ Critical Forensic Limitations & Ethical Doctrine

1. **A photo file alone cannot prove author identity:** Digital photographs lack cryptographic signatures proving who originally held the camera or sent the message over network applications (e.g. WhatsApp, AirDrop, Signal, Email) without primary device access and corroborated network logs.
2. **Missing metadata is not proof of tampering:** Most modern messaging and social platforms automatically strip EXIF metadata to protect user privacy. Stripped metadata is normal for internet-circulated files.
3. **Software tags indicate saving, not necessarily malicious manipulation:** An Adobe Photoshop or GIMP tag indicates the image was saved using that software, which may reflect basic rotation, resizing, or format conversion.
4. **"Earliest supplied copy" vs Original:** When comparing multiple files, the file with the oldest recorded EXIF date is labeled *"Earliest supplied copy"* within the provided dataset. It is never declared the certified original capture without primary storage verification.

---

## 🧪 Testing Verification Summary

The automated test suite verifies 20 distinct forensic capabilities:
- `test_validation.py`: Extension checking, binary magic bytes (JPEG, PNG, TIFF, WebP), file size bounds, corruption detection.
- `test_hashing.py`: Cryptographic SHA-256 verification and collision differentiation.
- `test_metadata.py`: Deep EXIF parsing, DMS-to-decimal GPS conversion, completeness scoring, and non-invention verification.
- `test_comparator.py`: Multi-copy hash collision detection, resolution variance, timeline construction.
- `test_reports.py`: PDF binary structure (`%PDF-`), report styling, and JSON schema conformity.
- `test_routes.py`: Flask HTTP routes (`/`, `/dashboard`, `/compare`, `/history`, `/privacy`, `/api/analyze`, `/api/compare`, `/api/export/...`).

---

## ☁️ Deployment Guide for Render

### Step 1: Push your code to GitHub
```powershell
git add .
git commit -m "Prepare PhotoTrace AI for Render deployment"
git branch -M main
git remote add origin https://github.com/<YOUR_USERNAME>/<YOUR_REPOSITORY>.git
git push -u origin main
```

### Step 2: Deploy on Render
1. Log in to [Render.com](https://render.com).
2. Click **New +** > **Web Service**.
3. Connect your GitHub repository (`phototrace-ai`).
4. Configure the Web Service settings:
   - **Name:** `phototrace-ai`
   - **Environment:** `Python 3`
   - **Region:** Any close to your users (e.g., Oregon, Frankfurt, Singapore)
   - **Branch:** `main`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn --bind 0.0.0.0:$PORT --workers 2 --timeout 120 app:app`
5. Under **Environment Variables**, add:
   - `PYTHON_VERSION`: `3.12.0`
   - `FLASK_ENV`: `production`
   - `SECRET_KEY`: *(Click "Generate" or provide a random 64-char hex)*
   - `ALLOW_REVERSE_GEOCODING`: `true`
6. Click **Create Web Service**.
7. Once deployment succeeds, Render gives you a live HTTPS URL (e.g. `https://phototrace-ai.onrender.com`).

