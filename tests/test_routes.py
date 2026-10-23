"""
Integration tests for Flask application routes and API endpoints.
"""

import io
import pytest
from app import app, ANALYSIS_STORE


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_public_pages(client):
    assert client.get("/").status_code == 200
    assert client.get("/dashboard").status_code == 200
    assert client.get("/compare").status_code == 200
    assert client.get("/history").status_code == 200
    assert client.get("/privacy").status_code == 200
    assert client.get("/api/health").status_code == 200


def test_api_analyze_valid_file(client, image_with_exif_and_gps):
    with open(image_with_exif_and_gps, "rb") as f:
        file_bytes = f.read()

    data = {
        "image": (io.BytesIO(file_bytes), "sample_test.jpg")
    }
    response = client.post("/api/analyze", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert "analysis_id" in json_data
    assert json_data["data"]["summary"]["has_exif"] is True

    analysis_id = json_data["analysis_id"]

    # Test PDF export route
    pdf_resp = client.get(f"/api/export/{analysis_id}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.mimetype == "application/pdf"

    # Test JSON export route
    json_resp = client.get(f"/api/export/{analysis_id}/json")
    assert json_resp.status_code == 200
    assert json_resp.mimetype == "application/json"

    # Test View Analysis page
    view_resp = client.get(f"/analysis/{analysis_id}")
    assert view_resp.status_code == 200


def test_api_analyze_invalid_file(client):
    # Upload text disguised as jpg
    data = {
        "image": (io.BytesIO(b"This is purely text"), "bad_file.jpg")
    }
    response = client.post("/api/analyze", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    json_data = response.get_json()
    assert "error" in json_data


def test_api_compare_endpoint(client, image_with_exif_and_gps, image_without_exif):
    with open(image_with_exif_and_gps, "rb") as f1, open(image_without_exif, "rb") as f2:
        b1, b2 = f1.read(), f2.read()

    data = {
        "images": [
            (io.BytesIO(b1), "copy1.jpg"),
            (io.BytesIO(b2), "copy2.png"),
        ]
    }
    response = client.post("/api/compare", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert json_data["comparison"]["copies_count"] == 2
