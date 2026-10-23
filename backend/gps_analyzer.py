"""
GPS Metadata Analyzer for PhotoTrace AI.

Parses EXIF GPS tags into standard decimal coordinates,
validates coordinate bounds, formats geographic data,
and provides optional rate-limited approximate reverse geocoding.
"""

from typing import Dict, Any, Optional, Tuple
import requests

# Nominatim OSM endpoint for optional reverse geocoding
NOMINATIM_URL = "https://nominatim.openstreetmap.org/reverse"
USER_AGENT = "PhotoTraceAI-Forensics/1.0 (Digital Forensics Educational Tool)"

# In-memory cache for reverse geocoding to prevent repeat network requests
_GEO_CACHE: Dict[Tuple[float, float], Dict[str, Any]] = {}


def _convert_dms_to_decimal(dms, ref: str) -> Optional[float]:
    """
    Converts (degrees, minutes, seconds) tuple or fractions to decimal degrees.
    Takes hemisphere reference ('N', 'S', 'E', 'W') into account.
    """
    try:
        def _to_float(v):
            if isinstance(v, (int, float)):
                return float(v)
            if hasattr(v, "num") and hasattr(v, "den") and v.den != 0:
                return float(v.num) / float(v.den)
            if hasattr(v, "numerator") and hasattr(v, "denominator") and v.denominator != 0:
                return float(v.numerator) / float(v.denominator)
            if isinstance(v, tuple) and len(v) == 2 and v[1] != 0:
                return float(v[0]) / float(v[1])
            return float(v)

        degrees = _to_float(dms[0])
        minutes = _to_float(dms[1])
        seconds = _to_float(dms[2])

        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)

        if ref and ref.upper() in ("S", "W"):
            decimal = -decimal

        return round(decimal, 6)
    except Exception:
        return None


def parse_gps_info(gps_dict: Dict[Any, Any]) -> Dict[str, Any]:
    """
    Parses raw EXIF GPS dictionary into structured GPS data.
    """
    result = {
        "has_gps": False,
        "latitude": None,
        "longitude": None,
        "altitude_meters": None,
        "coordinates_formatted": None,
        "dms_formatted": None,
        "timestamp_utc": None,
        "processing_method": None,
        "location_approximate": None,
        "status_message": "GPS data unavailable — No geolocation metadata embedded in this file.",
    }

    if not gps_dict:
        return result

    lat_raw = gps_dict.get("GPSLatitude") or gps_dict.get(2)
    lat_ref = gps_dict.get("GPSLatitudeRef") or gps_dict.get(1)
    lon_raw = gps_dict.get("GPSLongitude") or gps_dict.get(4)
    lon_ref = gps_dict.get("GPSLongitudeRef") or gps_dict.get(3)

    if lat_raw and lat_ref and lon_raw and lon_ref:
        lat = _convert_dms_to_decimal(lat_raw, str(lat_ref))
        lon = _convert_dms_to_decimal(lon_raw, str(lon_ref))

        if lat is not None and lon is not None:
            # Range validation
            if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0:
                # Basic check against dummy 0,0 null coordinates unless valid
                result["has_gps"] = True
                result["latitude"] = lat
                result["longitude"] = lon
                result["coordinates_formatted"] = f"{abs(lat):.6f}° {'N' if lat >= 0 else 'S'}, {abs(lon):.6f}° {'E' if lon >= 0 else 'W'}"
                result["dms_formatted"] = f"{lat_raw} {lat_ref}, {lon_raw} {lon_ref}"
                result["status_message"] = "Valid GPS Coordinates Extracted."

    # Altitude
    alt_raw = gps_dict.get("GPSAltitude") or gps_dict.get(6)
    alt_ref = gps_dict.get("GPSAltitudeRef") or gps_dict.get(5, 0)
    if alt_raw is not None:
        try:
            if hasattr(alt_raw, "num") and hasattr(alt_raw, "den") and alt_raw.den != 0:
                alt = float(alt_raw.num) / float(alt_raw.den)
            elif isinstance(alt_raw, (int, float)):
                alt = float(alt_raw)
            else:
                alt = None
            if alt is not None:
                if str(alt_ref) in ("1", b"\x01"):
                    alt = -alt  # Below sea level
                result["altitude_meters"] = round(alt, 2)
        except Exception:
            pass

    # GPS timestamp
    gps_time = gps_dict.get("GPSTimeStamp") or gps_dict.get(7)
    gps_date = gps_dict.get("GPSDateStamp") or gps_dict.get(29)
    if gps_date and gps_time:
        try:
            h = int(gps_time[0])
            m = int(gps_time[1])
            s = int(gps_time[2])
            result["timestamp_utc"] = f"{gps_date} {h:02d}:{m:02d}:{s:02d} UTC"
        except Exception:
            result["timestamp_utc"] = f"{gps_date} (raw time)"

    # Processing method
    proc_method = gps_dict.get("GPSProcessingMethod") or gps_dict.get(27)
    if proc_method:
        try:
            if isinstance(proc_method, bytes):
                # Clean EXIF header ASCII prefix if present
                clean = proc_method.replace(b"ASCII\x00\x00\x00", b"").decode("utf-8", "ignore").strip()
                result["processing_method"] = clean or None
            else:
                result["processing_method"] = str(proc_method)
        except Exception:
            pass

    return result


def reverse_geocode(latitude: float, longitude: float, allow_network: bool = True) -> Optional[Dict[str, Any]]:
    """
    Performs safe, rate-limited reverse geocoding via OpenStreetMap Nominatim.
    Clearly marks results as approximate. Never raises an uncaught network error.
    """
    if not allow_network or latitude is None or longitude is None:
        return None

    cache_key = (round(latitude, 4), round(longitude, 4))
    if cache_key in _GEO_CACHE:
        return _GEO_CACHE[cache_key]

    try:
        params = {
            "lat": latitude,
            "lon": longitude,
            "format": "jsonv2",
            "zoom": 16,
            "addressdetails": 1,
        }
        headers = {
            "User-Agent": USER_AGENT,
        }
        response = requests.get(NOMINATIM_URL, params=params, headers=headers, timeout=3.5)
        if response.status_code == 200:
            data = response.json()
            display_name = data.get("display_name", "")
            address = data.get("address", {})
            
            geo_info = {
                "display_name": display_name,
                "city": address.get("city") or address.get("town") or address.get("village"),
                "state": address.get("state"),
                "country": address.get("country"),
                "postcode": address.get("postcode"),
                "osm_id": data.get("osm_id"),
                "disclaimer": "Address is approximate via reverse-geocoding (OSM Nominatim). Not an authoritative GPS certificate.",
            }
            _GEO_CACHE[cache_key] = geo_info
            return geo_info
    except Exception:
        # Graceful fallback: Network unavailable or rate-limited
        pass

    return None
