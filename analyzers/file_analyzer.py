import hashlib
import io
from typing import Optional
import httpx  # pyrefly: ignore[missing-import]
from PIL import Image  # pyrefly: ignore[missing-import]
from config import config
from utils import b, i, hdr, esc, code, format_size


# ── Hash calculation ──────────────────────────────────────────────────────────

def calculate_hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ── EXIF extraction ───────────────────────────────────────────────────────────

# Map of EXIF tag IDs we care about
_EXIF_TAGS = {
    271:  "Camera Make",
    272:  "Camera Model",
    305:  "Software",
    36867:"Date Taken",
    36868:"Date Digitized",
    40962:"Image Width",
    40963:"Image Height",
    37385:"Flash",
    41986:"Exposure Mode",
    34853:"_gps_raw",   # handled separately
}

_GPS_TAGS = {
    1: "lat_ref",
    2: "lat",
    3: "lon_ref",
    4: "lon",
    6: "altitude",
    29: "date",
}


def _dms_to_decimal(dms_tuple, ref: str) -> float:
    """Convert DMS rational tuple to decimal degrees."""
    def _ratio(v):
        if isinstance(v, tuple):
            return v[0] / v[1] if v[1] else 0
        return float(v)

    d, m, s = dms_tuple
    dec = _ratio(d) + _ratio(m) / 60.0 + _ratio(s) / 3600.0
    if ref in ("S", "W"):
        dec = -dec
    return round(dec, 7)


def extract_exif(data: bytes) -> Optional[dict]:
    """Extract EXIF metadata from image bytes. Returns None if not an image."""
    try:
        img = Image.open(io.BytesIO(data))
    except Exception:
        return None

    # Public API (Pillow 6+), works in all modern versions
    try:
        exif_obj = img.getexif()
    except Exception:
        return {"_is_image": True, "_no_exif": True}

    if not exif_obj:
        return {"_is_image": True, "_no_exif": True}

    result: dict = {"_is_image": True}

    for tag_id, value in exif_obj.items():
        name = _EXIF_TAGS.get(tag_id)
        if not name:
            continue

        if name == "_gps_raw":
            # GPS IFD lives at tag 34853 — use get_ifd() for proper decoding
            try:
                gps_ifd = exif_obj.get_ifd(0x8825)  # 0x8825 == 34853
            except Exception:
                gps_ifd = value if isinstance(value, dict) else {}

            lat_raw = gps_ifd.get(2)   # GPSLatitude
            lat_ref = gps_ifd.get(1, "N")
            lon_raw = gps_ifd.get(4)   # GPSLongitude
            lon_ref = gps_ifd.get(3, "E")

            if lat_raw and lon_raw:
                try:
                    lat_ref_s = lat_ref if isinstance(lat_ref, str) else lat_ref.decode()
                    lon_ref_s = lon_ref if isinstance(lon_ref, str) else lon_ref.decode()
                    lat = _dms_to_decimal(lat_raw, lat_ref_s)
                    lon = _dms_to_decimal(lon_raw, lon_ref_s)
                    result["GPS Latitude"]  = lat
                    result["GPS Longitude"] = lon
                    result["GPS Map Link"]  = f"https://maps.google.com/?q={lat},{lon}"
                except Exception:
                    pass

            alt_raw = gps_ifd.get(6)
            if alt_raw:
                try:
                    result["GPS Altitude"] = f"{float(alt_raw):.1f} m"
                except Exception:
                    pass
        else:
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8", errors="ignore").strip()
                except Exception:
                    value = repr(value)
            result[name] = str(value)[:150]

    return result



# ── VirusTotal hash lookup ─────────────────────────────────────────────────────

async def _vt_hash_check(sha256: str) -> Optional[dict]:
    if not config.VIRUSTOTAL_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "name":       attrs.get("meaningful_name", ""),
                    "type":       attrs.get("type_description", ""),
                    "size":       attrs.get("size", 0),
                }
            elif resp.status_code == 404:
                return {"not_found": True}
    except Exception:
        return None


# ── Main entry point ──────────────────────────────────────────────────────────

async def analyze_file(file_data: bytes, filename: str) -> dict:
    hashes = calculate_hashes(file_data)
    exif   = extract_exif(file_data)
    vt     = await _vt_hash_check(hashes["sha256"])

    return {
        "filename": filename,
        "size":     len(file_data),
        "hashes":   hashes,
        "exif":     exif,
        "virustotal": vt,
    }


def format_file_result(data: dict) -> str:
    filename = data["filename"]
    size     = data["size"]
    hashes   = data["hashes"]

    lines = [f"📄 <b>File Analysis — {esc(filename)}</b>"]
    lines.append(f"\n📦 {b('Size:')} {esc(format_size(size))}")

    # ── Hashes ────────────────────────────────────────────────────────────
    lines.append(hdr("Hashes"))
    lines.append(f"{code('MD5   ')} {esc(hashes['md5'])}")
    lines.append(f"{code('SHA1  ')} {esc(hashes['sha1'])}")
    lines.append(f"{code('SHA256')} {esc(hashes['sha256'])}")

    # ── EXIF ─────────────────────────────────────────────────────────────
    exif = data.get("exif")
    if exif is None:
        lines.append(f"\n📷 {i('Not an image — EXIF extraction skipped')}")
    elif exif.get("_no_exif"):
        lines.append(f"\n📷 {b('EXIF:')} No metadata embedded in this image")
    else:
        lines.append(hdr("EXIF Metadata"))
        _skip = {"_is_image", "_no_exif", "GPS Map Link"}
        gps_present = False

        for key, val in exif.items():
            if key in _skip:
                continue
            if "GPS" in key:
                gps_present = True
                if key == "GPS Map Link":
                    continue
                lines.append(f"  🌍 {b(esc(key) + ':')} {esc(str(val))}")
            else:
                lines.append(f"  📌 {b(esc(key) + ':')} {esc(str(val))}")

        gps_link = exif.get("GPS Map Link")
        if gps_link:
            lines.append(f'\n  📍 <a href="{gps_link}">📍 View location on Google Maps</a>')
            lines.append(f"\n  ⚠️ {b('GPS coordinates found!')} Location data is embedded in this image.")

    # ── VirusTotal ────────────────────────────────────────────────────────
    vt = data.get("virustotal")
    if vt:
        lines.append(hdr("VirusTotal Hash Check"))
        if vt.get("not_found"):
            lines.append("⚠️ Hash not found in VirusTotal database")
            lines.append(f"   {i('File has never been scanned before')}")
        else:
            mal = vt["malicious"]
            sus = vt["suspicious"]
            har = vt["harmless"]
            emoji = "🔴" if mal > 0 else ("🟡" if sus > 0 else "🟢")
            lines.append(
                f"{emoji} {b('Malicious:')} {mal}  "
                f"{b('Suspicious:')} {sus}  "
                f"{b('Harmless:')} {har}"
            )
            if vt.get("name"):
                lines.append(f"📛 {b('Name:')} {esc(vt['name'])}")
            if vt.get("type"):
                lines.append(f"🏷 {b('Type:')} {esc(vt['type'])}")
    elif not config.VIRUSTOTAL_API_KEY:
        lines.append(f"\n{i('⚠️ VirusTotal check skipped — no API key configured')}")

    return "\n".join(lines)
