import httpx  # pyrefly: ignore[missing-import]
import phonenumbers  # pyrefly: ignore[missing-import]
from phonenumbers import geocoder, carrier, timezone as pn_timezone, PhoneNumberType  # pyrefly: ignore[missing-import]
from config import config
from utils import b, i, hdr, esc


_LINE_TYPE_NAMES = {
    PhoneNumberType.FIXED_LINE:           "Fixed line",
    PhoneNumberType.MOBILE:               "Mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed or Mobile",
    PhoneNumberType.TOLL_FREE:            "Toll-free",
    PhoneNumberType.PREMIUM_RATE:         "Premium rate",
    PhoneNumberType.SHARED_COST:          "Shared cost",
    PhoneNumberType.VOIP:                 "VoIP",
    PhoneNumberType.PERSONAL_NUMBER:      "Personal number",
    PhoneNumberType.PAGER:                "Pager",
    PhoneNumberType.UAN:                  "UAN",
    PhoneNumberType.VOICEMAIL:            "Voicemail",
    PhoneNumberType.UNKNOWN:              "Unknown",
}


async def analyze_phone(raw: str) -> dict:
    result: dict = {
        "input": raw,
        "valid": False,
        "possible": False,
        "parsed": None,
        "country": None,
        "carrier_name": None,
        "timezones": [],
        "line_type": None,
        "numverify": None,
        "error": None,
    }

    # ── Google libphonenumber (offline, always) ───────────────────────────
    try:
        # Prepend + if missing
        normalized = raw.strip().replace(" ", "").replace("-", "")
        if not normalized.startswith("+"):
            normalized = "+" + normalized

        parsed = phonenumbers.parse(normalized)
        result["valid"]    = phonenumbers.is_valid_number(parsed)
        result["possible"] = phonenumbers.is_possible_number(parsed)

        if result["valid"] or result["possible"]:
            result["parsed"] = {
                "international": phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                ),
                "national": phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.NATIONAL
                ),
                "e164": phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.E164
                ),
                "country_code": parsed.country_code,
            }
            result["country"]      = geocoder.description_for_number(parsed, "en") or None
            result["carrier_name"] = carrier.name_for_number(parsed, "en") or None
            result["timezones"]    = list(pn_timezone.time_zones_for_number(parsed))
            result["line_type"]    = _LINE_TYPE_NAMES.get(
                phonenumbers.number_type(parsed), "Unknown"
            )

    except phonenumbers.NumberParseException as exc:
        result["error"] = str(exc)
        return result

    # ── Numverify (optional) ──────────────────────────────────────────────
    if config.NUMVERIFY_API_KEY and result.get("parsed"):
        number_digits = result["parsed"]["e164"].lstrip("+")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    "http://apilayer.net/api/validate",
                    params={
                        "access_key": config.NUMVERIFY_API_KEY,
                        "number": number_digits,
                        "format": 1,
                    },
                )
                nv = resp.json()
                if nv.get("valid"):
                    result["numverify"] = nv
        except Exception:
            pass

    return result


def format_phone_result(data: dict) -> str:
    lines = [f"📱 <b>Phone Analysis — {esc(data['input'])}</b>"]

    if data.get("error") and not data.get("parsed"):
        lines.append(f"\n❌ Could not parse: {esc(data['error'])}")
        lines.append(f"\n{i('Tip: Include the country code, e.g. +380 for Ukraine')}")
        return "\n".join(lines)

    lines.append(hdr("Number Info"))

    if data.get("valid"):
        lines.append("✅ " + b("Status:") + " Valid number")
    elif data.get("possible"):
        lines.append("🟡 " + b("Status:") + " Possibly valid")
    else:
        lines.append("❌ " + b("Status:") + " Invalid number")

    parsed = data.get("parsed", {})
    if parsed:
        lines.append(f"📞 {b('International:')} {esc(parsed.get('international', 'N/A'))}")
        lines.append(f"🏠 {b('National:')}      {esc(parsed.get('national', 'N/A'))}")
        lines.append(f"🔢 {b('E.164:')}         {esc(parsed.get('e164', 'N/A'))}")
        lines.append(f"🌍 {b('Country code:')} +{esc(str(parsed.get('country_code', 'N/A')))}")

    if data.get("country"):
        lines.append(f"📍 {b('Location:')}   {esc(data['country'])}")

    if data.get("carrier_name"):
        lines.append(f"📡 {b('Carrier:')}    {esc(data['carrier_name'])}")

    if data.get("line_type"):
        lines.append(f"📋 {b('Line type:')} {esc(data['line_type'])}")

    if data.get("timezones"):
        tz_str = ", ".join(data["timezones"][:3])
        lines.append(f"🕐 {b('Timezone(s):')} {esc(tz_str)}")

    # ── Numverify supplement ──────────────────────────────────────────────
    nv = data.get("numverify")
    if nv:
        lines.append(hdr("Numverify"))
        if nv.get("carrier") and nv["carrier"] != data.get("carrier_name"):
            lines.append(f"📡 {b('Carrier:')}   {esc(nv['carrier'])}")
        if nv.get("line_type"):
            lines.append(f"📋 {b('Type:')}      {esc(nv['line_type'])}")
        if nv.get("location"):
            lines.append(f"📍 {b('Location:')} {esc(nv['location'])}")
    elif not config.NUMVERIFY_API_KEY:
        lines.append(f"\n{i('⚠️ Numverify enrichment skipped — no API key')}")

    return "\n".join(lines)
