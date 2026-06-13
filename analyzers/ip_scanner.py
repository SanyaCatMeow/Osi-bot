import httpx  # pyrefly: ignore[missing-import]
from config import config
from utils import format_flag, b, code, i, hdr, esc


async def analyze_ip(ip: str) -> dict:
    result: dict = {
        "ip": ip,
        "geolocation": None,
        "abuse": None,
        "error": None,
    }

    async with httpx.AsyncClient(timeout=12.0) as client:
        # ── ip-api.com (free, no key) ─────────────────────────────────────
        fields = (
            "status,message,country,countryCode,region,regionName,"
            "city,zip,lat,lon,timezone,isp,org,as,asname,"
            "proxy,hosting,mobile,query"
        )
        try:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": fields},
            )
            data = resp.json()
            if data.get("status") == "success":
                result["geolocation"] = data
            else:
                result["error"] = data.get("message", "ip-api error")
        except Exception as exc:
            result["error"] = str(exc)

        # ── AbuseIPDB (optional) ──────────────────────────────────────────
        if config.ABUSEIPDB_API_KEY:
            try:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": config.ABUSEIPDB_API_KEY,
                        "Accept": "application/json",
                    },
                )
                if resp.status_code == 200:
                    result["abuse"] = resp.json().get("data", {})
            except Exception:
                pass

    return result


def format_ip_result(data: dict) -> str:
    ip = data["ip"]
    lines = [f"🌐 <b>IP Analysis — {esc(ip)}</b>"]

    geo = data.get("geolocation")
    if geo:
        flag = format_flag(geo.get("countryCode", ""))
        lines.append(hdr("Geolocation"))
        lines.append(f"{flag} {b('Country:')}  {esc(geo.get('country', 'N/A'))} ({esc(geo.get('countryCode', ''))})")
        lines.append(f"🏙 {b('City:')}      {esc(geo.get('city', 'N/A'))}, {esc(geo.get('regionName', 'N/A'))}")
        lines.append(f"📮 {b('ZIP:')}       {esc(geo.get('zip', 'N/A'))}")
        lines.append(f"🕐 {b('Timezone:')} {esc(geo.get('timezone', 'N/A'))}")
        lines.append(f"📡 {b('ISP:')}       {esc(geo.get('isp', 'N/A'))}")
        lines.append(f"🏢 {b('Org:')}       {esc(geo.get('org', 'N/A'))}")
        lines.append(f"🔢 {b('ASN:')}       {esc(geo.get('as', 'N/A'))}")
        lat = geo.get("lat", "N/A")
        lon = geo.get("lon", "N/A")
        lines.append(
            f"📍 {b('Coordinates:')} "
            f'<a href="https://maps.google.com/?q={lat},{lon}">{esc(str(lat))}, {esc(str(lon))}</a>'
        )

        lines.append(hdr("Flags"))
        tags = []
        if geo.get("proxy"):
            tags.append("🔴 VPN / Proxy / Tor detected")
        if geo.get("hosting"):
            tags.append("🟡 Hosting / Datacenter")
        if geo.get("mobile"):
            tags.append("📱 Mobile network")
        if not tags:
            tags.append("✅ Residential — no proxy/VPN detected")
        lines.extend(tags)
    else:
        lines.append(f"\n❌ {esc(data.get('error', 'Could not fetch geolocation'))}")

    abuse = data.get("abuse")
    if abuse:
        score = abuse.get("abuseConfidenceScore", 0)
        emoji = "🔴" if score > 50 else ("🟡" if score > 20 else "🟢")
        lines.append(hdr("AbuseIPDB"))
        lines.append(f"{emoji} {b('Abuse Score:')}  {esc(score)}%")
        lines.append(f"📝 {b('Total Reports:')} {esc(abuse.get('totalReports', 0))}")
        lines.append(f"👥 {b('Distinct Users:')} {esc(abuse.get('numDistinctUsers', 0))}")
        last = abuse.get("lastReportedAt")
        if last:
            lines.append(f"📅 {b('Last Report:')}  {esc(str(last)[:10])}")
        domain = abuse.get("domain")
        if domain:
            lines.append(f"🌐 {b('Domain:')}       {esc(domain)}")
        lines.append(f"🏷 {b('Usage Type:')}  {esc(abuse.get('usageType', 'N/A'))}")
        isp = abuse.get("isp")
        if isp:
            lines.append(f"📡 {b('ISP:')}          {esc(isp)}")
    elif not config.ABUSEIPDB_API_KEY:
        lines.append(f"\n{i('⚠️ AbuseIPDB check skipped — no API key configured')}")

    return "\n".join(lines)
