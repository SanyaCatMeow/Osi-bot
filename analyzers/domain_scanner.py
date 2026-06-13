import asyncio
import httpx  # pyrefly: ignore[missing-import]
import dns.asyncresolver  # pyrefly: ignore[missing-import]
from config import config
from utils import b, code, i, hdr, esc


def _safe_str(value, max_len: int = 120) -> str:
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value)[:max_len]


async def analyze_domain(domain: str) -> dict:
    result: dict = {
        "domain": domain,
        "whois": None,
        "whois_error": None,
        "dns": {},
        "virustotal": None,
    }

    # ── WHOIS (sync library, run in thread) ──────────────────────────────
    try:
        import whois as _whois  # pyrefly: ignore[missing-import]

        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, _whois.whois, domain)  # pyrefly: ignore[bad-argument-type]
        result["whois"] = w
    except Exception as exc:
        result["whois_error"] = str(exc)

    # ── DNS records ───────────────────────────────────────────────────────
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            answers = await resolver.resolve(domain, rtype)
            result["dns"][rtype] = [str(r) for r in answers]
        except Exception:
            pass

    # ── VirusTotal domain lookup ──────────────────────────────────────────
    if config.VIRUSTOTAL_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
                )
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    result["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "reputation": attrs.get("reputation", 0),
                        "categories": attrs.get("categories", {}),
                        "creation_date": attrs.get("creation_date"),
                        "last_analysis_date": attrs.get("last_analysis_date"),
                    }
        except Exception:
            pass

    return result


def format_domain_result(data: dict) -> str:
    domain = data["domain"]
    lines = [f"🔍 <b>Domain Analysis — {esc(domain)}</b>"]

    # ── WHOIS ─────────────────────────────────────────────────────────────
    w = data.get("whois")
    if w:
        lines.append(hdr("WHOIS"))

        def _get(attr):
            v = getattr(w, attr, None) or (w.get(attr) if isinstance(w, dict) else None)
            return _safe_str(v) if v else None

        registrar = _get("registrar")
        org = _get("org")
        country = _get("country")
        creation = _get("creation_date")
        expiration = _get("expiration_date")
        name_servers = getattr(w, "name_servers", None) or (w.get("name_servers") if isinstance(w, dict) else None)
        status = _get("status")

        if registrar:
            lines.append(f"🏢 {b('Registrar:')}   {esc(registrar)}")
        if org:
            lines.append(f"👤 {b('Org:')}         {esc(org)}")
        if country:
            lines.append(f"🌍 {b('Country:')}     {esc(country)}")
        if creation:
            lines.append(f"📅 {b('Created:')}     {esc(creation[:10])}")
        if expiration:
            lines.append(f"⏳ {b('Expires:')}     {esc(expiration[:10])}")
        if name_servers:
            ns_list = [name_servers] if isinstance(name_servers, str) else list(name_servers)
            lines.append(f"🔧 {b('Nameservers:')} {esc(', '.join(str(ns).lower() for ns in ns_list[:4]))}")
        if status:
            lines.append(f"📋 {b('Status:')}      {esc(status[:80])}")
    elif data.get("whois_error"):
        lines.append(f"\n{i('⚠️ WHOIS lookup failed: ' + data['whois_error'][:100])}")

    # ── DNS ───────────────────────────────────────────────────────────────
    dns_records = data.get("dns", {})
    if dns_records:
        lines.append(hdr("DNS Records"))
        for rtype, records in dns_records.items():
            if not records:
                continue
            if rtype == "TXT":
                # TXT can be very long — truncate each record
                vals = " | ".join(r[:80] for r in records[:2])
            elif rtype == "MX":
                vals = " | ".join(r[:60] for r in records[:4])
            else:
                vals = " | ".join(r[:80] for r in records[:4])
            lines.append(f"  {code(rtype + ':')}  {esc(vals)}")

    # ── VirusTotal ────────────────────────────────────────────────────────
    vt = data.get("virustotal")
    if vt:
        lines.append(hdr("VirusTotal"))
        malicious = vt["malicious"]
        suspicious = vt["suspicious"]
        harmless = vt["harmless"]
        emoji = "🔴" if malicious > 0 else ("🟡" if suspicious > 0 else "🟢")
        lines.append(
            f"{emoji} {b('Malicious:')} {esc(malicious)}  "
            f"{b('Suspicious:')} {esc(suspicious)}  "
            f"{b('Harmless:')} {esc(harmless)}"
        )
        lines.append(f"⭐ {b('Reputation:')} {esc(vt['reputation'])}")
        cats = list(set(vt["categories"].values()))[:3]
        if cats:
            lines.append(f"🏷 {b('Categories:')} {esc(', '.join(cats))}")
    elif not config.VIRUSTOTAL_API_KEY:
        lines.append(f"\n{i('⚠️ VirusTotal check skipped — no API key configured')}")

    return "\n".join(lines)
