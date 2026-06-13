import base64
import httpx  # pyrefly: ignore[missing-import]
from bs4 import BeautifulSoup  # pyrefly: ignore[missing-import]
from config import config
from utils import b, i, hdr, esc, code

_PARSER = "html.parser"  # built-in, no C-extensions needed

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}


async def analyze_url(url: str) -> dict:
    result: dict = {
        "original_url": url,
        "final_url":    None,
        "redirects":    [],
        "status_code":  None,
        "metadata":     None,
        "virustotal":   None,
        "safe_browsing": None,
        "error":        None,
    }

    async with httpx.AsyncClient(
        headers=_HEADERS,
        follow_redirects=True,
        timeout=15.0,
    ) as client:

        # ── Fetch page ────────────────────────────────────────────────────
        try:
            resp = await client.get(url)
            result["final_url"]   = str(resp.url)
            result["status_code"] = resp.status_code
            result["redirects"]   = [str(r.url) for r in resp.history]

            # HTML metadata
            ct = resp.headers.get("content-type", "")
            if "text/html" in ct:
                soup = BeautifulSoup(resp.text, _PARSER)
                meta: dict = {}

                if t := soup.find("title"):
                    meta["title"] = t.get_text(strip=True)[:200]
                if m := soup.find("meta", attrs={"name": "description"}):
                    meta["description"] = (m.get("content") or "")[:300]
                if m := soup.find("meta", attrs={"property": "og:title"}):
                    meta["og_title"] = (m.get("content") or "")[:200]
                if m := soup.find("meta", attrs={"property": "og:site_name"}):
                    meta["og_site"] = (m.get("content") or "")[:100]

                meta["server"]         = resp.headers.get("server", "")
                meta["content_type"]   = ct.split(";")[0].strip()
                meta["content_length"] = resp.headers.get("content-length", "")
                result["metadata"] = meta

        except Exception as exc:
            result["error"] = str(exc)[:200]

        # ── VirusTotal URL lookup ─────────────────────────────────────────
        if config.VIRUSTOTAL_API_KEY:
            try:
                vt_headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                vt_resp = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=vt_headers,
                )
                if vt_resp.status_code == 200:
                    attrs = vt_resp.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    result["virustotal"] = {
                        "malicious":  stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless":   stats.get("harmless", 0),
                    }
                elif vt_resp.status_code == 404:
                    # Submit URL for scanning
                    post = await client.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers=vt_headers,
                        data={"url": url},
                    )
                    if post.status_code == 200:
                        result["virustotal"] = {
                            "pending": True,
                            "message": "Submitted for analysis — check again in ~60 s",
                        }
            except Exception:
                pass

        # ── Google Safe Browsing ──────────────────────────────────────────
        if config.GOOGLE_SAFE_BROWSING_KEY:
            payload = {
                "client": {"clientId": "osint-bot", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            try:
                gsb = await client.post(
                    "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                    params={"key": config.GOOGLE_SAFE_BROWSING_KEY},
                    json=payload,
                )
                if gsb.status_code == 200:
                    matches = gsb.json().get("matches", [])
                    result["safe_browsing"] = {
                        "safe":    len(matches) == 0,
                        "threats": matches,
                    }
            except Exception:
                pass

    return result


def format_url_result(data: dict) -> str:
    lines = [f"🔗 <b>URL Analysis</b>"]
    lines.append(f"\n📎 {b('Original:')} {code(esc(data['original_url'][:80]))}")

    final = data.get("final_url")
    if final and final != data["original_url"]:
        lines.append(f"➡️ {b('Resolved:')} {code(esc(final[:80]))}")

    hops = data.get("redirects", [])
    if hops:
        lines.append(f"🔄 {b('Redirects:')} {len(hops)} hop(s)")

    status = data.get("status_code")
    if status:
        emoji = "✅" if 200 <= status < 300 else ("🟡" if 300 <= status < 400 else "🔴")
        lines.append(f"{emoji} {b('HTTP Status:')} {status}")

    # ── Page metadata ─────────────────────────────────────────────────────
    meta = data.get("metadata") or {}
    if meta:
        lines.append(hdr("Page Metadata"))
        if meta.get("title"):
            lines.append(f"📌 {b('Title:')}       {esc(meta['title'])}")
        og = meta.get("og_title", "")
        if og and og != meta.get("title", ""):
            lines.append(f"🏷 {b('OG Title:')}    {esc(og)}")
        if meta.get("og_site"):
            lines.append(f"🌐 {b('Site:')}        {esc(meta['og_site'])}")
        if meta.get("description"):
            desc = meta["description"]
            lines.append(f"📝 {b('Description:')} {esc(desc[:120])}{'…' if len(desc) > 120 else ''}")
        if meta.get("server"):
            lines.append(f"💻 {b('Server:')}      {esc(meta['server'])}")
        if meta.get("content_type"):
            lines.append(f"📄 {b('Content-Type:')} {esc(meta['content_type'])}")

    # ── VirusTotal ────────────────────────────────────────────────────────
    vt = data.get("virustotal")
    if vt:
        lines.append(hdr("VirusTotal"))
        if vt.get("pending"):
            lines.append(f"⏳ {esc(vt['message'])}")
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
    elif not config.VIRUSTOTAL_API_KEY:
        lines.append(f"\n{i('⚠️ VirusTotal check skipped — no API key configured')}")

    # ── Google Safe Browsing ──────────────────────────────────────────────
    sb = data.get("safe_browsing")
    if sb:
        lines.append(hdr("Google Safe Browsing"))
        if sb.get("safe"):
            lines.append("✅ No threats detected")
        else:
            for t in sb["threats"]:
                lines.append(f"🔴 {esc(t.get('threatType', 'Unknown'))}")
    elif not config.GOOGLE_SAFE_BROWSING_KEY:
        lines.append(f"\n{i('⚠️ Safe Browsing check skipped — no API key configured')}")

    if data.get("error"):
        lines.append(f"\n⚠️ {b('Error:')} {esc(data['error'])}")

    return "\n".join(lines)
