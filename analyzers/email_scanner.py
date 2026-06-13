import re
import httpx  # pyrefly: ignore[missing-import]
import dns.asyncresolver  # pyrefly: ignore[missing-import]
from config import config
from utils import b, i, hdr, esc, code


async def analyze_email(email: str) -> dict:
    result: dict = {
        "email": email,
        "valid_format": False,
        "domain": None,
        "mx_records": [],
        "mx_valid": False,
        "hibp": None,
        "error": None,
    }

    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        result["error"] = "Invalid email format"
        return result

    result["valid_format"] = True
    domain = email.split("@")[1]
    result["domain"] = domain

    # ── MX record check ───────────────────────────────────────────────────
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8
    try:
        answers = await resolver.resolve(domain, "MX")
        result["mx_records"] = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers]
        )
        result["mx_valid"] = True
    except Exception:
        result["mx_valid"] = False

    # ── HaveIBeenPwned (optional, requires paid key) ──────────────────────
    if config.HIBP_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers={
                        "hibp-api-key": config.HIBP_API_KEY,
                        "user-agent": "OSINT-Bot/1.0",
                    },
                    params={"truncateResponse": "false"},
                )
                if resp.status_code == 200:
                    result["hibp"] = resp.json()
                elif resp.status_code == 404:
                    result["hibp"] = []  # clean — no breaches
        except Exception:
            pass

    return result


def format_email_result(data: dict) -> str:
    email = data["email"]
    lines = [f"📧 <b>Email Analysis — {esc(email)}</b>"]

    if not data.get("valid_format"):
        lines.append(f"\n❌ Invalid email format")
        return "\n".join(lines)

    lines.append(f"\n✅ {b('Format:')} Valid")
    lines.append(f"🌐 {b('Domain:')} {esc(data.get('domain', 'N/A'))}")

    # ── Mail server check ─────────────────────────────────────────────────
    lines.append(hdr("Mail Server"))
    if data.get("mx_valid"):
        mx = data["mx_records"]
        lines.append("✅ Domain accepts email")
        if mx:
            primary = mx[0]
            lines.append(f"📮 {b('Primary MX:')} {esc(primary[1])} {i('(priority ' + str(primary[0]) + ')')}")
            if len(mx) > 1:
                for pref, host in mx[1:3]:
                    lines.append(f"   {esc(host)} {i('(priority ' + str(pref) + ')')}")
    else:
        lines.append("❌ No MX records found — domain may not accept email")

    # ── HaveIBeenPwned ────────────────────────────────────────────────────
    lines.append(hdr("Data Breaches (HIBP)"))
    hibp = data.get("hibp")
    if hibp is None and not config.HIBP_API_KEY:
        lines.append(f"{i('⚠️ Skipped — HIBP_API_KEY not configured')}")
        lines.append(f"   Set your key from haveibeenpwned.com to enable breach checks.")
    elif hibp == []:
        lines.append("✅ Not found in any known data breach")
    elif hibp:
        lines.append(f"🔴 {b('Found in')} {b(str(len(hibp)))} {b('breach(es)!')}")
        for breach in hibp[:6]:
            name = breach.get("Name", "Unknown")
            date = breach.get("BreachDate", "N/A")
            count = breach.get("PwnCount", 0)
            data_classes = breach.get("DataClasses", [])[:3]
            lines.append(
                f"\n  💥 {b(esc(name))} ({esc(date)})\n"
                f"     {i(str(count) + ' accounts')} — {esc(', '.join(data_classes))}"
            )
        if len(hibp) > 6:
            lines.append(f"\n  {i('...and ' + str(len(hibp) - 6) + ' more breaches')}")

    return "\n".join(lines)
