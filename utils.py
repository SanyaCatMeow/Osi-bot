import html
import re


# ── Validation helpers ───────────────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 or basic IPv6 address."""
    ipv4 = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4, ip):
        return all(0 <= int(p) <= 255 for p in ip.split("."))
    return ":" in ip and len(ip) <= 45  # basic IPv6 check


def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def is_valid_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


# ── HTML formatting helpers ──────────────────────────────────────────────────

def esc(text) -> str:
    """HTML-escape and stringify a value."""
    return html.escape(str(text))


def b(text) -> str:
    """Bold."""
    return f"<b>{esc(text)}</b>"


def code(text) -> str:
    """Inline code."""
    return f"<code>{esc(text)}</code>"


def i(text) -> str:
    """Italic."""
    return f"<i>{esc(text)}</i>"


def link(label: str, url: str) -> str:
    """Hyperlink — url is NOT escaped (must be a safe URL)."""
    return f'<a href="{url}">{esc(label)}</a>'


def hdr(text) -> str:
    """Section header line."""
    return f"\n<b>━━ {esc(text)} ━━</b>"


# ── Output helpers ───────────────────────────────────────────────────────────

def truncate(text: str, max_len: int = 4000) -> str:
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def format_flag(country_code: str) -> str:
    """Convert ISO-2 country code to flag emoji."""
    if not country_code or len(country_code) != 2:
        return "🌐"
    return "".join(chr(ord(c) + 127397) for c in country_code.upper())


def format_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n = n / 1024.0
    return f"{n:.1f} TB"
