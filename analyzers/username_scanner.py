import asyncio
import random
from typing import List
import httpx  # pyrefly: ignore[missing-import]
from utils import esc, b, i, hdr

# ── Platform definitions ─────────────────────────────────────────────────────
PLATFORMS: dict = {
    # ── global ──────────────────────────────────────────────────
    "GitHub": {
        "url":         "https://api.github.com/users/{username}",
        "profile_url": "https://github.com/{username}",
        "check":       "status_200",
    },
    "GitLab": {
        "url":   "https://gitlab.com/{username}",
        "check": "not_404",
    },
    "Reddit": {
        "url":         "https://www.reddit.com/user/{username}/about.json",
        "profile_url": "https://www.reddit.com/user/{username}",
        "check":       "status_200",
    },
    "Twitter / X": {
        "url":   "https://x.com/{username}",
        "check": "not_404",
    },
    "Instagram": {
        "url":   "https://www.instagram.com/{username}/",
        "check": "not_404",
    },
    "TikTok": {
        "url":   "https://www.tiktok.com/@{username}",
        "check": "not_404",
    },
    "Pinterest": {
        "url":   "https://www.pinterest.com/{username}/",
        "check": "not_404",
    },
    "Tumblr": {
        "url":   "https://{username}.tumblr.com/",
        "check": "not_404",
    },
    "Twitch": {
        "url":   "https://www.twitch.tv/{username}",
        "check": "not_404",
    },
    "Steam": {
        "url":   "https://steamcommunity.com/id/{username}",
        "check": "content_not:The specified profile could not be found.",
    },
    "Medium": {
        "url":   "https://medium.com/@{username}",
        "check": "not_404",
    },
    "SoundCloud": {
        "url":   "https://soundcloud.com/{username}",
        "check": "not_404",
    },
    "Vimeo": {
        "url":   "https://vimeo.com/{username}",
        "check": "not_404",
    },
    "DeviantArt": {
        "url":   "https://www.deviantart.com/{username}",
        "check": "not_404",
    },
    "Keybase": {
        "url":   "https://keybase.io/{username}",
        "check": "not_404",
    },
    "Telegram": {
        "url":   "https://t.me/{username}",
        "check": "not_404",
    },
    "Bitbucket": {
        "url":   "https://bitbucket.org/{username}/",
        "check": "not_404",
    },
    "HackerNews": {
        "url":         "https://hacker-news.firebaseio.com/v0/user/{username}.json",
        "profile_url": "https://news.ycombinator.com/user?id={username}",
        "check":       "json_not_null",
    },
    "Replit": {
        "url":   "https://replit.com/@{username}",
        "check": "not_404",
    },
    "Chess.com": {
        "url":         "https://api.chess.com/pub/player/{username}",
        "profile_url": "https://www.chess.com/member/{username}",
        "check":       "status_200",
    },
    "Lichess": {
        "url":         "https://lichess.org/api/user/{username}",
        "profile_url": "https://lichess.org/@/{username}",
        "check":       "status_200",
    },
    "npm": {
        "url":   "https://www.npmjs.com/~{username}",
        "check": "not_404",
    },
    "PyPI": {
        "url":   "https://pypi.org/user/{username}/",
        "check": "not_404",
    },
    "Pastebin": {
        "url":   "https://pastebin.com/u/{username}",
        "check": "not_404",
    },
    "Spotify": {
        "url":   "https://open.spotify.com/user/{username}",
        "check": "not_404",
    },
    "Gravatar": {
        "url":   "https://en.gravatar.com/{username}",
        "check": "not_404",
    },
    "Flickr": {
        "url":   "https://www.flickr.com/people/{username}/",
        "check": "not_404",
    },
    "Behance": {
        "url":   "https://www.behance.net/{username}",
        "check": "not_404",
    },
    # ── local ─────────────────────────────────
    "DOU.ua": {
        "url":   "https://dou.ua/users/{username}/",
        "check": "not_404",
    },
    "Freelancehunt": {
        "url":   "https://freelancehunt.com/freelancer/{username}.html",
        "check": "not_404",
    },
    "GitBook": {
        "url":   "https://{username}.gitbook.io/",
        "check": "not_404", 
    },
    "Fandom": {
        "url":   "https://www.fandom.com/u/{username}",
        "check": "not_404", 
    },
    "TryHackMe": {
        "url":         "https://tryhackme.com/api/user/exist/{username}",
        "profile_url": "https://tryhackme.com/p/{username}",
        "check":       "status_200", 
    },
    "Habr": {
        "url":   "https://habr.com/ru/users/{username}/",
        "check": "not_404", 
    },
}

# Rotation of User-Agents to avoid blocking
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
]

async def _check_one(
    client: httpx.AsyncClient,
    name: str,
    cfg: dict,
    username: str,
) -> dict:
    url = cfg["url"].replace("{username}", username)
    profile_tpl: str = cfg.get("profile_url") or cfg["url"]
    profile_url = profile_tpl.replace("{username}", username)
    check = cfg.get("check", "not_404")

    # random User-Agent
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9"
    }

    try:
        resp = await client.get(url, headers=headers, follow_redirects=True, timeout=10.0)

        # check for typical blockings
        if resp.status_code == 429:
            return {"platform": name, "url": profile_url, "exists": False, "error": "Rate Limited (429)"}
        
        if resp.status_code in (403, 401):
            return {"platform": name, "url": profile_url, "exists": False, "error": f"Access Denied ({resp.status_code})"}

        # logic of checks
        if check == "status_200":
            exists = resp.status_code == 200
        elif check == "not_404":
            exists = resp.status_code not in (404, 410)
        elif check.startswith("content_not:"):
            needle = check.split(":", 1)[1]
            exists = resp.status_code == 200 and needle not in resp.text
        elif check.startswith("content_must_have:"):
            needle = check.split(":", 1)[1].replace("{username}", username)
            exists = resp.status_code == 200 and needle in resp.text
        elif check == "json_not_null":
            try:
                exists = resp.status_code == 200 and resp.json() is not None
            except Exception:
                exists = False
        else:
            exists = resp.status_code == 200

        return {"platform": name, "url": profile_url, "exists": exists}

    except httpx.TimeoutException:
        return {"platform": name, "url": profile_url, "exists": False, "error": "Timeout"}
    except Exception as exc:
        return {"platform": name, "url": profile_url, "exists": False, "error": str(exc)[:80]}

async def scan_username(username: str) -> List[dict]:
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
    async with httpx.AsyncClient(limits=limits) as client:
        tasks = [
            _check_one(client, name, cfg, username)
            for name, cfg in PLATFORMS.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    return [r for r in results if isinstance(r, dict)]

def format_username_result(username: str, results: List[dict]) -> str:
    found  = [r for r in results if r.get("exists")]
    missed = [r for r in results if not r.get("exists") and not r.get("error")]
    errors = [r for r in results if r.get("error")]

    lines = [
        f"👤 <b>Username Search — {esc(username)}</b>",
        "",
        f"🟢 Found: {b(str(len(found)))}   "
        f"🔴 Not found: {len(missed)}   "
        f"⚠️ Errors: {len(errors)}",
    ]

    if found:
        lines.append(hdr("Found Profiles"))
        for r in found:
            lines.append(f'  • <a href="{r["url"]}">{esc(r["platform"])}</a>')

    if missed:
        lines.append(hdr("Not Found"))
        lines.append("  " + esc(", ".join(r["platform"] for r in missed)))

    if errors:
        lines.append(hdr("Could Not Check"))
        for r in errors:
            lines.append(f"  ⚠️ {esc(r['platform'])}: {i(esc(r.get('error', '')))}")

    lines.append(
        f"\n{i('Scanned ' + str(len(results)) + ' platforms using public profile pages only.')}"
    )
    return "\n".join(lines)