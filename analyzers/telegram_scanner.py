import logging
import os
from telethon import TelegramClient
from telethon.tl.functions.users import GetFullUserRequest
from utils import esc
# Якщо ти не імпортуєш config, а використовуєш os.getenv, 
# переконайся, що BOT_TOKEN у тебе в системних змінних або .env файлі

logger = logging.getLogger(__name__)

# Official Android App Keys
API_ID = 2040
API_HASH = "b18441a1ff607e10a989891a5462e627"
BOT_TOKEN = os.getenv("BOT_TOKEN") 

client = TelegramClient('bot_mtproto_session', API_ID, API_HASH)

async def scan_telegram_profile(username: str) -> str:
    # Ensure client is connected and authorized
    if not client.is_connected():
        await client.connect()
    
    if not await client.is_user_authorized():
        # pyrefly: ignore [not-async]
        await client.start(bot_token=BOT_TOKEN)

    target = username.strip()
    if not target.startswith("@"):
        target = f"@{target}"

    try:
        # Resolve the username globally using MTProto
        # pyrefly: ignore
        full_user = await client(GetFullUserRequest(target))
        user = full_user.users[0]
        full_info = full_user.full_user

        lines = [
            f"✈️ <b>Telegram Profile Search — {esc(target)}</b>\n",
            f"🆔 <b>Telegram ID:</b> <code>{user.id}</code>"
        ]

        full_name = user.first_name or ""
        if user.last_name:
            full_name += f" {user.last_name}"
        if full_name:
            lines.append(f"👤 <b>Name:</b> {esc(full_name.strip())}")

        if full_info.about:
            lines.append(f"📝 <b>Bio:</b> {esc(full_info.about)}")

        # Safe attribute checks
        is_premium = getattr(user, 'premium', False)
        if is_premium:
            lines.append("💎 <b>Status:</b> Telegram Premium User")

        if user.photo:
            lines.append("📸 <b>Photo:</b> Yes (can be downloaded by ID)")
        else:
            lines.append("📸 <b>Photo:</b> Hidden or None")

        lines.append(f"\n🔗 <b>Link:</b> <a href='https://t.me/{target[1:]}'>t.me/{target[1:]}</a>")

        return "\n".join(lines)

    except ValueError as e:
        if "No user has" in str(e) or "Cannot find" in str(e):
            return f"❌ <b>Error:</b> User {esc(target)} not found."
        return f"⚠️ <b>API Error:</b> {esc(str(e))}"
    except Exception as exc:
        logger.exception("Telethon scan failed")
        return f"⚠️ <b>Unknown Error:</b> {esc(str(exc))}"