# pyrefly: ignore-all-errors  # telegram stubs unavailable — NoneType errors are all false positives
import logging
from telegram import Update, InlineKeyboardMarkup  # pyrefly: ignore[missing-import]
from telegram.ext import ContextTypes, ConversationHandler  # pyrefly: ignore[missing-import]
from telegram.constants import ParseMode, ChatAction  # pyrefly: ignore[missing-import]

from config import config
from database import db
from keyboards import main_menu_keyboard
from utils import is_valid_ip, is_valid_domain, is_valid_email, truncate, esc, b, i
from analyzers.ip_scanner import analyze_ip, format_ip_result
from analyzers.domain_scanner import analyze_domain, format_domain_result
from analyzers.email_scanner import analyze_email, format_email_result
from analyzers.username_scanner import scan_username, format_username_result
from analyzers.phone_scanner import analyze_phone, format_phone_result
from analyzers.url_scanner import analyze_url, format_url_result
from analyzers.file_analyzer import analyze_file, format_file_result
from analyzers.telegram_scanner import scan_telegram_profile

logger = logging.getLogger(__name__)

# ConversationHandler state
WAITING_FILE = 1

_HTML = ParseMode.HTML

# ── Help text ────────────────────────────────────────────────────────────────

_WELCOME = (
    "👋 Hello, <b>{name}</b>!\n\n"
    "🔍 <b>OSINT Automation Bot</b> — open-source intelligence at your fingertips.\n"
    "All data is gathered exclusively from <b>public, open sources</b>.\n\n"
    "<b>Available commands:</b>\n"
    "  /ip &lt;address&gt;    — IP geolocation &amp; reputation\n"
    "  /domain &lt;domain&gt; — WHOIS, DNS records, VirusTotal\n"
    "  /email &lt;address&gt; — Email validation &amp; breach check\n"
    "  /user &lt;nick&gt;    — Username across 28+ platforms\n"
    "  /tg &lt;nick&gt;      — Telegram profile search\n"
    "  /phone &lt;number&gt; — Phone number analysis\n"
    "  /url &lt;link&gt;     — URL scan &amp; metadata\n"
    "  /file            — Upload file → EXIF + hashes\n"
    "  /history         — Your recent queries\n"
    "  /help            — Show this message\n\n"
    "👇 <i>Tap a button below to learn more about each tool.</i>"
)

_HELP_TEXTS = {
    "help_ip": (
        "🌐 <b>IP Analysis</b>\n"
        "Usage: <code>/ip &lt;address&gt;</code>\n"
        "Example: <code>/ip 8.8.8.8</code>\n\n"
        "Returns geolocation, ISP, ASN, VPN/Proxy/Tor detection and AbuseIPDB score."
    ),
    "help_domain": (
        "🔍 <b>Domain Analysis</b>\n"
        "Usage: <code>/domain &lt;domain&gt;</code>\n"
        "Example: <code>/domain google.com</code>\n\n"
        "Returns WHOIS info, DNS records (A, MX, NS, TXT, SOA) and VirusTotal reputation."
    ),
    "help_email": (
        "📧 <b>Email Analysis</b>\n"
        "Usage: <code>/email &lt;address&gt;</code>\n"
        "Example: <code>/email user@gmail.com</code>\n\n"
        "Validates format, checks MX records, and optionally checks data breaches (HIBP)."
    ),
    "help_user": (
        "👤 <b>Username Search</b>\n"
        "Usage: <code>/user &lt;username&gt;</code>\n"
        "Example: <code>/user johndoe</code>\n\n"
        "Searches for the username on 28+ platforms: GitHub, Reddit, TikTok, Steam, etc."
    ),
    "help_phone": (
        "📱 <b>Phone Analysis</b>\n"
        "Usage: <code>/phone &lt;number&gt;</code>\n"
        "Example: <code>/phone +380501234567</code>\n\n"
        "Identifies country, carrier, line type and timezone. Include country code."
    ),
    "help_url": (
        "🔗 <b>URL Analysis</b>\n"
        "Usage: <code>/url &lt;link&gt;</code>\n"
        "Example: <code>/url https://bit.ly/something</code>\n\n"
        "Follows redirects, extracts page metadata, checks VirusTotal and Google Safe Browsing."
    ),
    "help_file": (
        "📄 <b>File / Image Analysis</b>\n"
        "Usage: <code>/file</code> then send a file or photo.\n\n"
        "• Extracts EXIF metadata (camera, GPS location, date)\n"
        "• Calculates MD5 / SHA1 / SHA256 hashes\n"
        "• Checks hash against VirusTotal"
    ),
    "help_history": (
        "📊 <b>Query History</b>\n"
        "Usage: <code>/history</code>\n\n"
        "Shows your last 10 OSINT queries with timestamps."
    ),
    "help_tg": (
        "✈️ <b>Telegram Profile Search</b>\n"
        "Usage: <code>/tg &lt;username&gt;</code>\n"
        "Example: <code>/tg @durov</code>\n\n"
        "Fetches the hidden Telegram ID, Name, Bio, and Premium status of any user."
    ),
}


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _save(update: Update, command: str, query: str, result: str):
    user = update.effective_user
    await db.save_query(
        user.id,
        user.username or user.first_name or str(user.id),
        command,
        query,
        result[:500],
    )


# ── Command handlers ──────────────────────────────────────────────────────────

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = update.effective_user.first_name or "there"
    await update.message.reply_text(
        _WELCOME.format(name=esc(name)),
        parse_mode=_HTML,
        reply_markup=main_menu_keyboard(),
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await start_command(update, context)


async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ Usage: <code>/ip &lt;IP address&gt;</code>\nExample: <code>/ip 8.8.8.8</code>",
            parse_mode=_HTML,
        )
        return

    ip = context.args[0].strip()
    if not is_valid_ip(ip):
        await update.message.reply_text("❌ Invalid IP address format.", parse_mode=_HTML)
        return

    msg = await update.message.reply_text(
        f"🔍 Analyzing IP <code>{esc(ip)}</code>…", parse_mode=_HTML
    )
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)

    try:
        data   = await analyze_ip(ip)
        text   = format_ip_result(data)
        await msg.edit_text(truncate(text), parse_mode=_HTML)
        await _save(update, "ip", ip, text)
    except Exception as exc:
        logger.exception("IP analysis failed")
        await msg.edit_text(f"❌ Error: {esc(str(exc)[:200])}", parse_mode=_HTML)


async def domain_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ Usage: <code>/domain &lt;domain&gt;</code>\nExample: <code>/domain google.com</code>",
            parse_mode=_HTML,
        )
        return

    raw = context.args[0].strip().lower()
    # Strip scheme / path
    domain = raw.removeprefix("https://").removeprefix("http://").split("/")[0].split("?")[0]

    if not is_valid_domain(domain):
        await update.message.reply_text("❌ Invalid domain format.", parse_mode=_HTML)
        return

    msg = await update.message.reply_text(
        f"🔍 Analyzing domain <code>{esc(domain)}</code>…", parse_mode=_HTML
    )
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)

    try:
        data = await analyze_domain(domain)
        text = format_domain_result(data)
        await msg.edit_text(truncate(text), parse_mode=_HTML)
        await _save(update, "domain", domain, text)
    except Exception as exc:
        logger.exception("Domain analysis failed")
        await msg.edit_text(f"❌ Error: {esc(str(exc)[:200])}", parse_mode=_HTML)


async def email_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ Usage: <code>/email &lt;address&gt;</code>\nExample: <code>/email user@gmail.com</code>",
            parse_mode=_HTML,
        )
        return

    email = context.args[0].strip().lower()
    if not is_valid_email(email):
        await update.message.reply_text("❌ Invalid email format.", parse_mode=_HTML)
        return

    msg = await update.message.reply_text(
        f"🔍 Analyzing <code>{esc(email)}</code>…", parse_mode=_HTML
    )
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)

    try:
        data = await analyze_email(email)
        text = format_email_result(data)
        await msg.edit_text(truncate(text), parse_mode=_HTML)
        await _save(update, "email", email, text)
    except Exception as exc:
        logger.exception("Email analysis failed")
        await msg.edit_text(f"❌ Error: {esc(str(exc)[:200])}", parse_mode=_HTML)


async def user_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ Usage: <code>/user &lt;username&gt;</code>\nExample: <code>/user johndoe</code>",
            parse_mode=_HTML,
        )
        return

    username = context.args[0].strip().lstrip("@")
    if not (2 <= len(username) <= 50):
        await update.message.reply_text(
            "❌ Username must be 2–50 characters.", parse_mode=_HTML
        )
        return

    msg = await update.message.reply_text(
        f"🔍 Searching for <code>{esc(username)}</code> across 28+ platforms…\n"
        "⏳ This may take 15–30 seconds.",
        parse_mode=_HTML,
    )
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)

    try:
        results = await scan_username(username)
        text    = format_username_result(username, results)
        await msg.edit_text(
            truncate(text), parse_mode=_HTML, disable_web_page_preview=True
        )
        await _save(update, "user", username, text)
    except Exception as exc:
        logger.exception("Username scan failed")
        await msg.edit_text(f"❌ Error: {esc(str(exc)[:200])}", parse_mode=_HTML)


async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ Usage: <code>/phone &lt;number&gt;</code>\nExample: <code>/phone +380501234567</code>",
            parse_mode=_HTML,
        )
        return

    phone = " ".join(context.args).strip()
    msg   = await update.message.reply_text(
        f"🔍 Analyzing <code>{esc(phone)}</code>…", parse_mode=_HTML
    )
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)

    try:
        data = await analyze_phone(phone)
        text = format_phone_result(data)
        await msg.edit_text(truncate(text), parse_mode=_HTML)
        await _save(update, "phone", phone, text)
    except Exception as exc:
        logger.exception("Phone analysis failed")
        await msg.edit_text(f"❌ Error: {esc(str(exc)[:200])}", parse_mode=_HTML)


async def url_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ Usage: <code>/url &lt;link&gt;</code>\nExample: <code>/url https://example.com</code>",
            parse_mode=_HTML,
        )
        return

    url = context.args[0].strip()
    if not url.startswith("http"):
        url = "https://" + url

    msg = await update.message.reply_text("🔍 Analyzing URL…", parse_mode=_HTML)
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)

    try:
        data = await analyze_url(url)
        text = format_url_result(data)
        await msg.edit_text(
            truncate(text), parse_mode=_HTML, disable_web_page_preview=True
        )
        await _save(update, "url", url, text)
    except Exception as exc:
        logger.exception("URL analysis failed")
        await msg.edit_text(f"❌ Error: {esc(str(exc)[:200])}", parse_mode=_HTML)


# ── File ConversationHandler ──────────────────────────────────────────────────

async def file_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📤 <b>Send me a file or photo</b> to analyze.\n\n"
        "I will extract:\n"
        "  • 📷 EXIF metadata (camera model, GPS, date taken)\n"
        "  • 🔐 File hashes: MD5 / SHA1 / SHA256\n"
        "  • 🔬 VirusTotal reputation (by hash)\n\n"
        "Send the file now, or /cancel to abort.",
        parse_mode=_HTML,
    )
    return WAITING_FILE


async def file_received(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc   = update.message.document
    photo = update.message.photo

    if photo:
        file_obj = photo[-1]          # largest resolution
        filename = f"photo_{file_obj.file_id[:8]}.jpg"
    elif doc:
        file_obj = doc
        filename = doc.file_name or f"file_{doc.file_id[:8]}"
    else:
        await update.message.reply_text(
            "❌ Please send a file or photo, or /cancel.", parse_mode=_HTML
        )
        return WAITING_FILE

    msg = await update.message.reply_text("⏳ Analyzing file…", parse_mode=_HTML)
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)

    try:
        tg_file   = await context.bot.get_file(file_obj.file_id)
        file_data = bytes(await tg_file.download_as_bytearray())

        data = await analyze_file(file_data, filename)
        text = format_file_result(data)

        await msg.edit_text(
            truncate(text), parse_mode=_HTML, disable_web_page_preview=False
        )
        await _save(update, "file", filename, text)
    except Exception as exc:
        logger.exception("File analysis failed")
        await msg.edit_text(f"❌ Error: {esc(str(exc)[:200])}", parse_mode=_HTML)

    return ConversationHandler.END


async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ Operation cancelled.", parse_mode=_HTML)
    return ConversationHandler.END


# ── History ───────────────────────────────────────────────────────────────────

async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    rows = await db.get_history(user.id)

    if not rows:
        await update.message.reply_text(
            "📭 No query history yet.\nStart with any OSINT command!", parse_mode=_HTML
        )
        return

    lines = ["📊 <b>Your Recent Queries:</b>\n"]
    for idx, (command, query, timestamp) in enumerate(rows, 1):
        ts = str(timestamp)[:16]
        lines.append(
            f"{idx}. <code>/{esc(command)}</code> → "
            f"<code>{esc(query[:40])}</code> "
            f"<i>({esc(ts)})</i>"
        )

    await update.message.reply_text("\n".join(lines), parse_mode=_HTML)


# ── Inline button callbacks ───────────────────────────────────────────────────

async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    text = _HELP_TEXTS.get(query.data)
    if text:
        await query.message.reply_text(text, parse_mode=_HTML)

async def tg_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❓ Usage: <code>/tg &lt;username&gt;</code>\nExample: <code>/tg @durov</code>",
            parse_mode=_HTML,
        )
        return

    username = context.args[0].strip()
    msg = await update.message.reply_text(
        f"⏳ Querying Telegram servers for <code>{esc(username)}</code>…", 
        parse_mode=_HTML
    )
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)

    try:
        # Видаляємо context.bot, залишаємо тільки username
        result = await scan_telegram_profile(username)
        
        await msg.edit_text(result, parse_mode=_HTML, disable_web_page_preview=True)
        
        # Save query to history
        await _save(update, "tg", username, result)
    except Exception as exc:
        logger.exception("Telegram scan failed")
        await msg.edit_text(f"❌ Error: {esc(str(exc)[:200])}", parse_mode=_HTML)