import asyncio
import logging

from telegram import Update  # pyrefly: ignore[missing-import]
from telegram.ext import (  # pyrefly: ignore[missing-import]
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ConversationHandler,
    MessageHandler,
    filters,
)

from config import config
from database import db
from handlers import (
    WAITING_FILE,
    cancel_command,
    callback_handler,
    domain_command,
    email_command,
    file_command,
    file_received,
    help_command,
    history_command,
    ip_command,
    phone_command,
    start_command,
    url_command,
    user_command,
)

logging.basicConfig(
    format="%(asctime)s  %(name)-24s  %(levelname)-8s  %(message)s",
    level=logging.INFO,
)
for _lib in ("httpx", "httpcore", "telegram"):
    logging.getLogger(_lib).setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


async def _post_init(app) -> None:
    """Runs inside PTB's own event loop — perfect place to init async resources."""
    await db.init()
    logger.info("Database initialised ✓")


def main() -> None:
    config.validate()

    # ── Build application with post_init hook ─────────────────────────────
    # post_init runs inside PTB's own event loop, before polling starts.
    # This avoids any asyncio.run() / event-loop conflict with Python 3.14.
    app = (
        ApplicationBuilder()
        .token(config.TELEGRAM_TOKEN)
        .post_init(_post_init)
        .build()
    )

    # ── File upload conversation ───────────────────────────────────────────
    file_conv = ConversationHandler(
        entry_points=[CommandHandler("file", file_command)],
        states={
            WAITING_FILE: [
                MessageHandler(filters.Document.ALL | filters.PHOTO, file_received)
            ]
        },
        fallbacks=[CommandHandler("cancel", cancel_command)],
        allow_reentry=True,
    )

    # ── Register all handlers ─────────────────────────────────────────────
    app.add_handler(CommandHandler("start",   start_command))
    app.add_handler(CommandHandler("help",    help_command))
    app.add_handler(CommandHandler("ip",      ip_command))
    app.add_handler(CommandHandler("domain",  domain_command))
    app.add_handler(CommandHandler("email",   email_command))
    app.add_handler(CommandHandler("user",    user_command))
    app.add_handler(CommandHandler("phone",   phone_command))
    app.add_handler(CommandHandler("url",     url_command))
    app.add_handler(CommandHandler("history", history_command))
    app.add_handler(file_conv)
    app.add_handler(CallbackQueryHandler(callback_handler))

    logger.info("🤖 OSINT Bot started — polling for updates…")

    # Python 3.14 no longer auto-creates an event loop via get_event_loop().
    # PTB 21.6 relies on this internally, so we create one explicitly.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # run_polling() is SYNCHRONOUS in PTB v20+ — manages its own event loop
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
