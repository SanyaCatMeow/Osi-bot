from telegram import InlineKeyboardButton, InlineKeyboardMarkup  # pyrefly: ignore[missing-import]


def main_menu_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [
            InlineKeyboardButton("🌐 IP Analysis", callback_data="help_ip"),
            InlineKeyboardButton("🔍 Domain",      callback_data="help_domain"),
        ],
        [
            InlineKeyboardButton("📧 Email",       callback_data="help_email"),
            InlineKeyboardButton("👤 Username",    callback_data="help_user"),
        ],
        [
            InlineKeyboardButton("📱 Phone",       callback_data="help_phone"),
            InlineKeyboardButton("🔗 URL",         callback_data="help_url"),
        ],
        [
            InlineKeyboardButton("📄 File / EXIF", callback_data="help_file"),
            InlineKeyboardButton("📊 History",     callback_data="help_history"),

            InlineKeyboardButton("✈️ TG",     callback_data="help_tg"),
        ],
    ]
    return InlineKeyboardMarkup(buttons)
