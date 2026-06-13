import os
from dotenv import load_dotenv  # pyrefly: ignore[missing-import]

# Load from config.env (avoids conflict with .env directory)
load_dotenv(dotenv_path="config.env")


class Config:
    # Required
    TELEGRAM_TOKEN: str = os.getenv("TELEGRAM_TOKEN", "")

    # Optional API keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    NUMVERIFY_API_KEY: str = os.getenv("NUMVERIFY_API_KEY", "")
    GOOGLE_SAFE_BROWSING_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    HIBP_API_KEY: str = os.getenv("HIBP_API_KEY", "")

    # Internal
    DB_PATH: str = "osint_bot.db"
    BOT_VERSION: str = "1.0.0"

    def validate(self):
        if not self.TELEGRAM_TOKEN:
            raise ValueError(
                "TELEGRAM_TOKEN is required. "
                "Copy config.env.example to config.env and set your token."
            )


config = Config()
