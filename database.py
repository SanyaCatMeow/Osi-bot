import aiosqlite  # pyrefly: ignore[missing-import]
from config import config


class Database:
    def __init__(self, db_path: str = config.DB_PATH):
        self.db_path = db_path

    async def init(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS queries (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id   INTEGER NOT NULL,
                    username  TEXT,
                    command   TEXT    NOT NULL,
                    query     TEXT    NOT NULL,
                    result    TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await db.commit()

    async def save_query(
        self,
        user_id: int,
        username: str,
        command: str,
        query: str,
        result: str,
    ):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO queries (user_id, username, command, query, result) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, username, command, query, result),
            )
            await db.commit()

    async def get_history(self, user_id: int, limit: int = 10):
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT command, query, timestamp "
                "FROM queries WHERE user_id = ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (user_id, limit),
            ) as cursor:
                return await cursor.fetchall()


db = Database()
