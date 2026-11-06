import json
import sqlite3
import secrets
from pathlib import Path
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = Path(__file__).resolve().parent
DB = BASE / "lab_devices.db"

env = {}
for line in (BASE / ".env").read_text().splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()

API_KEY = env.get("LAB_API_KEY", "")
if len(API_KEY) < 32:
    raise RuntimeError("مفتاح الحماية غير صالح")


def connect_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


with connect_db() as db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            manufacturer TEXT,
            model TEXT,
            android_version TEXT,
            api_level INTEGER,
            locale TEXT,
            timezone TEXT,
            storage_total_gb REAL,
            storage_available_gb REAL,
            app_version TEXT,
            last_seen TEXT
        )
    """)


class Handler(BaseHTTPRequestHandler):

    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        key = self.headers.get("X-Lab-Key", "")
        return secrets.compare_digest(key, API_KEY)

    def do_GET(self):
        if self.path in ("/", "/health"):
            return self.send_json(200, {
                "status": "online",
                "service": "CyberSecurityLab"
            })

        if self.path == "/devices":
            if not self.authorized():
                return self.send_json(401, {"error": "Unauthorized"})

            with connect_db() as db:
                rows = db.execute(
                    "SELECT * FROM devices ORDER BY last_seen DESC"
                ).fetchall()

            return self.send_json(200, {
                "count": len(rows),
                "devices": [dict(row) for row in rows]
            })

        self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/register":
            return self.send_json(404, {"error": "Not found"})

        if not self.authorized():
            return self.send_json(401, {"error": "Unauthorized"})

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 16000:
                return self.send_json(400, {"error": "Invalid body size"})

            data = json.loads(self.rfile.read(length))
            required = [
                "device_id", "manufacturer", "model",
                "android_version", "api_level", "locale",
                "timezone", "storage_total_gb",
                "storage_available_gb", "app_version"
            ]

            if any(k not in data for k in required):
                return self.send_json(400, {"error": "Missing fields"})

            if not isinstance(data["device_id"], str) or not 8 <= len(data["device_id"]) <= 100:
                return self.send_json(400, {"error": "Invalid device ID"})

            now = datetime.now(timezone.utc).isoformat()
            values = [data[k] for k in required] + [now]

            with connect_db() as db:
                db.execute("""
                    INSERT INTO devices VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    ON CONFLICT(device_id) DO UPDATE SET
                        manufacturer=excluded.manufacturer,
                        model=excluded.model,
                        android_version=excluded.android_version,
                        api_level=excluded.api_level,
                        locale=excluded.locale,
                        timezone=excluded.timezone,
                        storage_total_gb=excluded.storage_total_gb,
                        storage_available_gb=excluded.storage_available_gb,
                        app_version=excluded.app_version,
                        last_seen=excluded.last_seen
                """, values)

            self.send_json(200, {
                "success": True,
                "message": "Device registered"
            })

        except (ValueError, TypeError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid data"})

    def log_message(self, format, *args):
        print(format % args)


if __name__ == "__main__":
    print("CyberSecurityLab server starting on port 8000")
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
