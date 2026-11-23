#!/usr/bin/env python3
"""MASTERDAW beta sign-up: email in, download link out.

    POST /api/beta/signup   {"email": "...", "platform": "windows|mac|linux"}
         -> stores the sign-up, emails a personal link /download/<token>
    GET  /download/<token>  -> the newest file in $BETA_FILES_DIR/<platform>/

Standard library only. Behind nginx in production (nginx proxies /api/ and
/download/ here, and serves the file itself via X-Accel-Redirect). Locally,
`python server/beta.py --static .` also serves the site, so the whole flow
can be tried at http://127.0.0.1:8766/masterdaw/.

Settings come from the environment (see server/beta.env.example). With no
SMTP_HOST the email is printed to stdout instead of sent.
"""

import argparse
import json
import mimetypes
import os
import re
import secrets
import smtplib
import sqlite3
import sys
import threading
import time
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

PLATFORMS = {"windows": "Windows", "mac": "Mac (Apple Silicon)", "linux": "Linux"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("BETA_DB", ROOT / "beta.db"))
FILES_DIR = Path(os.environ.get("BETA_FILES_DIR", ROOT / "downloads"))
BASE_URL = os.environ.get("BETA_BASE_URL", "http://127.0.0.1:8766").rstrip("/")
TOKEN_DAYS = int(os.environ.get("BETA_TOKEN_DAYS", "7"))
ACCEL = os.environ.get("BETA_ACCEL") == "1"  # let nginx send the file

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "MASTERDAW <support@3vee.app>")

# Abuse limits: the form sends mail to any address typed into it.
PER_IP_PER_HOUR = 5
PER_EMAIL_PER_DAY = 3

_db_lock = threading.Lock()


def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _db_lock, db() as con:
        con.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS signups (
                id       INTEGER PRIMARY KEY,
                email    TEXT NOT NULL,
                name     TEXT,
                platform TEXT NOT NULL,
                token    TEXT NOT NULL UNIQUE,
                ip       TEXT,
                created  INTEGER NOT NULL,
                mailed   INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS signups_email ON signups(email);
            CREATE TABLE IF NOT EXISTS downloads (
                id     INTEGER PRIMARY KEY,
                token  TEXT NOT NULL,
                file   TEXT NOT NULL,
                ip     TEXT,
                at     INTEGER NOT NULL
            );
        """)
        # databases made before the name field existed
        if "name" not in {r["name"] for r in con.execute("PRAGMA table_info(signups)")}:
            con.execute("ALTER TABLE signups ADD COLUMN name TEXT")


def newest_file(platform):
    folder = FILES_DIR / platform
    if not folder.is_dir():
        return None
    files = [p for p in folder.iterdir() if p.is_file() and not p.name.startswith(".")]
    return max(files, key=lambda p: p.stat().st_mtime) if files else None


def send_mail(to, person, platform, link):
    name = PLATFORMS[platform]
    msg = EmailMessage()
    msg["From"] = MAIL_FROM
    msg["To"] = to
    msg["Subject"] = f"Your MASTERDAW beta download for {name}"
    greeting = f"Hi {person},\n\n" if person else ""
    msg.set_content(
        f"{greeting}Thanks for trying the MASTERDAW beta.\n\n"
        f"Download for {name}:\n{link}\n\n"
        f"The link is yours and works for {TOKEN_DAYS} days.\n"
    )
    if not SMTP_HOST:
        print("---- email (not sent: no SMTP_HOST) ----\n" + msg.as_string(), flush=True)
        return
    if SMTP_PORT == 465:
        smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20)
    else:
        smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
        smtp.starttls()
    with smtp:
        if SMTP_USER:
            smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)


class Handler(BaseHTTPRequestHandler):
    server_version = "beta"
    static_dir = None  # set by --static for local testing

    # -- helpers -------------------------------------------------------------
    def client_ip(self):
        return self.headers.get("CF-Connecting-IP") or self.client_address[0]

    def send_json(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, code, text):
        data = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.client_ip()} {fmt % args}\n")

    # -- routes --------------------------------------------------------------
    def do_POST(self):
        if urlsplit(self.path).path != "/api/beta/signup":
            return self.send_json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 2048:
                raise ValueError
            body = json.loads(self.rfile.read(length) or b"{}")
            email = str(body.get("email", "")).strip()
            platform = str(body.get("platform", "")).strip().lower()
            # optional; one line, no control characters, so it is safe in the email
            person = " ".join(str(body.get("name") or "").split())[:100]
            person = "".join(ch for ch in person if ch.isprintable())
        except (ValueError, json.JSONDecodeError):
            return self.send_json(400, {"error": "bad request"})

        if platform not in PLATFORMS:
            return self.send_json(400, {"error": "Pick Windows, Mac or Linux."})
        if len(email) > 254 or not EMAIL_RE.match(email):
            return self.send_json(400, {"error": "That email address doesn't look right."})

        ip, now = self.client_ip(), int(time.time())
        with _db_lock, db() as con:
            by_ip = con.execute("SELECT COUNT(*) FROM signups WHERE ip=? AND created>?",
                                (ip, now - 3600)).fetchone()[0]
            by_email = con.execute("SELECT COUNT(*) FROM signups WHERE lower(email)=lower(?) AND created>?",
                                   (email, now - 86400)).fetchone()[0]
            if by_ip >= PER_IP_PER_HOUR or by_email >= PER_EMAIL_PER_DAY:
                return self.send_json(429, {"error": "Too many requests. Try again later."})
            token = secrets.token_urlsafe(24)
            con.execute("INSERT INTO signups(email, name, platform, token, ip, created) VALUES (?,?,?,?,?,?)",
                        (email, person or None, platform, token, ip, now))

        try:
            send_mail(email, person, platform, f"{BASE_URL}/download/{token}")
        except Exception as e:  # noqa: BLE001 - report any mail failure the same way
            sys.stderr.write(f"mail to {email} failed: {e!r}\n")
            return self.send_json(502, {"error": "Couldn't send the email. Try again in a minute."})
        with _db_lock, db() as con:
            con.execute("UPDATE signups SET mailed=1 WHERE token=?", (token,))
        return self.send_json(200, {"ok": True})

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/download/"):
            return self.download(path[len("/download/"):])
        if path == "/api/health":
            return self.send_json(200, {"ok": True})
        if self.static_dir:
            return self.static(path)
        return self.send_text(404, "Not found")

    def download(self, token):
        with _db_lock, db() as con:
            row = con.execute("SELECT platform, created FROM signups WHERE token=?", (token,)).fetchone()
        if not row:
            return self.send_text(404, "This download link isn't valid.")
        if time.time() - row["created"] > TOKEN_DAYS * 86400:
            return self.send_text(410, "This download link has expired. Sign up again for a new one.")
        f = newest_file(row["platform"])
        if not f:
            return self.send_text(404, f"The {PLATFORMS[row['platform']]} build isn't available yet.")
        with _db_lock, db() as con:
            con.execute("INSERT INTO downloads(token, file, ip, at) VALUES (?,?,?,?)",
                        (token, f.name, self.client_ip(), int(time.time())))

        self.send_response(200)
        self.send_header("Content-Disposition", f'attachment; filename="{f.name}"')
        self.send_header("Cache-Control", "no-store")
        if ACCEL:
            self.send_header("X-Accel-Redirect", f"/_beta_files/{row['platform']}/{f.name}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(f.stat().st_size))
        self.end_headers()
        with f.open("rb") as fh:
            while chunk := fh.read(1 << 16):
                self.wfile.write(chunk)

    def static(self, path):
        root = Path(self.static_dir).resolve()
        target = (root / unquote(path).lstrip("/")).resolve()
        if root not in target.parents and target != root:
            return self.send_text(404, "Not found")
        if target.is_dir():
            if not path.endswith("/"):
                self.send_response(301)
                self.send_header("Location", path + "/")
                self.end_headers()
                return
            target = target / "index.html"
        if not target.is_file():
            return self.send_text(404, "Not found")
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--static", help="also serve this folder (local testing only)")
    args = ap.parse_args()
    Handler.static_dir = args.static
    init_db()
    print(f"beta server on http://{args.host}:{args.port}  db={DB_PATH}  files={FILES_DIR}"
          f"  mail={'smtp ' + SMTP_HOST if SMTP_HOST else 'console'}", flush=True)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
