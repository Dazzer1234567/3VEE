#!/usr/bin/env python3
"""MASTERDAW beta: sign-up, accounts with email sign-in links, downloads.

Public (nginx proxies /api/, /login/ and /download/ here):

    POST /api/beta/signup   {"email", "name"?, "platform"} -> creates/updates the account, records the
                            sign-up and emails a sign-in link
    POST /api/login         {"email"} -> emails a sign-in link if the account exists (same reply either way)
    GET  /login/<token>     -> a page with a "Sign in" button (email scanners that pre-open links don't
                               press it, so they can't use the link up)
    POST /login/<token>     -> one-time: starts a session (cookie) and redirects to /account/
    GET  /api/account       -> the signed-in person's details and the available builds (401 if not signed in)
    POST /api/account/download/<platform> -> the newest build for that platform (signed in)
    POST /api/logout
    POST /api/support       {"subject"?, "message", "thread_id"?, "files"?} -> a message to support (signed in)
    GET  /api/support       -> the signed-in person's conversations
    GET  /api/support/attachment/<id> -> a file from one of their own conversations
    POST /api/inbound-email -> an email to support@, from the Cloudflare Email Worker (Bearer secret)
    GET/POST /download/<token> -> old personal download links emailed before accounts existed
                               (page with a Download button; each link works MAX_USES times)
    GET  /api/tips?build=<b> -> the program's tooltips (tips.json), fetched by every copy at start and
                               every few minutes; each fetch is counted (see below). ETag / 304.
    POST /api/tips          -> new tips.json, from the developer's build only (Bearer TIPS_SECRET)

Copies running: no ID is sent. Each tips fetch stores the time, the build, the country and a hash of
the address with a salt kept only in memory and changed every day -- so fetches from one address
count as one copy, and the address itself can never be read back. Kept TIPS_PING_DAYS days.

Admin (separate listener, --admin-port; only answers loopback and Tailscale addresses, and the
firewall only opens it on the tailscale0 interface):

    GET  /admin             -> server/admin.html (people, logins, downloads, charts)
    GET  /admin/data.json   -> the numbers behind it
    GET  /admin/export.zip  -> everything: people.csv, signups.csv, downloads.csv, beta.db, README.txt
    POST /admin/delete      {"emails": [...]} -> removes those people completely
    GET  /admin/support.json, /admin/support/<id>.json, /admin/support/attachment/<id>
    POST /admin/support/<id>/reply {"text", "files"?}, /admin/support/<id>/status {"status": "open"|"closed"}

Support inbox: a Cloudflare Email Worker POSTs each email sent to support@ (raw, with a shared secret)
to /api/inbound-email; the account page's Support tab POSTs to /api/support. Both land in the same
conversations, and each new message sends a short notification to ADMIN_NOTIFY. Files travel as
"files": [{"name", "type", "data" (base64)}]; attachments in emails (including the owner's replies by
email) are kept too, and our replies email them to the customer.

Standard library only. nginx serves the build files itself via X-Accel-Redirect. Locally,
`python server/beta.py --static .` also serves the site, so the whole flow can be tried at
http://127.0.0.1:8766/masterdaw/. Settings come from the environment (server/beta.env.example).
With no SMTP_HOST the email is printed to stdout instead of sent.
"""

import argparse
import hashlib
import ipaddress
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
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

PLATFORMS = {"windows": "Windows", "mac": "Mac (Apple Silicon)", "linux": "Linux"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("BETA_DB", ROOT / "beta.db"))
FILES_DIR = Path(os.environ.get("BETA_FILES_DIR", ROOT / "downloads"))
BASE_URL = os.environ.get("BETA_BASE_URL", "http://127.0.0.1:8766").rstrip("/")
TOKEN_DAYS = int(os.environ.get("BETA_TOKEN_DAYS", "7"))      # old download links
MAX_USES = int(os.environ.get("BETA_MAX_USES", "3"))           # old download links
LOGIN_LINK_HOURS = int(os.environ.get("BETA_LOGIN_LINK_HOURS", "24"))
SESSION_DAYS = int(os.environ.get("BETA_SESSION_DAYS", "30"))
BUILD_DAYS = int(os.environ.get("BETA_BUILD_DAYS", "30"))      # each beta build works this long
ACCEL = os.environ.get("BETA_ACCEL") == "1"                    # let nginx send the file
COOKIE = "mdaw_session"
SECURE_COOKIE = BASE_URL.startswith("https://")

# Support inbox: emails to support@ arrive from a Cloudflare Email Worker (POST /api/inbound-email with
# this shared secret); each new message triggers a short notification to ADMIN_NOTIFY.
INBOUND_SECRET = os.environ.get("INBOUND_SECRET", "")

# The program's tooltips: written by the developer's build (POST /api/tips with this secret), read by
# every copy (GET /api/tips). See NOT_IN_RELEASE.md in MASTER_DAW.
TIPS_SECRET = os.environ.get("TIPS_SECRET", "")
TIPS_PATH = Path(os.environ.get("TIPS_PATH", DB_PATH.parent / "tips.json"))
TIPS_PING_DAYS = int(os.environ.get("TIPS_PING_DAYS", "30"))
MAX_TIPS_BYTES = 2 * 1024 * 1024
RUNNING_WINDOW = 10 * 60      # a copy fetches every 5 minutes: seen in the last 10 is running
ADMIN_NOTIFY = os.environ.get("ADMIN_NOTIFY", "")
ADMIN_URL = os.environ.get("ADMIN_URL", "http://vultr-3vee.tailba9a89.ts.net:8767/admin")
SUPPORT_DIR = Path(os.environ.get("BETA_SUPPORT_DIR", DB_PATH.parent / "support"))
MAX_INBOUND_BYTES = 30 * 1024 * 1024      # whole email, as sent by the Worker
MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024   # each attachment; bigger ones are listed but not stored
MAX_UPLOAD_FILES = 5                      # files per message sent from the account or admin page
MAX_UPLOAD_TOTAL = 25 * 1024 * 1024       # all files of one such message together
MAX_UPLOAD_REQUEST = MAX_UPLOAD_TOTAL * 4 // 3 + 200_000   # the same, base64 in JSON, plus the text

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "MASTERDAW <support@3vee.app>")

# Abuse limits: these forms send mail to any address typed into them.
PER_IP_PER_HOUR = 5
PER_EMAIL_PER_DAY = 3

# Small pages the server renders itself (str.format: {title}, {body}; CSS braces are doubled).
PAGE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex">
<title>{title} - MASTERDAW</title>
<link rel="icon" type="image/svg+xml" href="/pIX/favicon.svg">
<link href="https://fonts.googleapis.com/css2?family=Kanit:wght@300;400;800&display=swap" rel="stylesheet">
<style>
  @font-face {{ font-family: 'Qilka'; src: url('/comp247/Fonts/qilka/Qilka-Bold.otf') format('opentype'); font-weight: 700; font-display: swap; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Kanit', sans-serif; background: #0A0908; color: #F5F4F0; min-height: 100vh;
         display: flex; align-items: center; justify-content: center; padding: 32px 16px; text-align: center; }}
  main {{ max-width: 560px; }}
  h1 {{ font-family: 'Qilka', 'Kanit', sans-serif; font-weight: 700; font-size: clamp(28px, 6vw, 44px); line-height: 1.15; }}
  .m {{ color: #FF8A4C; }} .d {{ color: #29B6F6; }}
  p {{ font-size: 18px; font-weight: 300; color: #aaa; margin-top: 16px; line-height: 1.5; }}
  p.for {{ font-size: 22px; color: #F5F4F0; margin-top: 8px; }}
  p.small {{ font-size: 14px; color: #777; margin-top: 18px; }}
  form {{ margin-top: 28px; }}
  .btn {{ display: inline-block; font-family: 'Kanit', sans-serif; font-weight: 800; font-size: 20px; letter-spacing: 0.03em;
         color: #000; background: #FF8A4C; border: none; border-radius: 9999px 9999px 9999px 0; padding: 18px 44px;
         cursor: pointer; text-decoration: none; margin-top: 12px; }}
  .btn:hover {{ opacity: 0.88; }}
</style></head>
<body><main>{body}</main></body></html>
"""
LOGO = "<span class='m'>MASTER</span><span class='d'>DAW</span>"

_db_lock = threading.Lock()


# --- database ------------------------------------------------------------------------------------

def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _db_lock, db() as con:
        con.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS tips_pings (
                at      INTEGER NOT NULL,
                who     TEXT NOT NULL,              -- hash of the address, salted per day: see who()
                build   TEXT,
                country TEXT
            );
            CREATE INDEX IF NOT EXISTS tips_pings_at ON tips_pings(at);
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
                token  TEXT NOT NULL,          -- old download link, or '' for account downloads
                file   TEXT NOT NULL,
                ip     TEXT,
                at     INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY,
                email       TEXT NOT NULL UNIQUE,   -- stored lower-case
                name        TEXT,
                platform    TEXT,                   -- the platform they last asked for
                created     INTEGER NOT NULL,
                last_login  INTEGER,
                logins      INTEGER NOT NULL DEFAULT 0,
                stripe_customer_id TEXT             -- for payments later
            );
            CREATE TABLE IF NOT EXISTS login_links (
                hash     TEXT PRIMARY KEY,          -- sha256 of the token in the email
                user_id  INTEGER NOT NULL,
                created  INTEGER NOT NULL,
                used     INTEGER,
                ip       TEXT,
                mailed   INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                hash       TEXT PRIMARY KEY,        -- sha256 of the cookie value
                user_id    INTEGER NOT NULL,
                created    INTEGER NOT NULL,
                expires    INTEGER NOT NULL,
                last_seen  INTEGER,
                ip         TEXT
            );
            CREATE TABLE IF NOT EXISTS support_threads (
                id        INTEGER PRIMARY KEY,
                email     TEXT NOT NULL,            -- the customer, lower-case
                name      TEXT,
                subject   TEXT,
                status    TEXT NOT NULL DEFAULT 'open',   -- open | closed
                unread    INTEGER NOT NULL DEFAULT 1,
                created   INTEGER NOT NULL,
                updated   INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS support_threads_email ON support_threads(email);
            CREATE TABLE IF NOT EXISTS support_messages (
                id          INTEGER PRIMARY KEY,
                thread_id   INTEGER NOT NULL,
                direction   TEXT NOT NULL,          -- in (customer) | out (our reply)
                source      TEXT NOT NULL,          -- email | form | admin
                from_addr   TEXT,
                subject     TEXT,
                body        TEXT,                   -- plain text (HTML mail is converted)
                message_id  TEXT,                   -- RFC 5322 Message-ID, for threading
                created     INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS support_messages_thread ON support_messages(thread_id);
            CREATE INDEX IF NOT EXISTS support_messages_msgid ON support_messages(message_id);
            CREATE TABLE IF NOT EXISTS support_attachments (
                id          INTEGER PRIMARY KEY,
                message_id  INTEGER NOT NULL,       -- support_messages.id
                filename    TEXT NOT NULL,
                content_type TEXT,
                size        INTEGER NOT NULL,
                path        TEXT                    -- NULL when too big to keep
            );
        """)
        # columns added after the first databases were made
        for table, cols in (("signups", ("name", "country", "region", "city")),
                            ("downloads", ("country", "region", "city", "platform", "user_id")),
                            ("support_messages", ("body_full",))):
            have = {r["name"] for r in con.execute(f"PRAGMA table_info({table})")}
            for col in cols:
                if col not in have:
                    kind = "INTEGER" if col == "user_id" else "TEXT"
                    con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {kind}")
        # support emails stored before quote trimming / link redaction: tidy them up once
        for r in con.execute("SELECT id, body FROM support_messages WHERE direction='in' AND source='email' AND body_full IS NULL").fetchall():
            full = redact(r["body"])
            short_body = strip_quoted(full)
            if short_body != r["body"]:
                con.execute("UPDATE support_messages SET body=?, body_full=? WHERE id=?",
                            (short_body, full if full != short_body else None, r["id"]))
        # every sign-up has an account (also for sign-ups made before accounts existed)
        con.execute("""
            INSERT OR IGNORE INTO users(email, name, platform, created)
            SELECT lower(s.email),
                   (SELECT name FROM signups x WHERE lower(x.email)=lower(s.email) AND name IS NOT NULL ORDER BY created DESC LIMIT 1),
                   (SELECT platform FROM signups x WHERE lower(x.email)=lower(s.email) ORDER BY created DESC LIMIT 1),
                   MIN(s.created)
            FROM signups s GROUP BY lower(s.email)
        """)
        # old link downloads: who and which platform
        con.execute("""
            UPDATE downloads SET
              platform = COALESCE(platform, (SELECT s.platform FROM signups s WHERE s.token = downloads.token)),
              user_id  = COALESCE(user_id, (SELECT u.id FROM signups s JOIN users u ON u.email = lower(s.email)
                                            WHERE s.token = downloads.token))
            WHERE token != '' AND (platform IS NULL OR user_id IS NULL)
        """)


def sha(token):
    return hashlib.sha256(token.encode()).hexdigest()


# --- copies running ---------------------------------------------------------------------------------

_salt = {"day": None, "value": b""}


def who(ip):
    """The address, hashed with a salt that lives only in memory and changes each UTC day."""
    day = time.strftime("%Y-%m-%d", time.gmtime())
    if _salt["day"] != day:
        _salt["day"], _salt["value"] = day, secrets.token_bytes(32)
    return hashlib.sha256(_salt["value"] + ip.encode()).hexdigest()[:16]


def note_tips_fetch(ip, build, country):
    now = int(time.time())
    build = re.sub(r"[^A-Za-z0-9._-]", "", build or "")[:40] or None
    with _db_lock, db() as con:
        con.execute("INSERT INTO tips_pings(at, who, build, country) VALUES (?,?,?,?)",
                    (now, who(ip), build, country))
        con.execute("DELETE FROM tips_pings WHERE at < ?", (now - TIPS_PING_DAYS * 86400,))


def running_data():
    """How many copies are running now, by build, and over the last 7 days hour by hour."""
    now = int(time.time())
    with _db_lock, db() as con:
        live = con.execute("SELECT build, COUNT(DISTINCT who) n FROM tips_pings WHERE at >= ? GROUP BY build",
                           (now - RUNNING_WINDOW,)).fetchall()
        hours = con.execute("""SELECT at / 3600 h, COUNT(DISTINCT who) n FROM tips_pings
                               WHERE at >= ? GROUP BY h ORDER BY h""", (now - 7 * 86400,)).fetchall()
        today = con.execute("SELECT COUNT(DISTINCT who) FROM tips_pings WHERE at >= ?",
                            (now - now % 86400,)).fetchone()[0]
    by_build = sorted(({"build": r["build"] or "unknown", "running": r["n"]} for r in live),
                      key=lambda b: -b["running"])
    return {"now": sum(b["running"] for b in by_build), "by_build": by_build, "today": today,
            "hourly": [{"at": r["h"] * 3600, "running": r["n"]} for r in hours]}


def geo(headers):
    """Approximate location from Cloudflare's headers (derived from the visitor's IP).

    CF-IPCountry is always sent; cf-region and cf-ipcity need the "Add visitor location headers"
    managed transform. Returns (country, region, city), each None when unknown.
    """
    def clean(name, limit):
        v = headers.get(name) or ""
        try:  # http.server decodes header bytes as latin-1; city names arrive as UTF-8
            v = v.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
        v = " ".join(unquote(v).split())[:limit]
        return "".join(ch for ch in v if ch.isprintable()) or None

    country = (clean("CF-IPCountry", 2) or "").upper()
    if not re.fullmatch(r"[A-Z]{2}", country) or country in ("XX", "T1"):  # unknown / Tor
        country = None
    return country, clean("cf-region", 80), clean("cf-ipcity", 80)


def newest_file(platform):
    folder = FILES_DIR / platform
    if not folder.is_dir():
        return None
    files = [p for p in folder.iterdir() if p.is_file() and not p.name.startswith(".")]
    return max(files, key=lambda p: p.stat().st_mtime) if files else None


# --- email ---------------------------------------------------------------------------------------

def send_mail(to, subject, body, headers=None, attachments=()):
    msg = EmailMessage()
    msg["From"] = MAIL_FROM
    msg["To"] = to
    msg["Subject"] = subject
    for k, v in (headers or {}).items():
        if v:
            msg[k] = v
    msg.set_content(body)
    for filename, ctype, data in attachments:
        maintype, _, subtype = (ctype if re.fullmatch(r"[\w.+-]+/[\w.+-]+", ctype or "") else "application/octet-stream").partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
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


def signup_mail(person, platform, link):
    name = PLATFORMS[platform]
    greeting = f"Hi {person},\n\n" if person else ""
    return (f"Your MASTERDAW beta download for {name}",
            f"{greeting}Thanks for trying the MASTERDAW beta.\n\n"
            f"Sign in to download MASTERDAW for {name}:\n{link}\n\n"
            f"The link works once, within {LOGIN_LINK_HOURS} hours. After that you can download new beta\n"
            f"versions any time from your account: {BASE_URL}/account/\n")


def login_mail(person, link):
    greeting = f"Hi {person},\n\n" if person else ""
    return ("Sign in to MASTERDAW",
            f"{greeting}Here's your link to sign in to your MASTERDAW account:\n{link}\n\n"
            f"It works once, within {LOGIN_LINK_HOURS} hours. If you didn't ask for this, you can ignore this email.\n")


def new_login_link(con, user_id, ip):
    token = secrets.token_urlsafe(32)
    con.execute("INSERT INTO login_links(hash, user_id, created, ip) VALUES (?,?,?,?)",
                (sha(token), user_id, int(time.time()), ip))
    return token


# --- support inbox -------------------------------------------------------------------------------

def html_to_text(html):
    """Readable plain text from an HTML email (we never render customer HTML)."""
    from html.parser import HTMLParser

    class P(HTMLParser):
        def __init__(self):
            super().__init__()
            self.out, self.skip = [], 0

        def handle_starttag(self, tag, attrs):
            if tag in ("script", "style", "head"):
                self.skip += 1
            elif tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3", "blockquote"):
                self.out.append("\n")

        def handle_endtag(self, tag):
            if tag in ("script", "style", "head"):
                self.skip = max(0, self.skip - 1)

        def handle_data(self, data):
            if not self.skip:
                self.out.append(data)

    p = P()
    p.feed(html)
    text = "".join(p.out)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(line.rstrip() for line in text.splitlines())).strip()


LOGIN_LINK_RE = re.compile(r"https?://[^\s/]+/login/[A-Za-z0-9_-]{20,}")
QUOTE_HEADER_RE = re.compile(
    r"^\s*(On\s.{0,300}?\swrote:|Op\s.{0,300}?\sschreef.{0,80}:|Am\s.{0,300}?\sschrieb.{0,80}:|Le\s.{0,300}?\sa écrit\s?:"
    r"|-{2,}\s*Original Message\s*-{2,}|-{2,}\s*Oorspronkelijk bericht\s*-{2,}|_{10,})\s*$", re.I | re.S)


def redact(text):
    """Sign-in links must never be stored (customers often quote our sign-in email in replies)."""
    return LOGIN_LINK_RE.sub("[sign-in link removed]", text or "")


def strip_quoted(text):
    """What the customer actually wrote: drops the quoted previous email that mail programs add to replies."""
    lines = (text or "").splitlines()
    cut = len(lines)
    for i in range(len(lines)):
        # a quote header can be wrapped over two or three lines ("On Mon, 23 Nov ... <x@y>\nwrote:")
        for span in (1, 2, 3):
            chunk = " ".join(lines[i:i + span])
            if QUOTE_HEADER_RE.match(chunk):
                cut = i
                break
        if cut != len(lines):
            break
        # Outlook-style header block: "From: ..." followed by "Sent:" / "Date:" within two lines
        if re.match(r"^\s*(From|Van):\s", lines[i]) and any(re.match(r"^\s*(Sent|Date|Verzonden|Datum):\s", x) for x in lines[i + 1:i + 3]):
            cut = i
            break
    kept = lines[:cut]
    while kept and (kept[-1].lstrip().startswith(">") or not kept[-1].strip()):  # a trailing "> ..." block
        kept.pop()
    result = "\n".join(kept).strip()
    # an email that only quotes an earlier one: say so (the quote stays available as the full text)
    return result or ("(No new text: this email only quotes an earlier message.)" if (text or "").strip() else "")


def parse_inbound(raw):
    """The parts of a raw RFC 5322 email the support inbox needs."""
    from email import policy
    from email.parser import BytesParser
    from email.utils import getaddresses, parseaddr

    msg = BytesParser(policy=policy.default).parsebytes(raw)
    name, addr = parseaddr(str(msg.get("Reply-To") or msg.get("From") or ""))
    if not addr:
        name, addr = parseaddr(str(msg.get("From") or ""))
    body = msg.get_body(preferencelist=("plain", "html"))
    text = ""
    if body is not None:
        try:
            content = body.get_content()
        except (LookupError, ValueError):
            content = body.get_payload(decode=True).decode("utf-8", "replace")
        text = html_to_text(content) if body.get_content_type() == "text/html" else content
    attachments = []
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True) or b""
        attachments.append((part.get_filename() or "attachment", part.get_content_type(), data))
    refs = re.findall(r"<[^<>\s]+>", f"{msg.get('In-Reply-To', '')} {msg.get('References', '')}")
    auto = (str(msg.get("Auto-Submitted", "no")).lower() != "no" or msg.get("X-Autoreply")
            or str(msg.get("Precedence", "")).lower() in ("bulk", "junk", "auto_reply"))
    full = redact(text.strip()[:200_000])
    return {"name": name.strip()[:100] or None, "email": addr.strip().lower()[:254], "subject": str(msg.get("Subject") or "")[:300],
            "body": strip_quoted(full), "body_full": full, "message_id": str(msg.get("Message-ID") or "").strip()[:300] or None,
            "refs": refs, "attachments": attachments, "auto": bool(auto),
            "to": [a for _, a in getaddresses([str(msg.get("To") or "")])]}


def store_message(con, *, email, name, subject, body, source, message_id=None, refs=(), attachments=(), body_full=None,
                  thread_id=None):
    """Add a customer message to the right conversation; returns (thread_id, message row id)."""
    now = int(time.time())
    thread = {"thread_id": thread_id} if thread_id else None
    if refs and not thread:  # a reply to a message in a conversation we know joins it; anything else starts a new one
        marks = ",".join("?" * len(refs))
        thread = con.execute(f"""SELECT m.thread_id FROM support_messages m JOIN support_threads t ON t.id = m.thread_id
                                 WHERE m.message_id IN ({marks}) AND t.email = ? ORDER BY m.id DESC LIMIT 1""",
                             [*refs, email]).fetchone()
    if thread:
        tid = thread["thread_id"]
        con.execute("UPDATE support_threads SET status='open', unread=1, updated=?, name=COALESCE(name, ?) WHERE id=?",
                    (now, name, tid))
    else:
        tid = con.execute("INSERT INTO support_threads(email, name, subject, created, updated) VALUES (?,?,?,?,?)",
                          (email, name, subject or "(no subject)", now, now)).lastrowid
    body = redact(body)
    full = redact(body_full) if body_full and redact(body_full) != body else None
    mid = con.execute("INSERT INTO support_messages(thread_id, direction, source, from_addr, subject, body, body_full, message_id, created)"
                      " VALUES (?,?,?,?,?,?,?,?,?)", (tid, "in", source, email, subject, body, full, message_id, now)).lastrowid
    save_attachments(con, mid, attachments)
    return tid, mid


def safe_filename(filename):
    return re.sub(r"[^A-Za-z0-9._ -]", "_", filename or "")[:120].strip(". ") or "attachment"


def save_attachments(con, mid, attachments):
    """Keep a message's files on disk (too-big ones are only listed). Returns the ones kept."""
    kept = []
    for filename, ctype, data in attachments:
        safe = safe_filename(filename)
        path = None
        if len(data) <= MAX_ATTACHMENT_BYTES:
            folder = SUPPORT_DIR / str(mid)
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / f"{secrets.token_hex(4)}-{safe}"
            target.write_bytes(data)
            path = str(target)
            kept.append((safe, ctype, data))
        con.execute("INSERT INTO support_attachments(message_id, filename, content_type, size, path) VALUES (?,?,?,?,?)",
                    (mid, safe, ctype, len(data), path))
    return kept


def decode_uploads(files):
    """Files sent from the account or admin page: [{"name", "type", "data" (base64)}] -> [(name, type, bytes)].

    Raises ValueError with a message for the person when something is wrong."""
    import base64
    import binascii
    if not files:
        return []
    if not isinstance(files, list) or len(files) > MAX_UPLOAD_FILES:
        raise ValueError(f"You can attach up to {MAX_UPLOAD_FILES} files.")
    out, total = [], 0
    for f in files:
        if not isinstance(f, dict):
            raise ValueError("bad request")
        try:
            data = base64.b64decode(str(f.get("data") or ""), validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("A file couldn't be read. Please try again.") from None
        name = safe_filename(str(f.get("name") or ""))
        if len(data) > MAX_ATTACHMENT_BYTES:
            raise ValueError(f"{name} is too big: each file can be up to {MAX_ATTACHMENT_BYTES // 1024 // 1024} MB.")
        total += len(data)
        ctype = str(f.get("type") or "")[:100]
        out.append((name, ctype if re.fullmatch(r"[\w.+-]+/[\w.+-]+", ctype) else "application/octet-stream", data))
    if total > MAX_UPLOAD_TOTAL:
        raise ValueError(f"The files are too big together: up to {MAX_UPLOAD_TOTAL // 1024 // 1024} MB per message.")
    return out


def thread_code(tid):
    """Secret per-conversation code for notification subjects, e.g. "12-k3f9a2c1".

    Replying to a notification sends the reply to the customer, but only if the subject still carries
    the right code: anyone can fake a From address, nobody else knows the code.
    """
    import hmac
    key = (INBOUND_SECRET or "no-secret").encode()
    return f"{tid}-{hmac.new(key, f'thread:{tid}'.encode(), hashlib.sha256).hexdigest()[:8]}"


THREAD_CODE_RE = re.compile(r"\[#(\d+)-([0-9a-f]{8})\]")


def notify_admin(tid, who, subject, body, attachments=()):
    """Short heads-up to the owner's normal inbox, with the customer's files attached.
    Replying to it answers the customer (see inbound_email)."""
    if not ADMIN_NOTIFY:
        return
    preview = body.strip()
    if len(preview) > 1500:
        preview = preview[:1500].rstrip() + "…"
    files = [(safe_filename(n), c, d) for n, c, d in attachments if len(d) <= MAX_ATTACHMENT_BYTES]
    if sum(len(d) for _, _, d in files) > MAX_UPLOAD_TOTAL:  # keep the notification deliverable
        files = []
    names = ", ".join(safe_filename(a[0]) for a in attachments)
    note = (f"Attachments: {names}" + ("" if len(files) == len(attachments) else " (download them from the admin page)") + "\n\n"
            if attachments else "")
    try:
        send_mail(ADMIN_NOTIFY, f"[#{thread_code(tid)}] {who}: {subject or '(no subject)'}"[:200],
                  f"{who} wrote:\n\n{preview}\n\n{note}"
                  "———\n"
                  "Reply to this email to answer them: your reply is sent from support@3vee.app and saved in the conversation.\n"
                  "Keep the [#…] code in the subject line, it tells the server which conversation it belongs to.\n"
                  f"Or answer in the admin page: {ADMIN_URL}#support/{tid}\n",
                  {"Auto-Submitted": "auto-generated"}, files)
    except Exception as e:  # noqa: BLE001 - a failed notification must not lose the message
        sys.stderr.write(f"admin notification failed: {e!r}\n")


def send_reply(tid, text, attachments=()):
    """Email our reply (and any files) to the customer from support@, continuing their thread, and store it."""
    from email.utils import make_msgid

    with _db_lock, db() as con:
        t = con.execute("SELECT * FROM support_threads WHERE id=?", (tid,)).fetchone()
        if not t:
            return None
        ids = [r[0] for r in con.execute("SELECT message_id FROM support_messages WHERE thread_id=? AND message_id IS NOT NULL ORDER BY id",
                                         (tid,))]
    subject = t["subject"] if (t["subject"] or "").lower().startswith("re:") else f"Re: {t['subject']}"
    msgid = make_msgid(domain=urlsplit(BASE_URL).hostname or "3vee.app")
    files = [(safe_filename(n), c, d) for n, c, d in attachments if len(d) <= MAX_ATTACHMENT_BYTES]
    send_mail(t["email"], subject, text, {"Message-ID": msgid, "In-Reply-To": ids[-1] if ids else None,
                                          "References": " ".join(ids[-10:]) or None}, files)
    now = int(time.time())
    with _db_lock, db() as con:
        mid = con.execute("INSERT INTO support_messages(thread_id, direction, source, from_addr, subject, body, message_id, created)"
                          " VALUES (?,?,?,?,?,?,?,?)", (tid, "out", "admin", MAIL_FROM, subject, text, msgid, now)).lastrowid
        save_attachments(con, mid, files)
        con.execute("UPDATE support_threads SET unread=0, updated=? WHERE id=?", (now, tid))
    return msgid


# --- public site ---------------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "beta"
    static_dir = None  # set by --static for local testing

    # -- helpers ---------------------------------------------------------------------------------
    def client_ip(self):
        return self.headers.get("CF-Connecting-IP") or self.client_address[0]

    def send_json(self, code, body, cookie=None):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, code, text):
        data = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_page(self, code, title, body_html):
        data = PAGE.format(title=title, body=body_html).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, f, platform):
        self.send_response(200)
        self.send_header("Content-Disposition", f'attachment; filename="{f.name}"')
        self.send_header("Cache-Control", "no-store")
        if ACCEL:
            self.send_header("X-Accel-Redirect", f"/_beta_files/{platform}/{f.name}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(f.stat().st_size))
        self.end_headers()
        with f.open("rb") as fh:
            while chunk := fh.read(1 << 16):
                self.wfile.write(chunk)

    def read_json(self, limit=2048):
        length = int(self.headers.get("Content-Length", "0"))
        if length > limit:
            raise ValueError
        body = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(body, dict):
            raise ValueError
        return body

    def same_origin(self):
        """Cookie-authenticated POSTs must come from this site (the cookie is also SameSite=Lax)."""
        origin = self.headers.get("Origin")
        return not origin or urlsplit(origin).netloc == self.headers.get("Host")

    def session_cookie(self, value, max_age):
        parts = [f"{COOKIE}={value}", "Path=/", "HttpOnly", "SameSite=Lax", f"Max-Age={max_age}"]
        if SECURE_COOKIE:
            parts.append("Secure")
        return "; ".join(parts)

    def current_user(self):
        """The signed-in account for this request, or None."""
        try:
            jar = SimpleCookie(self.headers.get("Cookie") or "")
        except CookieError:
            return None
        if COOKIE not in jar:
            return None
        now = int(time.time())
        with _db_lock, db() as con:
            row = con.execute("""SELECT u.*, s.hash AS session FROM sessions s JOIN users u ON u.id = s.user_id
                                 WHERE s.hash = ? AND s.expires > ?""", (sha(jar[COOKIE].value), now)).fetchone()
            if row:
                con.execute("UPDATE sessions SET last_seen=? WHERE hash=?", (now, row["session"]))
        return row

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.client_ip()} {fmt % args}\n")

    # -- routes ----------------------------------------------------------------------------------
    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/api/beta/signup":
            return self.signup()
        if path == "/api/login":
            return self.request_login()
        if path == "/api/logout":
            return self.logout()
        if path == "/api/inbound-email":
            return self.inbound_email()
        if path == "/api/tips":
            return self.put_tips()
        if path == "/api/support":
            return self.support_form()
        if path.startswith("/api/account/download/"):
            return self.account_download(path.rsplit("/", 1)[-1])
        if path.startswith("/login/"):
            return self.login(path[len("/login/"):], sign_in=True)
        if path.startswith("/download/"):
            return self.link_download(path[len("/download/"):], fetch=True)
        return self.send_json(404, {"error": "not found"})

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/login/"):
            return self.login(path[len("/login/"):])
        if path == "/api/account":
            return self.account()
        if path == "/api/support":
            return self.support_conversations()
        if path.startswith("/api/support/attachment/"):
            return self.my_attachment(path.rsplit("/", 1)[-1])
        if path.startswith("/download/"):
            return self.link_download(path[len("/download/"):])
        if path == "/api/health":
            return self.send_json(200, {"ok": True})
        if path == "/api/tips":
            return self.get_tips()
        if self.static_dir:
            return self.static(path)
        return self.send_text(404, "Not found")

    # -- the program's tooltips ------------------------------------------------------------------
    def get_tips(self):
        query = dict(p.split("=", 1) for p in (urlsplit(self.path).query or "").split("&") if "=" in p)
        try:
            note_tips_fetch(self.client_ip(), unquote(query.get("build", "")), geo(self.headers)[0])
        except sqlite3.Error:
            pass  # counting never stops the tips going out
        try:
            data = TIPS_PATH.read_bytes()
        except OSError:
            return self.send_json(404, {"error": "no tips yet"})
        tag = '"' + hashlib.sha256(data).hexdigest()[:32] + '"'
        if self.headers.get("If-None-Match") == tag:
            self.send_response(304)
            self.send_header("ETag", tag)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("ETag", tag)
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def put_tips(self):
        import hmac
        auth = self.headers.get("Authorization", "")
        if not TIPS_SECRET or not hmac.compare_digest(auth.encode(), f"Bearer {TIPS_SECRET}".encode()):
            return self.send_json(403, {"error": "forbidden"})
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_TIPS_BYTES:
            return self.send_json(413, {"error": "too big"})
        data = self.rfile.read(length)
        try:
            tips = json.loads(data)
            rows = tips.get("tips") if isinstance(tips, dict) else None
            if not isinstance(rows, list) or not all(isinstance(r, dict) and isinstance(r.get("id"), str) for r in rows):
                raise ValueError
        except ValueError:
            return self.send_json(400, {"error": "not a tips file"})
        TIPS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = TIPS_PATH.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, TIPS_PATH)
        return self.send_json(200, {"ok": True, "tips": len(rows)})

    # -- sign-up and sign-in ---------------------------------------------------------------------
    def signup(self):
        try:
            body = self.read_json()
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
            by_ip = con.execute("SELECT COUNT(*) FROM signups WHERE ip=? AND created>?", (ip, now - 3600)).fetchone()[0]
            by_email = con.execute("SELECT COUNT(*) FROM signups WHERE lower(email)=lower(?) AND created>?",
                                   (email, now - 86400)).fetchone()[0]
            if by_ip >= PER_IP_PER_HOUR or by_email >= PER_EMAIL_PER_DAY:
                return self.send_json(429, {"error": "Too many requests. Try again later."})
            con.execute("INSERT INTO users(email, name, platform, created) VALUES (lower(?),?,?,?) "
                        "ON CONFLICT(email) DO UPDATE SET platform=excluded.platform, name=COALESCE(excluded.name, users.name)",
                        (email, person or None, platform, now))
            user = con.execute("SELECT id, name FROM users WHERE email=lower(?)", (email,)).fetchone()
            # the sign-up row keeps the history (and the rate limits); its token is no longer emailed
            con.execute("INSERT INTO signups(email, name, platform, token, ip, created, country, region, city)"
                        " VALUES (?,?,?,?,?,?,?,?,?)",
                        (email, person or None, platform, secrets.token_urlsafe(24), ip, now, *geo(self.headers)))
            signup_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
            token = new_login_link(con, user["id"], ip)
        try:
            send_mail(email, *signup_mail(person or user["name"], platform, f"{BASE_URL}/login/{token}"))
        except Exception as e:  # noqa: BLE001 - report any mail failure the same way
            sys.stderr.write(f"mail to {email} failed: {e!r}\n")
            return self.send_json(502, {"error": "Couldn't send the email. Try again in a minute."})
        with _db_lock, db() as con:
            con.execute("UPDATE signups SET mailed=1 WHERE id=?", (signup_id,))
            con.execute("UPDATE login_links SET mailed=1 WHERE hash=?", (sha(token),))
        return self.send_json(200, {"ok": True})

    def request_login(self):
        """Email a sign-in link to an existing account. The reply never says whether the account exists."""
        try:
            email = str(self.read_json().get("email", "")).strip()
        except (ValueError, json.JSONDecodeError):
            return self.send_json(400, {"error": "bad request"})
        if len(email) > 254 or not EMAIL_RE.match(email):
            return self.send_json(400, {"error": "That email address doesn't look right."})
        ip, now = self.client_ip(), int(time.time())
        with _db_lock, db() as con:
            by_ip = con.execute("SELECT COUNT(*) FROM login_links WHERE ip=? AND created>?", (ip, now - 3600)).fetchone()[0]
            if by_ip >= PER_IP_PER_HOUR * 2:
                return self.send_json(429, {"error": "Too many requests. Try again later."})
            user = con.execute("SELECT id, name FROM users WHERE email=lower(?)", (email,)).fetchone()
            token = None
            if user:
                recent = con.execute("SELECT COUNT(*) FROM login_links WHERE user_id=? AND created>?",
                                     (user["id"], now - 3600)).fetchone()[0]
                if recent < PER_EMAIL_PER_DAY:
                    token = new_login_link(con, user["id"], ip)
        if token:
            try:
                send_mail(email, *login_mail(user["name"], f"{BASE_URL}/login/{token}"))
                with _db_lock, db() as con:
                    con.execute("UPDATE login_links SET mailed=1 WHERE hash=?", (sha(token),))
            except Exception as e:  # noqa: BLE001
                sys.stderr.write(f"login mail to {email} failed: {e!r}\n")
                return self.send_json(502, {"error": "Couldn't send the email. Try again in a minute."})
        return self.send_json(200, {"ok": True})

    def login(self, token, sign_in=False):
        """GET: a page with a Sign in button. POST (the button): uses the link once and starts a session."""
        again = '<p><a class="btn" href="/account/">Send me a new link</a></p>'
        bad = ("<h1>This sign-in link isn't valid.</h1><p>Check that you used the whole link from the email.</p>" + again)
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,64}", token):
            return self.send_page(404, "Link not valid", bad)
        now = int(time.time())
        with _db_lock, db() as con:
            link = con.execute("SELECT * FROM login_links WHERE hash=?", (sha(token),)).fetchone()
            if not link:
                return self.send_page(404, "Link not valid", bad)
            if link["used"]:
                return self.send_page(410, "Link already used", "<h1>This sign-in link has already been used.</h1>"
                                      "<p>Each link works once. Ask for a new one, it only takes a moment.</p>" + again)
            if now - link["created"] > LOGIN_LINK_HOURS * 3600:
                return self.send_page(410, "Link expired", "<h1>This sign-in link has expired.</h1>"
                                      f"<p>Links work for {LOGIN_LINK_HOURS} hours. Ask for a new one.</p>" + again)
            if not sign_in:
                return self.send_page(200, "Sign in", f"<h1>Sign in to {LOGO}</h1>"
                                      '<form method="post"><button class="btn" type="submit">Sign in</button></form>'
                                      "<p class='small'>Then you can download the beta from your account.</p>")
            value = secrets.token_urlsafe(32)
            con.execute("UPDATE login_links SET used=? WHERE hash=?", (now, link["hash"]))
            con.execute("INSERT INTO sessions(hash, user_id, created, expires, last_seen, ip) VALUES (?,?,?,?,?,?)",
                        (sha(value), link["user_id"], now, now + SESSION_DAYS * 86400, now, self.client_ip()))
            con.execute("UPDATE users SET last_login=?, logins=logins+1 WHERE id=?", (now, link["user_id"]))
            con.execute("DELETE FROM sessions WHERE expires < ?", (now,))
        self.send_response(303)
        self.send_header("Location", "/account/")
        self.send_header("Set-Cookie", self.session_cookie(value, SESSION_DAYS * 86400))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def logout(self):
        if not self.same_origin():
            return self.send_json(403, {"error": "forbidden"})
        user = self.current_user()
        if user:
            with _db_lock, db() as con:
                con.execute("DELETE FROM sessions WHERE hash=?", (user["session"],))
        return self.send_json(200, {"ok": True}, cookie=self.session_cookie("", 0))

    # -- support ---------------------------------------------------------------------------------
    def inbound_email(self):
        """An email to support@, handed over by the Cloudflare Email Worker (raw message in the body)."""
        import hmac
        auth = self.headers.get("Authorization", "")
        if not INBOUND_SECRET or not hmac.compare_digest(auth.encode(), f"Bearer {INBOUND_SECRET}".encode()):
            return self.send_json(401, {"error": "unauthorized"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 < length <= MAX_INBOUND_BYTES:
            return self.send_json(413, {"error": "too large"})
        raw = self.rfile.read(length)
        try:
            m = parse_inbound(raw)
        except Exception as e:  # noqa: BLE001 - unparseable mail: let the Worker fall back to Gmail
            sys.stderr.write(f"inbound email parse failed: {e!r}\n")
            return self.send_json(422, {"error": "unparseable"})
        own = re.sub(r".*<|>.*", "", MAIL_FROM).lower()
        if not m["email"] or m["email"] == own:  # nothing to reply to, or our own mail looping back
            return self.send_json(200, {"ok": True, "stored": False})

        # The owner replying to a notification: send it to the customer as our reply. Requires both the
        # owner's address AND the secret conversation code from the notification's subject.
        code = THREAD_CODE_RE.search(m["subject"])
        if code and ADMIN_NOTIFY and m["email"] == ADMIN_NOTIFY.lower():
            import hmac
            tid = int(code.group(1))
            if not hmac.compare_digest(f"{code.group(1)}-{code.group(2)}", thread_code(tid)):
                sys.stderr.write(f"admin email reply with a wrong code for thread {tid}: ignored\n")
                return self.send_json(200, {"ok": True, "stored": False})
            text = m["body"]
            if not text or text.startswith("(No new text"):
                text = ""
            if not text and not m["attachments"]:
                return self.send_json(200, {"ok": True, "stored": False})
            try:
                if not send_reply(tid, text, m["attachments"]):
                    raise LookupError("conversation not found (deleted?)")
            except Exception as e:  # noqa: BLE001 - tell the owner instead of failing silently
                sys.stderr.write(f"admin email reply for thread {tid} failed: {e!r}\n")
                try:
                    send_mail(ADMIN_NOTIFY, f"Your reply wasn't sent: {m['subject']}"[:200],
                              f"Your reply couldn't be delivered to the customer ({e}).\n"
                              f"Please answer in the admin page instead: {ADMIN_URL}#support/{tid}\n",
                              {"Auto-Submitted": "auto-generated"})
                except Exception:  # noqa: BLE001
                    pass
            return self.send_json(200, {"ok": True, "stored": True, "as": "admin-reply"})
        with _db_lock, db() as con:
            dup = m["message_id"] and con.execute("SELECT 1 FROM support_messages WHERE message_id=?", (m["message_id"],)).fetchone()
            if dup:  # the Worker retried something we already have
                return self.send_json(200, {"ok": True, "stored": False})
            tid, _ = store_message(con, email=m["email"], name=m["name"], subject=m["subject"], body=m["body"], body_full=m["body_full"],
                                   source="email", message_id=m["message_id"], refs=m["refs"], attachments=m["attachments"])
        if not m["auto"]:
            notify_admin(tid, m["name"] or m["email"], m["subject"], m["body"], m["attachments"])
        return self.send_json(200, {"ok": True, "stored": True})

    def support_form(self):
        """A message from the Support tab of a signed-in account."""
        if not self.same_origin():
            return self.send_json(403, {"error": "forbidden"})
        user = self.current_user()
        if not user:
            return self.send_json(401, {"error": "Please sign in again."})
        try:
            body = self.read_json(limit=MAX_UPLOAD_REQUEST)
            subject = " ".join(str(body.get("subject") or "").split())[:200]
            message = str(body.get("message") or "").strip()[:20_000]
            thread_id = int(body["thread_id"]) if body.get("thread_id") else None
        except (ValueError, TypeError, json.JSONDecodeError):
            return self.send_json(400, {"error": "Couldn't send that (are the files too big?)."})
        try:
            files = decode_uploads(body.get("files"))
        except ValueError as e:
            return self.send_json(400, {"error": str(e)})
        if len(message) < 2 and not files:
            return self.send_json(400, {"error": "Please write a message."})
        now = int(time.time())
        with _db_lock, db() as con:
            recent = con.execute("""SELECT COUNT(*) FROM support_messages m JOIN support_threads t ON t.id = m.thread_id
                                    WHERE t.email=? AND m.direction='in' AND m.created>?""", (user["email"], now - 3600)).fetchone()[0]
            if recent >= 10:
                return self.send_json(429, {"error": "That's a lot of messages in a short time. Please try again later."})
            if thread_id:  # a reply in one of their own conversations
                t = con.execute("SELECT subject FROM support_threads WHERE id=? AND email=?", (thread_id, user["email"])).fetchone()
                if not t:
                    return self.send_json(404, {"error": "Conversation not found."})
                subject = t["subject"]
                tid, _ = store_message(con, email=user["email"], name=user["name"], subject=subject, body=message,
                                       source="form", thread_id=thread_id, attachments=files)
            else:
                platform = PLATFORMS.get(user["platform"] or "", "")
                subject = subject or "Message from the account page"
                tid, _ = store_message(con, email=user["email"], name=user["name"], subject=subject,
                                       body=message + (f"\n\n(Platform: {platform})" if platform else ""), source="form",
                                       attachments=files)
        notify_admin(tid, user["name"] or user["email"], subject, message, files)
        return self.send_json(200, {"ok": True, "conversations": self.my_conversations(user)})

    def my_conversations(self, user):
        """The signed-in person's support conversations, with all messages (both directions)."""
        with _db_lock, db() as con:
            threads = [dict(t) for t in con.execute(
                "SELECT id, subject, status, created, updated FROM support_threads WHERE email=? ORDER BY updated DESC", (user["email"],))]
            for t in threads:
                atts = {}
                for a in con.execute("""SELECT a.id, a.message_id, a.filename, a.size, a.path IS NOT NULL AS kept
                                        FROM support_attachments a JOIN support_messages m ON m.id = a.message_id
                                        WHERE m.thread_id=? ORDER BY a.id""", (t["id"],)):
                    atts.setdefault(a["message_id"], []).append({k: a[k] for k in ("id", "filename", "size", "kept")})
                t["messages"] = [{"direction": m["direction"], "source": m["source"], "created": m["created"],
                                  "body": re.sub(r"\n\n\(Platform: [^)]*\)$", "", m["body"] or ""),
                                  "attachments": atts.get(m["id"], [])} for m in con.execute(
                    "SELECT id, direction, source, body, created FROM support_messages WHERE thread_id=? ORDER BY id", (t["id"],))]
        return threads

    def my_attachment(self, aid):
        """A file from one of the signed-in person's own conversations (always a download, never shown inline)."""
        user = self.current_user()
        if not user:
            return self.send_text(401, "Please sign in again.")
        if not aid.isdigit():
            return self.send_text(404, "Not found")
        with _db_lock, db() as con:
            a = con.execute("""SELECT a.filename, a.path FROM support_attachments a JOIN support_messages m ON m.id = a.message_id
                               JOIN support_threads t ON t.id = m.thread_id WHERE a.id=? AND t.email=?""",
                            (int(aid), user["email"])).fetchone()
        if not a or not a["path"] or not Path(a["path"]).is_file():
            return self.send_text(404, "Not found")
        path = Path(a["path"])
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{safe_filename(a["filename"])}"')
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Content-Length", str(path.stat().st_size))
        self.end_headers()
        with path.open("rb") as fh:
            while chunk := fh.read(1 << 16):
                self.wfile.write(chunk)

    def support_conversations(self):
        user = self.current_user()
        if not user:
            return self.send_json(401, {"error": "not signed in"})
        return self.send_json(200, {"conversations": self.my_conversations(user)})

    # -- account ---------------------------------------------------------------------------------
    def account(self):
        user = self.current_user()
        if not user:
            return self.send_json(401, {"error": "not signed in"})
        builds = {}
        for key, label in PLATFORMS.items():
            f = newest_file(key)
            released = int(f.stat().st_mtime) if f else None
            builds[key] = {"label": label, "file": f.name if f else None, "size": f.stat().st_size if f else None,
                           "released": released, "expires": released + BUILD_DAYS * 86400 if f else None}
        return self.send_json(200, {"email": user["email"], "name": user["name"], "platform": user["platform"],
                                    "member_since": user["created"], "builds": builds})

    def account_download(self, platform):
        if not self.same_origin():
            return self.send_json(403, {"error": "forbidden"})
        user = self.current_user()
        if not user:
            self.send_response(303)
            self.send_header("Location", "/account/")
            self.send_header("Content-Length", "0")
            return self.end_headers()
        if platform not in PLATFORMS:
            return self.send_text(404, "Not found")
        f = newest_file(platform)
        if not f:
            return self.send_page(404, "Not available yet", f"<h1>The {PLATFORMS[platform]} build isn't available yet.</h1>"
                                  "<p><a class='btn' href='/account/'>Back to your account</a></p>")
        with _db_lock, db() as con:
            con.execute("INSERT INTO downloads(token, file, ip, at, country, region, city, platform, user_id)"
                        " VALUES ('',?,?,?,?,?,?,?,?)",
                        (f.name, self.client_ip(), int(time.time()), *geo(self.headers), platform, user["id"]))
        return self.send_file(f, platform)

    # -- old personal download links (emailed before accounts existed) ----------------------------
    def link_download(self, token, fetch=False):
        get_own = '<p><a class="btn" href="/account/">Sign in to download</a></p>'
        bad = "<h1>This download link isn't valid.</h1><p>Check that you copied the whole link from the email.</p>" + get_own
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,64}", token):
            return self.send_page(404, "Link not valid", bad)
        with _db_lock, db() as con:
            row = con.execute("""SELECT s.platform, s.created, u.id AS user_id FROM signups s
                                 LEFT JOIN users u ON u.email = lower(s.email) WHERE s.token=?""", (token,)).fetchone()
            if not row:
                return self.send_page(404, "Link not valid", bad)
            used = con.execute("SELECT COUNT(*) FROM downloads WHERE token=?", (token,)).fetchone()[0]
            name = PLATFORMS[row["platform"]]
            if time.time() - row["created"] > TOKEN_DAYS * 86400:
                return self.send_page(410, "Link expired", "<h1>This download link has expired.</h1>"
                                      "<p>You can download the beta from your account instead.</p>" + get_own)
            if used >= MAX_USES:
                return self.send_page(410, "Link used up", "<h1>This download link has already been used.</h1>"
                                      f"<p>Each link works {MAX_USES} times. Sign in to download again, or "
                                      "<a href='/masterdaw/' style='color:#FF8A4C'>get your own</a> if this wasn't yours.</p>" + get_own)
            f = newest_file(row["platform"])
            if not f:
                return self.send_page(404, "Not available yet", f"<h1>The {name} build isn't available yet.</h1>"
                                      "<p>We'll email you when it is.</p>")
            if not fetch:
                left = MAX_USES - used
                return self.send_page(200, f"Download for {name}",
                                      f"<h1>Download {LOGO} beta</h1><p class='for'>for {name}</p>"
                                      '<form method="post"><button class="btn" type="submit">Download</button></form>'
                                      f"<p class='small'>This link can be used {left}{' more' if used else ''} "
                                      f"{'time' if left == 1 else 'times'}. It's personal, please don't share it.</p>")
            # counted inside the lock, so two clicks at once can't both get the last use
            con.execute("INSERT INTO downloads(token, file, ip, at, country, region, city, platform, user_id)"
                        " VALUES (?,?,?,?,?,?,?,?,?)",
                        (token, f.name, self.client_ip(), int(time.time()), *geo(self.headers), row["platform"], row["user_id"]))
        return self.send_file(f, row["platform"])

    # -- local testing ---------------------------------------------------------------------------
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


# --- admin ---------------------------------------------------------------------------------------

ADMIN_PAGE = ROOT / "admin.html"
# who may open the admin page: this machine and the Tailscale network (CGNAT range)
ADMIN_NETS = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128", "100.64.0.0/10", "fd7a:115c:a1e0::/48")]


def admin_data():
    with _db_lock, db() as con:
        users = [dict(r) for r in con.execute("SELECT * FROM users ORDER BY created DESC")]
        signups = [dict(r) for r in con.execute("SELECT * FROM signups ORDER BY created")]
        downloads = [dict(r) for r in con.execute("SELECT * FROM downloads ORDER BY at")]
    by_email, by_user, link_uses = {}, {}, {}
    for s in signups:
        by_email.setdefault(s["email"].lower(), []).append(s)
    for d in downloads:
        by_user.setdefault(d["user_id"], []).append(d)
        if d["token"]:
            link_uses[d["token"]] = link_uses.get(d["token"], 0) + 1

    people = []
    for u in users:
        mine, dls = by_email.get(u["email"], []), by_user.get(u["id"], [])
        located = [x for x in reversed(mine) if x["country"]] or [x for x in reversed(dls) if x["country"]]
        loc = located[0] if located else {}
        people.append({
            "email": u["email"], "name": u["name"], "created": u["created"],
            "platforms": sorted({s["platform"] for s in mine} | ({u["platform"]} if u["platform"] else set()),
                                key=list(PLATFORMS).index),
            "signups": len(mine), "mailed": any(s["mailed"] for s in mine),
            "last_login": u["last_login"], "logins": u["logins"],
            "country": loc.get("country"), "region": loc.get("region"), "city": loc.get("city"),
            "downloads": len(dls),
            "first_download": dls[0]["at"] if dls else None,
            "download_log": [{"at": d["at"], "platform": d["platform"], "file": d["file"], "via": "link" if d["token"] else "account",
                              "country": d["country"], "city": d["city"]} for d in dls],
            # an old emailed download link that has been used all MAX_USES times
            "link_used_up": any(link_uses.get(s["token"], 0) >= MAX_USES for s in mine),
        })

    platforms = {}
    for key, label in PLATFORMS.items():
        asked = [p for p in people if key in p["platforms"]]
        platforms[key] = {
            "label": label,
            "signups": len(asked),
            "emailed": sum(1 for p in asked if p["mailed"]),
            "downloaded": sum(1 for p in people if any(d["platform"] == key for d in p["download_log"])),
            "downloads": sum(1 for p in people for d in p["download_log"] if d["platform"] == key),
        }
    countries = {}
    for p in people:
        c = countries.setdefault(p["country"], {"people": 0, "downloaded": 0})
        c["people"] += 1
        c["downloaded"] += 1 if p["downloads"] else 0
    by_country = sorted(({"country": k, **v} for k, v in countries.items()),
                        key=lambda c: (c["country"] is None, -c["people"], c["country"] or ""))
    return {"generated": int(time.time()), "max_uses": MAX_USES, "platforms": platforms,
            "countries": by_country, "people": people, "running": running_data()}


def support_list():
    with _db_lock, db() as con:
        rows = con.execute("""
            SELECT t.*, (SELECT COUNT(*) FROM support_messages m WHERE m.thread_id = t.id) AS messages,
                   (SELECT body FROM support_messages m WHERE m.thread_id = t.id ORDER BY m.id DESC LIMIT 1) AS last_body,
                   (SELECT direction FROM support_messages m WHERE m.thread_id = t.id ORDER BY m.id DESC LIMIT 1) AS last_dir,
                   (SELECT 1 FROM users u WHERE u.email = t.email) AS has_account
            FROM support_threads t ORDER BY t.unread DESC, t.updated DESC""").fetchall()
    return {"threads": [{**dict(r), "last_body": " ".join((r["last_body"] or "").split())[:160]} for r in rows]}


def support_thread(tid, mark_read=True):
    with _db_lock, db() as con:
        t = con.execute("SELECT * FROM support_threads WHERE id=?", (tid,)).fetchone()
        if not t:
            return None
        msgs = [dict(m) for m in con.execute("SELECT * FROM support_messages WHERE thread_id=? ORDER BY id", (tid,))]
        atts = {}
        for a in con.execute("""SELECT a.id, a.message_id, a.filename, a.size, a.path IS NOT NULL AS kept FROM support_attachments a
                                JOIN support_messages m ON m.id = a.message_id WHERE m.thread_id=?""", (tid,)):
            atts.setdefault(a["message_id"], []).append(dict(a))
        user = con.execute("SELECT email, name, platform, created, last_login FROM users WHERE email=?", (t["email"],)).fetchone()
        dls = con.execute("SELECT COUNT(*) FROM downloads d JOIN users u ON u.id = d.user_id WHERE u.email=?", (t["email"],)).fetchone()[0]
        if mark_read and t["unread"]:
            con.execute("UPDATE support_threads SET unread=0 WHERE id=?", (tid,))
    for m in msgs:
        m["attachments"] = atts.get(m["id"], [])
    return {"thread": dict(t), "messages": msgs,
            "account": {**dict(user), "downloads": dls} if user else None}


def csv_cell(v):
    """Text for a CSV cell; neutralise leading =+-@ so spreadsheets don't run it as a formula."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def export_zip():
    """Everything the server stores, as one zip: CSVs for reading, the database for restoring."""
    import csv
    import io
    import tempfile
    import zipfile
    from datetime import datetime, timezone

    iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if t else ""  # noqa: E731
    with _db_lock, db() as con:
        users = con.execute("SELECT * FROM users ORDER BY id").fetchall()
        signups = con.execute("SELECT * FROM signups ORDER BY id").fetchall()
        downloads = con.execute("SELECT d.*, u.email FROM downloads d LEFT JOIN users u ON u.id = d.user_id ORDER BY d.id").fetchall()
        support = con.execute("SELECT m.*, t.email FROM support_messages m JOIN support_threads t ON t.id = m.thread_id ORDER BY m.id").fetchall()
        with tempfile.TemporaryDirectory() as tmp:
            snap = Path(tmp) / "beta.db"
            dest = sqlite3.connect(snap)
            con.backup(dest)  # consistent copy while the service keeps running
            dest.close()
            db_bytes = snap.read_bytes()

    def table(header, rows):
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(header)
        w.writerows([csv_cell(v) for v in r] for r in rows)
        return "﻿" + out.getvalue()  # BOM so Excel reads UTF-8 (city names)

    plat = lambda k: PLATFORMS.get(k, k or "")  # noqa: E731
    now = datetime.now(timezone.utc)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("people.csv", table(
            ["id", "email", "name", "platform", "account_created_utc", "last_login_utc", "logins"],
            [(u["id"], u["email"], u["name"], plat(u["platform"]), iso(u["created"]), iso(u["last_login"]), u["logins"])
             for u in users]))
        z.writestr("signups.csv", table(
            ["id", "signed_up_utc", "email", "name", "platform", "email_sent", "country", "region", "city", "ip"],
            [(s["id"], iso(s["created"]), s["email"], s["name"], plat(s["platform"]),
              "yes" if s["mailed"] else "no", s["country"], s["region"], s["city"], s["ip"]) for s in signups]))
        z.writestr("downloads.csv", table(
            ["id", "downloaded_utc", "email", "platform", "file", "via", "country", "region", "city", "ip"],
            [(d["id"], iso(d["at"]), d["email"], plat(d["platform"]), d["file"], "old link" if d["token"] else "account",
              d["country"], d["region"], d["city"], d["ip"]) for d in downloads]))
        z.writestr("support.csv", table(
            ["thread", "message", "when_utc", "customer", "direction", "via", "subject", "text"],
            [(m["thread_id"], m["id"], iso(m["created"]), m["email"], m["direction"], m["source"], m["subject"], m["body"])
             for m in support]))
        z.writestr("beta.db", db_bytes)
        z.writestr("README.txt",
                   f"MASTERDAW beta export, made {now:%Y-%m-%d %H:%M} UTC\n\n"
                   f"people.csv     {len(users)} accounts (email, name, last login)\n"
                   f"signups.csv    {len(signups)} sign-ups (email, name, platform, location, time)\n"
                   f"downloads.csv  {len(downloads)} downloads (who, which file, when, from where)\n"
                   "beta.db        the complete SQLite database, for restoring the server\n\n"
                   "Times are UTC. Locations are approximate (from the IP address via Cloudflare).\n"
                   "This file contains personal data: keep it private and delete copies you don't need.\n")
    return buf.getvalue(), f"masterdaw-beta-export-{now:%Y-%m-%d-%H%M}.zip"


def delete_people(emails):
    """Remove everything stored about these people: account, sessions, sign-in links, sign-ups and downloads.

    Matched case-insensitively, so a later sign-up with the same address counts as new (and the per-email
    rate limit starts from zero). Snapshots in the backups keep the old data until they expire.
    """
    emails = sorted({e.strip().lower() for e in emails if isinstance(e, str) and e.strip()})
    if not emails:
        return {"people": 0, "signups": 0, "downloads": 0}
    marks = ",".join("?" * len(emails))
    with _db_lock, db() as con:
        ids = [r[0] for r in con.execute(f"SELECT id FROM users WHERE email IN ({marks})", emails)]
        idm = ",".join("?" * len(ids)) or "NULL"
        dl = con.execute(f"DELETE FROM downloads WHERE user_id IN ({idm}) OR token IN "
                         f"(SELECT token FROM signups WHERE lower(email) IN ({marks}))", ids + emails).rowcount
        su = con.execute(f"DELETE FROM signups WHERE lower(email) IN ({marks})", emails).rowcount
        con.execute(f"DELETE FROM sessions WHERE user_id IN ({idm})", ids)
        con.execute(f"DELETE FROM login_links WHERE user_id IN ({idm})", ids)
        con.execute(f"DELETE FROM users WHERE id IN ({idm})", ids)
        # their support conversations, messages and attachment files
        tids = [r[0] for r in con.execute(f"SELECT id FROM support_threads WHERE email IN ({marks})", emails)]
        tm = ",".join("?" * len(tids)) or "NULL"
        files = [r[0] for r in con.execute(f"""SELECT a.path FROM support_attachments a JOIN support_messages m ON m.id = a.message_id
                                              WHERE m.thread_id IN ({tm}) AND a.path IS NOT NULL""", tids)]
        con.execute(f"DELETE FROM support_attachments WHERE message_id IN (SELECT id FROM support_messages WHERE thread_id IN ({tm}))", tids)
        con.execute(f"DELETE FROM support_messages WHERE thread_id IN ({tm})", tids)
        con.execute(f"DELETE FROM support_threads WHERE id IN ({tm})", tids)
    for f in files:
        try:
            Path(f).unlink()
            Path(f).parent.rmdir()
        except OSError:
            pass
    sys.stderr.write(f"admin deleted {len(emails)} people: {su} sign-ups, {dl} downloads\n")
    return {"people": len(emails), "signups": su, "downloads": dl}


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "beta-admin"
    send_json = Handler.send_json
    send_text = Handler.send_text

    def log_message(self, fmt, *args):
        sys.stderr.write(f"admin {self.client_address[0]} {fmt % args}\n")

    def allowed(self):
        try:
            ip = ipaddress.ip_address(self.client_address[0].removeprefix("::ffff:"))
        except ValueError:
            return False
        return any(ip in n for n in ADMIN_NETS)

    def do_POST(self):
        if not self.allowed():
            return self.send_text(403, "Forbidden")
        path = urlsplit(self.path).path
        # Only the admin page itself may change things: a custom header can't be sent by another site's page
        # without a CORS preflight (which this server never approves), and Origin must be this host.
        origin = self.headers.get("Origin")
        if not self.headers.get("X-Admin-Action") or (origin and urlsplit(origin).netloc != self.headers.get("Host")):
            return self.send_json(403, {"error": "forbidden"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_UPLOAD_REQUEST:
                raise ValueError
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, json.JSONDecodeError):
            return self.send_json(400, {"error": "bad request"})
        if path == "/admin/delete" and self.headers.get("X-Admin-Action") == "delete":
            emails = body.get("emails", [])
            if not isinstance(emails, list):
                return self.send_json(400, {"error": "bad request"})
            return self.send_json(200, delete_people(emails))
        m = re.fullmatch(r"/admin/support/(\d+)/(reply|status)", path)
        if m and self.headers.get("X-Admin-Action") == "support":
            tid = int(m.group(1))
            if m.group(2) == "reply":
                text = str(body.get("text") or "").strip()
                try:
                    files = decode_uploads(body.get("files"))
                except ValueError as e:
                    return self.send_json(400, {"error": str(e)})
                if not text and not files:
                    return self.send_json(400, {"error": "Write a reply first."})
                try:
                    if not send_reply(tid, text[:50_000], files):
                        return self.send_json(404, {"error": "not found"})
                except Exception as e:  # noqa: BLE001
                    sys.stderr.write(f"support reply failed: {e!r}\n")
                    return self.send_json(502, {"error": "Couldn't send the email. Nothing was saved; try again."})
                return self.send_json(200, support_thread(tid))
            status = body.get("status")
            if status not in ("open", "closed"):
                return self.send_json(400, {"error": "bad status"})
            with _db_lock, db() as con:
                con.execute("UPDATE support_threads SET status=? WHERE id=?", (status, tid))
            return self.send_json(200, {"ok": True})
        return self.send_json(404, {"error": "not found"})

    def do_GET(self):
        if not self.allowed():
            return self.send_text(403, "Forbidden")
        path = urlsplit(self.path).path.rstrip("/")
        if path in ("", "/admin"):
            data = ADMIN_PAGE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return self.wfile.write(data)
        if path == "/admin/data.json":
            return self.send_json(200, admin_data())
        if path == "/admin/support.json":
            return self.send_json(200, support_list())
        m = re.fullmatch(r"/admin/support/(\d+)\.json", path)
        if m:
            t = support_thread(int(m.group(1)))
            return self.send_json(200, t) if t else self.send_json(404, {"error": "not found"})
        m = re.fullmatch(r"/admin/support/attachment/(\d+)", path)
        if m:
            with _db_lock, db() as con:
                a = con.execute("SELECT filename, path FROM support_attachments WHERE id=?", (int(m.group(1)),)).fetchone()
            if not a or not a["path"] or not Path(a["path"]).is_file():
                return self.send_text(404, "Not found")
            data = Path(a["path"]).read_bytes()
            self.send_response(200)
            # always a download, never rendered in the admin page's origin
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{a["filename"]}"')
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        if path == "/admin/export.zip":
            data, name = export_zip()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return self.wfile.write(data)
        return self.send_text(404, "Not found")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--static", help="also serve this folder (local testing only)")
    ap.add_argument("--admin-host", default="127.0.0.1")
    ap.add_argument("--admin-port", type=int, help="serve the admin page on this port")
    args = ap.parse_args()
    Handler.static_dir = args.static
    init_db()
    print(f"beta server on http://{args.host}:{args.port}  db={DB_PATH}  files={FILES_DIR}"
          f"  mail={'smtp ' + SMTP_HOST if SMTP_HOST else 'console'}", flush=True)
    if args.admin_port:
        admin = ThreadingHTTPServer((args.admin_host, args.admin_port), AdminHandler)
        threading.Thread(target=admin.serve_forever, daemon=True).start()
        print(f"admin page on http://{args.admin_host}:{args.admin_port}/admin", flush=True)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
