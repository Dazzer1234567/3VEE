#!/usr/bin/env python3
"""MASTER_DAW crash and problem reports, and test fixes sent back to one user.

    POST /api/reports/upload            body: the report zip the app made
         -> {"id": "r-20261114-ab12cd", "code": "K7M4Q"}; stored, and a GitHub
         issue opened. The code is the one the app made, unless another report
         has it already: then a free one, and the app shows that instead
    GET  /api/reports/fix?install=<id>  -> {"fix": {...}} or {"fix": null}
         a test fix offered for a report this install sent, not yet answered
    GET  /api/reports/fix/<fix>/file?install=<id>
         -> the fix build, only to the install that sent the report
    POST /api/reports/feedback          {"install", "fix", "verdict", "uses", "note"}
         verdict: fixed | still | untried

Everything the app says about itself is in the zip's report.json: build,
commit, platform, afterCrash, install, wantsFix, and fix (set when the report
comes from a test-fix build -- a crash from one is that fix failing, and the
issue is told so).

From the command line, on the server:

    reports.py serve                     the service (systemd runs this)
    reports.py list [-n 20]              newest reports, their fixes and answers
    reports.py show <report or code>     one report: its report.txt and fixes
    reports.py newid                     a fix id to build with (-DMDAW_TEST_FIX=...)
    reports.py offer <report> <file> [--note "..."] [--id <fix>]
                                         offer a fix build to that report's install
    reports.py withdraw <fix>            stop offering it

Standard library only. Settings from the environment (reports.env.example).
With no GITHUB_TOKEN, issues are skipped and the service works the same.
"""

import argparse
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("REPORTS_DIR", ROOT / "reports-data"))
DB_PATH = Path(os.environ.get("REPORTS_DB", DATA / "reports.db"))
ACCEL = os.environ.get("REPORTS_ACCEL") == "1"   # nginx sends fix files itself
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "Dazzer1234567/MASTER_DAW")

MAX_UPLOAD = 25 * 1024 * 1024
UPLOADS_PER_IP_PER_HOUR = 20
INSTALL_RE = re.compile(r"^[0-9a-f]{32}$")
REPORT_RE = re.compile(r"^r-\d{8}-[0-9a-f]{6}$")
FIX_RE = re.compile(r"^f-\d{8}-[0-9a-f]{6}$")
VERDICTS = {"fixed", "still", "untried"}

# Report codes: the person quotes one to support. The same alphabet, length and
# blocked words as the app's (core/src/BlackBox.cpp).
CODE_LETTERS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 5
BLOCKED = ("ANAL", "ANUS", "ARSE", "BUTT", "COCK", "COON", "CRAP", "CUNT", "DAMN", "DEAD", "DICK", "DYKE",
           "FAGS", "FUCK", "FUKK", "GOOK", "HELL", "HOER", "JERK", "JIZZ", "KANK", "KILL", "KUNT", "MUFF",
           "NAZI", "NUDE", "PAKI", "PEEN", "PISS", "PORN", "PUBE", "PUKE", "PUSS", "RAPE", "SCUM", "SHAG",
           "SHAT", "SHIT", "SLAG", "SLUT", "SMUT", "SPAZ", "SPIC", "SUCK", "TARD", "TITS", "TURD", "TWAT",
           "WANK", "WHOR", "BOOB", "DUMB", "UGLY", "HATE", "DOOM", "BLOW", "SEXY", "DRUG")


def is_code(c):
    return (isinstance(c, str) and len(c) == CODE_LENGTH and all(ch in CODE_LETTERS for ch in c)
            and not any(b in c for b in BLOCKED))


def new_code():
    while True:
        c = "".join(secrets.choice(CODE_LETTERS) for _ in range(CODE_LENGTH))
        if is_code(c):
            return c


def normal_code(c):
    """What a person typed, as a code: upper case, no spaces or dashes."""
    return str(c or "").strip().upper().replace("-", "").replace(" ", "")
CRASH_LINES = 150          # of the crash file, in the issue

_db_lock = threading.Lock()


# ---- the database ---------------------------------------------------------------

def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    (DATA / "reports").mkdir(parents=True, exist_ok=True)
    (DATA / "fixes").mkdir(parents=True, exist_ok=True)
    with _db_lock, db() as con:
        con.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS reports (
                id        TEXT PRIMARY KEY,
                install   TEXT,
                platform  TEXT,
                build     TEXT,
                commit_   TEXT,
                crash     INTEGER NOT NULL DEFAULT 0,
                wants_fix INTEGER NOT NULL DEFAULT 0,
                from_fix  TEXT,
                summary   TEXT,
                size      INTEGER,
                ip        TEXT,
                created   INTEGER NOT NULL,
                issue     INTEGER
            );
            CREATE INDEX IF NOT EXISTS reports_install ON reports(install);
            CREATE TABLE IF NOT EXISTS fixes (
                id        TEXT PRIMARY KEY,
                report    TEXT NOT NULL,
                install   TEXT NOT NULL,
                platform  TEXT,
                file      TEXT NOT NULL,
                size      INTEGER,
                note      TEXT,
                status    TEXT NOT NULL DEFAULT 'offered',   -- offered | withdrawn
                created   INTEGER NOT NULL,
                downloads INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id      INTEGER PRIMARY KEY,
                fix     TEXT NOT NULL,
                verdict TEXT NOT NULL,
                uses    INTEGER,
                note    TEXT,
                at      INTEGER NOT NULL
            );
        """)
        migrate(con)


def migrate(con):
    cols = [r[1] for r in con.execute("PRAGMA table_info(reports)")]
    if "code" not in cols:
        con.execute("ALTER TABLE reports ADD COLUMN code TEXT")
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS reports_code ON reports(code)")


def new_id(prefix):
    return f"{prefix}-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3)}"


# ---- reading a report -------------------------------------------------------------

def read_report(data):
    """(report.json as a dict, report.txt, first crash file's text) from the zip
    bytes, or raises ValueError saying what is wrong with it."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError("not a zip")
    names = z.namelist()
    if "report.json" not in names:
        raise ValueError("no report.json in it")
    try:
        meta = json.loads(z.read("report.json").decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError("report.json is not JSON")
    if not isinstance(meta, dict):
        raise ValueError("report.json is not an object")
    text = z.read("report.txt").decode("utf-8", "replace") if "report.txt" in names else ""
    crash = ""
    for n in sorted(names):
        if n.startswith("crashes/") and n.endswith(".txt"):
            crash = z.read(n).decode("utf-8", "replace")
            break
    return meta, text, crash


def clean_install(v):
    v = str(v or "").strip().lower()
    return v if INSTALL_RE.match(v) else None


# ---- GitHub -----------------------------------------------------------------------

def github(method, path, body):
    if not GITHUB_TOKEN:
        return None
    req = urllib.request.Request(
        f"https://api.github.com/repos/{GITHUB_REPO}{path}", method=method,
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {GITHUB_TOKEN}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "masterdaw-reports"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, ValueError) as e:
        sys.stderr.write(f"github {method} {path} failed: {e!r}\n")
        return None


def issue_comment(report_id, text):
    with _db_lock, db() as con:
        row = con.execute("SELECT issue FROM reports WHERE id=?", (report_id,)).fetchone()
    if row and row["issue"]:
        github("POST", f"/issues/{row['issue']}/comments", {"body": text})


def section(text, heading):
    """The body under a heading of report.txt (a line, then a line of dashes)."""
    m = re.search(rf"^{re.escape(heading)}\n-+\n(.*?)(?:\n\n[^\n]+\n-+\n|\Z)", text, re.S | re.M)
    return m.group(1).strip() if m else ""


def open_issue(report_id, meta, text, crash):
    said = section(text, "What happened") or "(nothing said)"
    first = said.splitlines()[0][:80]
    kind = "Crash" if meta.get("afterCrash") else "Problem"
    with _db_lock, db() as con:
        row = con.execute("SELECT code FROM reports WHERE id=?", (report_id,)).fetchone()
    code = row["code"] if row else ""
    title = f"{kind} report {code}: {first}"
    lines = [
        f"**Code** `{code}` (what the person quotes to support)  ",
        f"**Report** `{report_id}`  ",
        f"**Build** `{meta.get('version', '?')}` commit `{meta.get('commit', '?')}` "
        f"({meta.get('commitDate', '?')}), {meta.get('platform', '?')}  ",
        f"**Wants a test fix** {'yes' if meta.get('wantsFix') else 'no'}",
    ]
    if meta.get("fix"):
        lines.append(f"\n**From test fix `{meta['fix']}`** -- this is that fix failing.")
    lines += ["", "### What happened", said, "", "### Machine",
              "```", section(text, "Machine") or "?", "```"]
    if crash:
        cut = crash.splitlines()
        lines += ["", "### Crash", "```", "\n".join(cut[:CRASH_LINES]),
                  f"... ({len(cut) - CRASH_LINES} more lines in the zip)" if len(cut) > CRASH_LINES else "",
                  "```"]
    lines += ["", f"Zip on the server: `reports.py show {report_id}`.",
              "The email address stays in the zip and is never put here."]
    labels = ["crash-report" if meta.get("afterCrash") else "problem-report"]
    if meta.get("wantsFix"):
        labels.append("wants-test-fix")
    made = github("POST", "/issues", {"title": title, "body": "\n".join(lines), "labels": labels})
    if made and made.get("number"):
        with _db_lock, db() as con:
            con.execute("UPDATE reports SET issue=? WHERE id=?", (made["number"], report_id))
    if meta.get("fix"):
        with _db_lock, db() as con:
            row = con.execute("SELECT report FROM fixes WHERE id=?", (meta["fix"],)).fetchone()
        if row:
            issue_comment(row["report"], f"Test fix `{meta['fix']}` crashed: report `{report_id}`"
                          + (f" (#{made['number']})" if made and made.get("number") else "") + ".")


# ---- the service ------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "masterdaw-reports"

    def client_ip(self):
        return self.headers.get("CF-Connecting-IP") or self.client_address[0]

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.client_ip()} {fmt % args}\n")

    def send_json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def body(self, limit):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > limit:
            return None
        return self.rfile.read(n)

    # -- POST

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/api/reports/upload":
            return self.upload()
        if path == "/api/reports/feedback":
            return self.feedback()
        return self.send_json(404, {"error": "not found"})

    def upload(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_UPLOAD:
            return self.send_json(413, {"error": "report too large"})
        data = self.body(MAX_UPLOAD)
        if not data:
            return self.send_json(400, {"error": "empty"})
        try:
            meta, text, crash = read_report(data)
        except ValueError as e:
            return self.send_json(400, {"error": str(e)})
        ip, now = self.client_ip(), int(time.time())
        with _db_lock, db() as con:
            recent = con.execute("SELECT COUNT(*) FROM reports WHERE ip=? AND created>?",
                                 (ip, now - 3600)).fetchone()[0]
        if recent >= UPLOADS_PER_IP_PER_HOUR:
            return self.send_json(429, {"error": "too many reports; try later"})

        report_id = new_id("r")
        (DATA / "reports" / f"{report_id}.zip").write_bytes(data)
        said = section(text, "What happened")
        from_fix = str(meta.get("fix") or "") or None
        code = meta.get("code") if is_code(meta.get("code")) else new_code()
        with _db_lock, db() as con:
            # The app's code, unless another report has it: then a free one.
            while con.execute("SELECT 1 FROM reports WHERE code=?", (code,)).fetchone():
                code = new_code()
            con.execute(
                "INSERT INTO reports(id, install, platform, build, commit_, crash, wants_fix,"
                " from_fix, summary, size, ip, created, code) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (report_id, clean_install(meta.get("install")), str(meta.get("platform", ""))[:32],
                 str(meta.get("version", ""))[:64], str(meta.get("commit", ""))[:64],
                 1 if meta.get("afterCrash") else 0, 1 if meta.get("wantsFix") else 0,
                 from_fix if from_fix and FIX_RE.match(from_fix) else None,
                 said.splitlines()[0][:200] if said else None, len(data), ip, now, code))
        # The answer cannot wait for GitHub: Cloudflare gives up at 100 s.
        threading.Thread(target=open_issue, args=(report_id, meta, text, crash), daemon=True).start()
        return self.send_json(200, {"id": report_id, "code": code})

    def feedback(self):
        raw = self.body(8192)
        try:
            b = json.loads(raw or b"")
        except ValueError:
            return self.send_json(400, {"error": "not JSON"})
        install, fix = clean_install(b.get("install")), str(b.get("fix", ""))
        verdict = str(b.get("verdict", ""))
        if not install or not FIX_RE.match(fix) or verdict not in VERDICTS:
            return self.send_json(400, {"error": "install, fix and verdict please"})
        with _db_lock, db() as con:
            row = con.execute("SELECT report FROM fixes WHERE id=? AND install=?", (fix, install)).fetchone()
            if not row:
                return self.send_json(404, {"error": "no such fix"})
            uses = b.get("uses")
            uses = int(uses) if isinstance(uses, (int, float)) else None
            note = str(b.get("note") or "")[:2000] or None
            con.execute("INSERT INTO feedback(fix, verdict, uses, note, at) VALUES (?,?,?,?,?)",
                        (fix, verdict, uses, note, int(time.time())))
        words = {"fixed": "says it is **fixed**", "still": "says it **still happens**",
                 "untried": "has **not tried** it yet"}[verdict]
        msg = f"The user of test fix `{fix}` {words}."
        if uses is not None:
            msg += f" Did the thing that crashed {uses} time{'s' if uses != 1 else ''} since installing it."
        if note:
            msg += f"\n\n> {note}"
        threading.Thread(target=issue_comment, args=(row["report"], msg), daemon=True).start()
        return self.send_json(200, {"ok": True})

    # -- GET

    def do_GET(self):
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        install = clean_install((q.get("install") or [""])[0])
        if u.path == "/api/reports/health":
            return self.send_json(200, {"ok": True})
        if u.path == "/api/reports/fix":
            return self.offered(install)
        m = re.match(r"^/api/reports/fix/(f-\d{8}-[0-9a-f]{6})/file$", u.path)
        if m:
            return self.fix_file(m.group(1), install)
        return self.send_json(404, {"error": "not found"})

    def offered(self, install):
        if not install:
            return self.send_json(400, {"error": "install please"})
        with _db_lock, db() as con:
            row = con.execute(
                "SELECT f.* FROM fixes f WHERE f.install=? AND f.status='offered'"
                " AND NOT EXISTS (SELECT 1 FROM feedback b WHERE b.fix=f.id AND b.verdict<>'untried')"
                " ORDER BY f.created DESC LIMIT 1", (install,)).fetchone()
        if not row:
            return self.send_json(200, {"fix": None})
        return self.send_json(200, {"fix": {
            "id": row["id"], "report": row["report"], "note": row["note"] or "",
            "size": row["size"], "name": Path(row["file"]).name,
            "url": f"/api/reports/fix/{row['id']}/file?install={install}"}})

    def fix_file(self, fix, install):
        with _db_lock, db() as con:
            row = con.execute("SELECT * FROM fixes WHERE id=? AND install=? AND status='offered'",
                              (fix, install or "")).fetchone()
            if row:
                con.execute("UPDATE fixes SET downloads=downloads+1 WHERE id=?", (fix,))
        if not row:
            return self.send_json(404, {"error": "no such fix"})
        f = DATA / "fixes" / row["file"]
        if not f.is_file():
            return self.send_json(410, {"error": "the file is gone"})
        self.send_response(200)
        self.send_header("Content-Disposition", f'attachment; filename="{Path(row["file"]).name}"')
        self.send_header("Cache-Control", "no-store")
        if ACCEL:
            self.send_header("X-Accel-Redirect", f"/_report_fixes/{row['file']}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(f.stat().st_size))
        self.end_headers()
        with f.open("rb") as fh:
            while chunk := fh.read(1 << 16):
                self.wfile.write(chunk)


# ---- the command line ---------------------------------------------------------------

def when(t):
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")


def cmd_list(args):
    with db() as con:
        for r in con.execute("SELECT * FROM reports ORDER BY created DESC LIMIT ?", (args.n,)):
            print(f"{r['code'] or '-----'}  {r['id']}  {when(r['created'])}  {'CRASH ' if r['crash'] else 'report'}"
                  f"  {r['platform'] or '?':8} {r['build'] or '?':12}"
                  f"  {'#' + str(r['issue']) if r['issue'] else '-':6}"
                  f"  {'fix wanted ' if r['wants_fix'] else ''}{('from ' + r['from_fix'] + ' ') if r['from_fix'] else ''}"
                  f"{r['summary'] or ''}")
            for f in con.execute("SELECT * FROM fixes WHERE report=? ORDER BY created", (r["id"],)):
                answers = [b["verdict"] for b in con.execute("SELECT verdict FROM feedback WHERE fix=?"
                                                             " ORDER BY at", (f["id"],))]
                again = con.execute("SELECT COUNT(*) FROM reports WHERE from_fix=?", (f["id"],)).fetchone()[0]
                print(f"    {f['id']}  {f['status']}  {f['file']}  downloaded {f['downloads']}"
                      f"  answers {','.join(answers) or '-'}  crashed again {again}")


def find_report(key):
    """A report's id from its id or its code, as a person typed it."""
    if REPORT_RE.match(key):
        return key
    with db() as con:
        row = con.execute("SELECT id FROM reports WHERE code=?", (normal_code(key),)).fetchone()
    return row["id"] if row else None


def cmd_show(args):
    rid = find_report(args.report)
    zp = DATA / "reports" / f"{rid}.zip"
    if not rid or not zp.is_file():
        sys.exit(f"no report {args.report}")
    meta, text, crash = read_report(zp.read_bytes())
    print(text)
    print(f"zip: {zp}")


def cmd_offer(args):
    src = Path(args.file)
    if not src.is_file():
        sys.exit(f"no file {src}")
    with db() as con:
        r = con.execute("SELECT * FROM reports WHERE id=?", (find_report(args.report) or "",)).fetchone()
    if not r:
        sys.exit(f"no report {args.report}")
    if not r["install"]:
        sys.exit("that report has no install id, so there is nobody to offer it to")
    fix_id = args.id or new_id("f")
    if not FIX_RE.match(fix_id):
        sys.exit(f"not a fix id: {fix_id} (f-YYYYMMDD-xxxxxx)")
    with db() as con:
        if con.execute("SELECT 1 FROM fixes WHERE id=?", (fix_id,)).fetchone():
            sys.exit(f"{fix_id} is offered already")
    name = f"{fix_id}/{src.name}"
    (DATA / "fixes" / fix_id).mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, DATA / "fixes" / name)
    with db() as con:
        con.execute("INSERT INTO fixes(id, report, install, platform, file, size, note, created)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (fix_id, r["id"], r["install"], r["platform"], name, src.stat().st_size,
                     args.note, int(time.time())))
    issue_comment(r["id"], f"Test fix `{fix_id}` offered to this user: `{src.name}`"
                  + (f"\n\n> {args.note}" if args.note else ""))
    print(f"{fix_id} offered to the install that sent {r['id']}")


def cmd_withdraw(args):
    with db() as con:
        n = con.execute("UPDATE fixes SET status='withdrawn' WHERE id=?", (args.fix,)).rowcount
    print("withdrawn" if n else f"no fix {args.fix}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8767)
    s = sub.add_parser("list")
    s.add_argument("-n", type=int, default=20)
    s = sub.add_parser("show")
    s.add_argument("report")
    s = sub.add_parser("offer")
    s.add_argument("report")
    s.add_argument("file")
    s.add_argument("--note", default="")
    s.add_argument("--id", default="", help="the id the build was made with (MDAW_TEST_FIX)")
    s = sub.add_parser("newid")
    s = sub.add_parser("withdraw")
    s.add_argument("fix")
    args = ap.parse_args()
    init_db()
    if args.cmd in (None, "serve"):
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", 8767)
        print(f"reports server on http://{host}:{port}  data={DATA}"
              f"  github={'on ' + GITHUB_REPO if GITHUB_TOKEN else 'off'}", flush=True)
        ThreadingHTTPServer((host, port), Handler).serve_forever()
    else:
        {"list": cmd_list, "show": cmd_show, "offer": cmd_offer, "withdraw": cmd_withdraw,
         "newid": lambda a: print(new_id("f"))}[args.cmd](args)


if __name__ == "__main__":
    main()
