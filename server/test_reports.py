#!/usr/bin/env python3
"""End to end for reports.py, with no GitHub: python server/test_reports.py"""

import io
import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

tmp = tempfile.mkdtemp(prefix="reports-test-")
os.environ["REPORTS_DIR"] = tmp
os.environ.pop("GITHUB_TOKEN", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import reports  # noqa: E402

reports.init_db()
srv = reports.ThreadingHTTPServer(("127.0.0.1", 0), reports.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
INSTALL = "0123456789abcdef0123456789abcdef"
OTHER = "fedcba9876543210fedcba9876543210"


def zip_of(meta, crash=True):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("report.json", json.dumps(meta))
        z.writestr("report.txt", "MASTER_DAW crash report\nmade x\n\nWhat happened\n-------------\n"
                                 "It fell over when I dragged a plugin.\n\nEmail\n-----\na@b.c\n\n"
                                 "Machine\n-------\nWindows 11\n")
        if crash:
            z.writestr("crashes/mdaw-1.txt", "access violation\n#0 foo.cpp:12\n")
    return b.getvalue()


def call(method, path, body=None, ctype="application/zip"):
    req = urllib.request.Request(BASE + path, method=method, data=body,
                                 headers={"Content-Type": ctype} if body is not None else {})
    try:
        with urllib.request.urlopen(req) as r:
            data = r.read()
            return r.status, (json.loads(data) if r.headers.get("Content-Type") == "application/json" else data)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


fails = 0


def check(what, ok):
    global fails
    print(("ok   " if ok else "FAIL ") + what)
    fails += 0 if ok else 1


meta = {"version": "0.9", "commit": "abc1234", "platform": "windows", "afterCrash": True, "code": "K7M4Q",
        "install": INSTALL, "wantsFix": True}
code, r = call("POST", "/api/reports/upload", zip_of(meta))
check("upload answers an id", code == 200 and reports.REPORT_RE.match(r.get("id", "")))
check("and the app's code, kept", r.get("code") == "K7M4Q")
code2, r2 = call("POST", "/api/reports/upload", zip_of(meta))
check("a code taken already: a free one instead", code2 == 200 and r2.get("code") != "K7M4Q"
      and reports.is_code(r2.get("code")))
_, r3 = call("POST", "/api/reports/upload", zip_of(dict(meta, code="SHIT2")))
check("a blocked code from the app is replaced", reports.is_code(r3.get("code")) and "SHIT" not in r3["code"])
check("found by its code, typed carelessly", reports.find_report(" k7m-4q ") == r["id"])
check("no code has a blocked word in it", all(reports.is_code(reports.new_code()) for _ in range(2000)))
rid = r["id"]
check("the zip is kept", (Path(tmp) / "reports" / f"{rid}.zip").is_file())
check("junk is refused", call("POST", "/api/reports/upload", b"not a zip")[0] == 400)
check("a zip without report.json is refused",
      call("POST", "/api/reports/upload", (lambda b: (zipfile.ZipFile(b, "w").close(), b.getvalue())[1])(io.BytesIO()))[0] == 400)

check("nothing offered yet", call("GET", f"/api/reports/fix?install={INSTALL}") == (200, {"fix": None}))
check("a bad install id is refused", call("GET", "/api/reports/fix?install=nope")[0] == 400)

build = Path(tmp) / "mdaw-fix.exe"
build.write_bytes(b"MZ fix build")
sys.argv = ["reports.py", "offer", rid, str(build), "--note", "null plugin guarded"]
reports.main()
code, r = call("GET", f"/api/reports/fix?install={INSTALL}")
fix = r["fix"]
check("the fix is offered to that install", code == 200 and fix and fix["report"] == rid
      and fix["note"] == "null plugin guarded")
check("and to no other", call("GET", f"/api/reports/fix?install={OTHER}") == (200, {"fix": None}))
code, data = call("GET", fix["url"])
check("the file downloads", code == 200 and data == b"MZ fix build")
check("not for another install", call("GET", f"/api/reports/fix/{fix['id']}/file?install={OTHER}")[0] == 404)

check("feedback untried keeps it offered",
      call("POST", "/api/reports/feedback", json.dumps({"install": INSTALL, "fix": fix["id"], "verdict": "untried"}).encode(), "application/json")[0] == 200
      and call("GET", f"/api/reports/fix?install={INSTALL}")[1]["fix"] is not None)
check("feedback from another install is refused",
      call("POST", "/api/reports/feedback", json.dumps({"install": OTHER, "fix": fix["id"], "verdict": "fixed"}).encode(), "application/json")[0] == 404)
check("feedback fixed",
      call("POST", "/api/reports/feedback", json.dumps({"install": INSTALL, "fix": fix["id"], "verdict": "fixed", "uses": 12}).encode(), "application/json")[0] == 200)
check("answered, so no longer offered", call("GET", f"/api/reports/fix?install={INSTALL}") == (200, {"fix": None}))

again = dict(meta, fix=fix["id"])
code, r = call("POST", "/api/reports/upload", zip_of(again))
with reports.db() as con:
    row = con.execute("SELECT from_fix FROM reports WHERE id=?", (r["id"],)).fetchone()
check("a crash from the fix build is tied to the fix", row["from_fix"] == fix["id"])

sys.argv = ["reports.py", "list"]
reports.main()
srv.shutdown()
print("all passed" if not fails else f"{fails} failed")
sys.exit(1 if fails else 0)
