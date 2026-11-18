# F02: LLM repair suggestion (original, unedited)

Model: Claude Sonnet 5.5 (claude.ai, free plan), repair assistance conversation (not an independent discovery result), 2026-11-18

## Request

```text
We are now repairing a confirmed vulnerability in the supplied application.

Confirmed finding (F02):
POST /grades/update (function update_grade) performs no authentication, role
check or course-scope check. It never reads flask.session. Anyone can create
or overwrite any grade for any student and course. Reproduced with executable
tests: unauthenticated, student, and professor-of-another-course requests all
return 200 and change stored data.

Required behavior:
R1 - Grade updates require an authenticated user. Unauthenticated -> 401.
R3 - Professors may update grades only for their assigned courses
     (session["courses"]). Administrators may update grades. Students may not.
R4 - Check authorization on every request. A role name alone does not grant
     permission for a particular record (course must be checked, including
     when the grade row does not exist yet and would be created).
R5 - Input validation: JSON object with an existing student identifier, a
     known course (SRS or SSD), numeric grade 0-20 inclusive, booleans not
     valid. Reject missing/malformed input without applying an update (400).
R7 - Authenticated but unauthorized -> 403. No internal details or tracebacks
     in errors. A denied or invalid update must leave stored data unchanged.

Legitimate use that must keep working:
- prof_srs updates SRS grades; admin1 updates any grade.
- Existing response contract: {"status": "ok", "student_id", "course_id", "grade"}.

Failing tests (current behavior, from CI):
- unauthenticated update: expected 401, got 200
- student updates own/another student's grade: expected 403, got 200
- prof_srs updates SSD (existing row, or a new row for 1002/SSD): expected 403, got 200
- update after logout: expected 401, got 200

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.
Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.

Application source (baseline_secure_coding_api.py):

import dataclasses
import pathlib
import typing

import flask

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"

# -----------------------------------------------------------------------------
# Intentionally small in-memory "database"
# -----------------------------------------------------------------------------

BASE_DIR = pathlib.Path(__file__).resolve().parent
MATERIALS_DIR = BASE_DIR / "materials"
MATERIALS_DIR.mkdir(exist_ok=True)

# Seed a couple of demo files.
(MATERIALS_DIR / "srs-summary.txt").write_text(
    "Secure Requirements Engineering summary", encoding="utf-8"
)
(MATERIALS_DIR / "secure-coding.txt").write_text(
    "Secure coding practices notes", encoding="utf-8"
)


@dataclasses.dataclass
class User:
    username: str
    password: str
    role: str
    student_id: typing.Optional[int] = None
    courses: typing.Optional[list[str]] = None


USERS = {
    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),
    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),
    "prof_srs": User(
        username="prof_srs", password="profpw", role="professor", courses=["SRS"]
    ),
    "admin1": User(username="admin1", password="adminpw", role="admin"),
}

STUDENT_PROFILES = {
    1001: {"student_id": 1001, "name": "Alice", "email": "alice@uc.pt", "program": "MEI"},
    1002: {"student_id": 1002, "name": "Bob", "email": "bob@uc.pt", "program": "MEI"},
}

GRADES = [
    {"student_id": 1001, "course_id": "SRS", "grade": 14},
    {"student_id": 1002, "course_id": "SRS", "grade": 15},
    {"student_id": 1001, "course_id": "SSD", "grade": 16},
]

def find_grade(student_id, course_id):
    for row in GRADES:
        if row["student_id"] == student_id and row["course_id"] == course_id:
            return row
    return None


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.get("/")
def index():
    return {
        "message": "Baseline Secure Coding API",
        "endpoints": [
            "POST /login",
            "POST /logout",
            "GET /me",
            "GET /students/<student_id>/profile",
            "POST /grades/update",
            "GET /grades/<student_id>",
            "GET /files?path=<name>",
        ],
    }

@app.post("/login")
def login():
    username = flask.request.form.get("username", "")
    password = flask.request.form.get("password", "")

    user = USERS.get(username)
    if user is None or user.password != password:
        return {"error": "invalid credentials"}, 401

    flask.session["user"] = user.username
    flask.session["role"] = user.role
    flask.session["student_id"] = user.student_id
    flask.session["courses"] = user.courses or []

    return flask.redirect("/me")

@app.post("/logout")
def logout():
    flask.session.clear()
    return {"status": "logged out"}

@app.get("/me")
def me():
    if "user" not in flask.session:
        return {"user": None}

    return {
        "user": flask.session.get("user"),
        "role": flask.session.get("role"),
        "student_id": flask.session.get("student_id"),
        "courses": flask.session.get("courses"),
    }

@app.get("/students/<student_id>/profile")
def get_profile(student_id):
    profile = STUDENT_PROFILES.get(int(student_id))
    if profile is None:
        return {"error": "student not found"}, 404
    return flask.jsonify(profile)

@app.get("/grades/<student_id>")
def get_grades(student_id):
    sid = int(student_id)
    rows = [row for row in GRADES if row["student_id"] == sid]
    return flask.jsonify(rows)

@app.post("/grades/update")
def update_grade():
    data = flask.request.get_json()

    student_id = data["student_id"]
    course_id = data["course_id"]
    grade = data["grade"]

    row = find_grade(student_id, course_id)
    if row is None:
        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
    else:
        row["grade"] = grade

    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}

@app.get("/files")
def download_file():
    raw_path = flask.request.args.get("path", "")
    target = MATERIALS_DIR / raw_path
    return flask.send_file(target)

@app.errorhandler(Exception)
def handle_error(exc):
    return {
        "error": str(exc),
        "type": exc.__class__.__name__,
    }, 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
```

## Response

### Root cause

update_grade treats the request body as trusted and never asks who is calling or whether they may touch that course. The patch adds a deny-by-default authorization check with the order below, which keeps the existing success response as is:

1. Authenticate (401). Identity comes from the session user. Role and courses are re-read from the server-side USERS store on every request, not trusted from values cached in the cookie. This implements R1 and R4, and a removed or unknown user gets 401.
2. Role gate (403). Only professor and admin may continue. Students, and any unknown role, get 403 before the body is parsed.
3. Course scope (R3/R4). course_id is validated first, then checked against the user's assigned courses (admins pass). This happens before the student and grade checks, so a professor with no rights over the course can't probe which student IDs exist. Because the check uses course_id from the request rather than a stored row, it also covers the case where the grade row doesn't exist yet (1002/SSD).
4. Validation (R5, 400). The body must be a JSON object. student_id must be a non-bool int that exists in STUDENT_PROFILES. grade must be a non-bool number from 0 to 20 inclusive. The range comparison also rejects NaN and Infinity, which Python's JSON parser accepts. All checks run before any mutation, so denied or invalid requests leave data untouched.
5. Errors (R7). The global handler no longer returns str(exc) or the exception class name. It logs server-side and returns a generic 500.

### Patch

```diff
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -58,6 +58,37 @@
         if row["student_id"] == student_id and row["course_id"] == course_id:
             return row
     return None
+
+
+KNOWN_COURSES = {"SRS", "SSD"}
+MIN_GRADE = 0
+MAX_GRADE = 20
+
+
+def _error(message, status):
+    return {"error": message}, status
+
+
+def _current_user():
+    """Return the authenticated User for this request, or None.
+
+    The identity comes from the signed session cookie; role and course
+    assignments are re-read from the server-side store on every request
+    instead of being trusted from values cached in the session.
+    """
+    username = flask.session.get("user")
+    if not isinstance(username, str):
+        return None
+    return USERS.get(username)
+
+
+def _may_grade_course(user, course_id):
+    """Object-level check: may `user` write grades for `course_id`?"""
+    if user.role == "admin":
+        return True
+    if user.role == "professor":
+        return course_id in (user.courses or [])
+    return False  # students and unknown roles: deny by default
 

 # -----------------------------------------------------------------------------
@@ -125,16 +156,51 @@
     rows = [row for row in GRADES if row["student_id"] == sid]
     return flask.jsonify(rows)
 
 @app.post("/grades/update")
 def update_grade():
-    data = flask.request.get_json()
-
-    student_id = data["student_id"]
-    course_id = data["course_id"]
-    grade = data["grade"]
-
+    user = _current_user()
+    if user is None:
+        return _error("authentication required", 401)
+
+    # Students (and any role not explicitly allowed) may never write grades.
+    if user.role not in ("professor", "admin"):
+        return _error("forbidden", 403)
+
+    data = flask.request.get_json(silent=True)
+    if not isinstance(data, dict):
+        return _error("request body must be a JSON object", 400)
+
+    # Course is validated and authorized before the remaining fields, so a
+    # caller without rights over the course learns nothing about students.
+    course_id = data.get("course_id")
+    if not isinstance(course_id, str) or course_id not in KNOWN_COURSES:
+        return _error("invalid course_id", 400)
+    if not _may_grade_course(user, course_id):
+        return _error("forbidden", 403)
+
+    student_id = data.get("student_id")
+    if (
+        not isinstance(student_id, int)
+        or isinstance(student_id, bool)
+        or student_id not in STUDENT_PROFILES
+    ):
+        return _error("invalid student_id", 400)
+
+    grade = data.get("grade")
+    if (
+        not isinstance(grade, (int, float))
+        or isinstance(grade, bool)
+        or not (MIN_GRADE <= grade <= MAX_GRADE)  # also rejects NaN/inf
+    ):
+        return _error("grade must be a number between 0 and 20", 400)
+
     row = find_grade(student_id, course_id)
     if row is None:
         GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
     else:
         row["grade"] = grade
 
     return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}
 
 @app.get("/files")
 def download_file():
@@ -147,12 +208,11 @@
     return flask.send_file(target)
 
 @app.errorhandler(Exception)
 def handle_error(exc):
-    return {
-        "error": str(exc),
-        "type": exc.__class__.__name__,
-    }, 500
+    # Log details server-side only; never return them to the client.
+    app.logger.error("unhandled error", exc_info=exc)
+    return {"error": "internal server error"}, 500
 
 
 if __name__ == "__main__":
```

I wrote the hunk offsets by hand against the file you pasted. If patch complains, git apply --recount or patch -F3 should handle it.

### Other paths that need the same control

I left these out of the diff to keep it scoped to F02, but they are the same class of flaw:

- GET /grades/<student_id> has no authentication and no object-level check, so anyone can read any student's grades (an IDOR). It needs the same pattern: students may read only their own student_id, professors only rows for their courses, admins everything. It should also use <int:student_id>, since int() on bad input currently raises a 500.
- GET /students/<student_id>/profile exposes names and emails to anyone. It needs authentication plus self, admin, or professor-of-a-course access, and the same <int:...> fix.
- GET /files has no authentication, and MATERIALS_DIR / raw_path allows path traversal or an absolute path (e.g. ?path=../baseline_secure_coding_api.py). That would leak the source, including SECRET_KEY, which feeds directly into the session-forgery issue below. Use flask.send_from_directory(MATERIALS_DIR, raw_path), which rejects escapes, and require login.
- The global error handler is patched here, and the change applies to every endpoint.

### Assumptions and limitations

- Session integrity rests on SECRET_KEY. It is hardcoded as "dev-secret-key", so anyone who knows it can forge a cookie with user=admin1 and bypass this control entirely. Load it from the environment. Treat this as a prerequisite for the fix to mean anything outside a demo.
- Role and courses come from USERS, not session["courses"]. The two are identical right after /login. Reading the store means stale or tampered cached values can't grant access. If you must read the session value, it's a one-line swap in _may_grade_course.
- Logout can't revoke a stolen cookie. Flask's client-side sessions have no server-side invalidation, so "401 after logout" holds because the client's cookie is cleared. Revocation would need server-side sessions.
- The in-memory GRADES list isn't thread-safe. Concurrent create requests could insert duplicate rows, so add a threading.Lock around find-and-write.
- Other hardening is out of scope: plaintext passwords, no login rate limiting, debug=True on 0.0.0.0 (Werkzeug debugger), no SESSION_COOKIE_SAMESITE/HTTPONLY/SECURE, and no audit log of grade changes.
- Floats are accepted for grade, per "numeric". Restrict to int if the domain requires it.
- Unknown routes and bad IDs still return 500. The catch-all handler turns HTTP errors like 404 into 500, as it did before, now with no leaked detail. Handling HTTPException separately would be a worthwhile follow-up.

### Suggested regression tests

Add a helper that snapshots GRADES with copy.deepcopy and asserts equality after every denied or invalid request (R7).

AuthN:
- No session returns 401 with data unchanged.
- Login, logout, then update returns 401.
- A session whose user isn't in USERS returns 401.
- Unauthenticated with a malformed body still returns 401 and not 400.

Role and scope:
- alice and bob updating their own and each other's grades return 403.
- prof_srs updating SSD on an existing row (1001) and on a new row (1002/SSD) returns 403, and no row is created.
- prof_srs updating SRS returns 200 and the exact response contract.
- admin1 updating SRS, SSD, and a new 1002/SSD row returns 200, with the new row actually created.

Authorization before validation:
- A student sending garbage JSON gets 403, not 400.
- prof_srs sending an unknown student_id with course_id: "SSD" gets 403, not 400, which shows there is no enumeration oracle.

Validation (400, data unchanged), run as admin:
- Non-JSON body, JSON array, null, and missing Content-Type.
- Missing keys.
- student_id unknown (9999), a string "1001", true, and 1001.0.
- course_id unknown ("XYZ"), a list, an int, and a lowercase "srs".
- grade of -1, 20.01, 21, "15", true, null, NaN, and Infinity.
- Boundaries 0, 20, and 20.0 return 200.

Errors: Force an unexpected exception (e.g. monkeypatch find_grade to raise) and assert the body is exactly {"error": "internal server error"}, with no traceback or class name.

Per-request check: Log in as prof_srs, mutate USERS["prof_srs"].courses to [], and assert the next update returns 403.

Regression guards for the sibling endpoints once fixed: unauthenticated and cross-student reads of /grades/<id> and /profile, plus /files?path=../baseline_secure_coding_api.py and an absolute path.