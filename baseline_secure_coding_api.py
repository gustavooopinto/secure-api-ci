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

KNOWN_COURSES = {"SRS", "SSD"}
MIN_GRADE = 0
MAX_GRADE = 20


def _error(message, status):
    return {"error": message}, status


def _current_user():
    """Return the authenticated User for this request, or None."""
    username = flask.session.get("user")
    if not isinstance(username, str):
        return None
    return USERS.get(username)


def _may_grade_course(user, course_id):
    """Object-level check: may `user` write grades for `course_id`?"""
    if user.role == "admin":
        return True
    if user.role == "professor":
        return course_id in (user.courses or [])
    return False  # students and unknown roles: deny by default

def _resolve_material(raw_path):
    """Map a user-supplied name to a regular file inside MATERIALS_DIR."""
    try:
        root = pathlib.Path(MATERIALS_DIR).resolve(strict=True)
        target = (root / raw_path).resolve(strict=True)
    except (OSError, ValueError, RuntimeError):
        return None
    if not target.is_relative_to(root) or not target.is_file():
        return None
    return target

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
    user = _current_user()
    if user is None:
        return _error("authentication required", 401)

    if user.role not in ("professor", "admin"):
        return _error("forbidden", 403)

    data = flask.request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("request body must be a JSON object", 400)

    course_id = data.get("course_id")
    if not isinstance(course_id, str) or course_id not in KNOWN_COURSES:
        return _error("invalid course_id", 400)
    if not _may_grade_course(user, course_id):
        return _error("forbidden", 403)

    student_id = data.get("student_id")
    if (
        not isinstance(student_id, int)
        or isinstance(student_id, bool)
        or student_id not in STUDENT_PROFILES
    ):
        return _error("invalid student_id", 400)

    grade = data.get("grade")
    if (
        not isinstance(grade, (int, float))
        or isinstance(grade, bool)
        or not (MIN_GRADE <= grade <= MAX_GRADE)
    ):
        return _error("grade must be a number between 0 and 20", 400)

    row = find_grade(student_id, course_id)
    if row is None:
        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
    else:
        row["grade"] = grade

    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}

@app.get("/files")
def download_file():
    user = _current_user()
    if user is None:
        return _error("authentication required", 401)

    raw_path = flask.request.args.get("path", "")
    if not raw_path:
        return _error("path is required", 400)

    target = _resolve_material(raw_path)
    if target is None:
        return _error("file not found", 404)

    try:
        return flask.send_file(target)
    except OSError:
        return _error("file not found", 404)

@app.errorhandler(Exception)
def handle_error(exc):
    app.logger.error("unhandled error", exc_info=exc)
    return {"error": "internal server error"}, 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)