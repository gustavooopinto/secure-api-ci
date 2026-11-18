# F01: LLM repair suggestion (original, unedited)

Model: Claude Sonnet 5.5 (claude.ai, free plan), repair assistance conversation (not an independent discovery result), 2026-11-18

## Request

```text
We are now repairing a confirmed vulnerability in the supplied application.

Confirmed finding (F01):
GET /files (function download_file) joins the user-controlled "path" query
parameter to MATERIALS_DIR with pathlib and passes it to flask.send_file,
with no authentication and no containment check. Reproduced with executable
tests: "../secret.txt", an absolute path, "sub/../../secret.txt" and a symlink
inside materials/ pointing outside all return 200 with the contents of a file
outside the materials directory.

Required behavior:
R1 - Material downloads require an authenticated user. Unauthenticated -> 401.
R6 - Authenticated users may download teaching materials within the materials
     directory. Requests must not read files outside that directory
     (including via "..", absolute paths, nested traversal or symlinks).
R7 - Invalid requests must return appropriate client errors (4xx) without
     exposing internal paths, tracebacks or exception details.

Legitimate use that must keep working:
- An authenticated user downloads an existing file inside materials/
  (e.g. srs-summary.txt) and receives its exact contents with 200.

Failing tests (current behavior, from CI):
- unauthenticated download: expected 401, got 200
- ../secret.txt, absolute path, sub/../../secret.txt, symlink escape:
  expected 4xx, got 200
- nonexistent file: expected 4xx without leaking paths, got 500

Note: the application has a global errorhandler(Exception) that turns every
exception, including abort(401/403/404), into a 500. The patch must work with
that (return responses directly, or handle HTTPException correctly).

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.
Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.

Application source (baseline_secure_coding_api.py):
<código do ficheiro com o patch do F02 já aplicado, como enviado ao modelo>
```

## Response

### Root cause

download_file builds a filesystem path from untrusted input (MATERIALS_DIR / raw_path) and opens it without checking where the path actually points. Joining with pathlib doesn't contain anything. An absolute raw_path replaces MATERIALS_DIR entirely, .. segments walk out of it, and send_file follows symlinks. The endpoint also never asks who the caller is.

### Control implemented

- Authenticate first (R1). The endpoint reuses _current_user() from the F02 fix and returns 401 before reading the query string. An unauthenticated caller learns nothing about which paths exist.
- Canonicalize, then contain (R6). _resolve_material computes (MATERIALS_ROOT / raw_path).resolve(strict=True). This collapses .. and follows every symlink to the real target, and it fails if the target doesn't exist. The check then requires target.is_relative_to(MATERIALS_ROOT), where MATERIALS_ROOT is itself resolved. This is the actual security boundary, and the checks that follow are derived from the resolved path.
  - Absolute paths (/etc/passwd) and sub/../../secret.txt resolve outside the root and are rejected.
  - Symlinks pointing outside resolve outside the root and are rejected. Symlinks that stay inside the root still work.
  - Sibling-prefix directories such as materials-backup/ are rejected because is_relative_to compares path components, not string prefixes.
  - The target must be a regular file, so directories are rejected too.
- Uniform client errors (R7).
  - A missing path parameter returns 400.
  - Nonexistent, directory, and out-of-root requests all return the same 404 {"error": "file not found"}. That avoids an oracle for probing the filesystem layout.
  - NUL bytes, over-long names, symlink loops, and permission errors surface as OSError, ValueError, or RuntimeError and are caught, so they get 404 instead of a 500.
  - Responses never echo the input or any server path.
- Works with the global handler. Every branch returns a response directly and never calls abort(). send_from_directory is deliberately not used because it raises NotFound, which the catch-all handler would turn into a 500.

### Patch

```diff
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -84,6 +84,25 @@
         return course_id in (user.courses or [])
     return False  # students and unknown roles: deny by default
 
+
+MATERIALS_ROOT = MATERIALS_DIR.resolve()
+
+
+def _resolve_material(raw_path):
+    """Map a user-supplied name to a regular file inside MATERIALS_ROOT.
+
+    Returns the fully resolved Path, or None if the name does not exist, is
+    not a regular file, or resolves (after following ".." and symlinks)
+    outside MATERIALS_ROOT.
+    """
+    try:
+        target = (MATERIALS_ROOT / raw_path).resolve(strict=True)
+    except (OSError, ValueError, RuntimeError):
+        return None  # missing, NUL byte, name too long, symlink loop, ...
+    if not target.is_relative_to(MATERIALS_ROOT) or not target.is_file():
+        return None
+    return target
+
 # -----------------------------------------------------------------------------
 # REST API Endpoints
 # -----------------------------------------------------------------------------
@@ -194,6 +213,21 @@
 
 @app.get("/files")
 def download_file():
-    raw_path = flask.request.args.get("path", "")
-    target = MATERIALS_DIR / raw_path
-    return flask.send_file(target)
+    user = _current_user()
+    if user is None:
+        return _error("authentication required", 401)
+
+    raw_path = flask.request.args.get("path", "")
+    if not raw_path:
+        return _error("path is required", 400)
+
+    target = _resolve_material(raw_path)
+    if target is None:
+        # Same answer for missing, non-file and out-of-root paths: no oracle.
+        return _error("file not found", 404)
+
+    try:
+        return flask.send_file(target)
+    except OSError:  # file vanished or became unreadable after the check
+        return _error("file not found", 404)
 
 @app.errorhandler(Exception)
 def handle_error(exc):
```

I computed the hunk offsets by hand against the file you pasted. If patch complains, use git apply --recount. The code uses Path.is_relative_to, which needs Python 3.9+. Your list[str] annotation already requires that.

### Other affected paths

- /files is the only endpoint that touches the filesystem with user input. The seeding code uses constant names, so nothing else needs this control today. Any future upload, download, or export endpoint should reuse _resolve_material, or a generalized version that takes the root as a parameter.
- GET /grades/<student_id> and GET /students/<student_id>/profile still have no authentication or object-level checks, as noted in the F02 answer. They are a different finding, but they share the same _current_user() pattern.
- The global error handler still turns HTTP exceptions such as 404 and 405 into 500. This patch doesn't depend on it, but it's worth fixing separately:

```python
import werkzeug.exceptions

@app.errorhandler(Exception)
def handle_error(exc):
    if isinstance(exc, werkzeug.exceptions.HTTPException):
        return {"error": exc.name.lower()}, exc.code
    app.logger.error("unhandled error", exc_info=exc)
    return {"error": "internal server error"}, 500
```

### Assumptions and limitations

- Any authenticated user can read any material. R6 says "authenticated users", and materials aren't linked to courses in the data model. If they should be course-scoped, that needs a material-to-course mapping and a check like _may_grade_course.
- Check-then-open race (TOCTOU). If someone who can write inside materials/ swaps a file for a symlink between the check and the open, the containment check could be bypassed. The pre-patch code had no containment at all, so this is a large improvement, but it isn't airtight. The usual fix is to open with O_NOFOLLOW (or openat-style handling) and serve the file descriptor. In practice, don't let untrusted parties write into materials/.
- debug=True on 0.0.0.0 undermines this fix. The Werkzeug debugger console allows arbitrary code execution, which makes any file restriction moot. Turn it off outside local development.
- Authentication depends on SECRET_KEY. It is hardcoded as "dev-secret-key", so a forged session cookie passes the 401 check. This was also flagged in F02.
- Dotfiles and anything else inside materials/ are downloadable. That includes any .env-style file someone drops there. An allowlist of extensions or a rule against hidden files would tighten this.
- Content type and sniffing. If HTML or SVG files ever land in materials/, they would render in the browser from your origin. Consider as_attachment=True and X-Content-Type-Options: nosniff. I left these out because they change response headers beyond what the finding requires.
- Windows. resolve and is_relative_to handle drive letters and case-insensitivity, but test on your target OS.

### Suggested regression tests

Create secret.txt outside materials/ with a unique marker string, and assert that the marker never appears in any response body.

Authentication:
- Unauthenticated GET /files?path=srs-summary.txt returns 401.
- Unauthenticated with a traversal path still returns 401, not 404, so the check order holds.
- Login, logout, then download returns 401.

Legitimate use:
- alice, prof_srs, and admin1 each get 200 with the exact bytes of srs-summary.txt and secure-coding.txt.
- A nested file such as materials/sub/notes.txt returns 200.
- A symlink inside materials/ pointing to another file inside it returns 200.

Traversal, all 4xx with body {"error": "file not found"}:
- ../secret.txt
- sub/../../secret.txt (create sub/)
- ....//secret.txt
- Percent-encoded %2e%2e%2fsecret.txt
- An absolute path to the secret file
- An absolute path to the app source
- The sibling-prefix case: create materials-backup/x.txt and request ../materials-backup/x.txt
- Backslash variants: ..\\secret.txt (on Windows)

Symlinks:
- A file symlink inside materials/ pointing outside returns 404.
- A directory symlink pointing outside, requested as link_dir/secret.txt, returns 404.
- A symlink loop returns 404, not 500.

Invalid input:
- A missing path parameter and an empty path= return 400.
- Directory targets (path=., path=sub) return 404.
- A NUL byte (path=a%00b) returns 404, not 500.
- A 5,000-character name returns 404, not 500.
- Repeated parameters (?path=a&path=b) use only the first value and still return a valid result.

No leakage and no oracle:
- For nonexistent, outside-root, and directory requests, the response bodies are byte-identical.
- The response bodies contain neither str(MATERIALS_DIR), BASE_DIR, Traceback, nor any exception class name.
- A file with permissions 000 returns 404, not 500 (skip when running as root).

Robustness:
- Monkeypatch flask.send_file to raise FileNotFoundError and assert 404 with the generic body.
- Monkeypatch _resolve_material to raise RuntimeError and assert the generic 500 body from the global handler.