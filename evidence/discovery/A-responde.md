Static Security Review: Flask Grades/Materials API

Scope: the single attached source file. Line numbers are approximate, counted from the pasted text. “Fact” means directly visible in the code. “Inferred” means a security requirement I assume, because no policy was supplied.

Assumptions

A1 (inferred): the intended policy is that students read only their own profile and grades, professors change grades only for courses they teach, admins may do both, and /files serves course materials only.
A2 (inferred): the app is reachable by untrusted clients, since it binds to 0.0.0.0.
A3 (inferred): it is launched via python app.py, not a production WSGI server.
If these are wrong, severity and exploitability change, as noted per finding.
Findings table
ID	Title	Location	Severity	Confidence
F-01	Path traversal / arbitrary file read	download_file, L144–148	Critical	High
F-02	Unauthenticated, unauthorized grade modification	update_grade, L128–142	Critical	High
F-03	Broken object-level authorization on student profiles	get_profile, L115–120	High	High
F-04	Broken object-level authorization on grades	get_grades, L122–126	High	High
F-05	Werkzeug debugger enabled and exposed on all interfaces	app.run(...), L158–159	High	Medium
F-06	Hard-coded session signing key	app.config, L8	High (latent)	High
F-07	Verbose exceptions and a catch-all handler that rewrites status codes	handle_error, L150–155	Medium	High
F-08	Missing input validation and type confusion	L117, L124, L130–140	Medium	High
F-09	Weak credential handling and no brute-force protection	USERS L36–43, login L82–96	Medium	Medium
F-10	Session lifecycle, cookie flags, CSRF posture	L8, login, logout L98–101	Low–Medium	Medium
F-11	No audit logging of security-relevant actions	whole app	Low	Medium (inferred requirement)
Supporting explanations
F-01: Path traversal / arbitrary file read
Input and flow: the path query parameter flows into raw_path, then MATERIALS_DIR / raw_path, then flask.send_file(target).
Missing control: no normalization, containment check, or allow-list. send_file does not confine paths to a directory; send_from_directory is the confining API.
Root cause (fact): pathlib / does not sandbox. .. segments are kept. An absolute raw_path replaces the base entirely. The endpoint has no authentication check.
Preconditions and impact: only network access. Any file readable by the process can be read: application source, config, and OS files. It also makes F-05 and F-06 easier to exploit. An empty path resolves to the directory itself and raises an exception, which feeds F-07.
Test: against a test instance, request /files?path=../<app file>, /files?path=/etc/hostname, and /files?path= and compare the responses. A contained implementation should return only files inside materials/, and should return the same error for non-existent and out-of-scope paths.
Confidence: high that traversal exists. Impact depends on file permissions of the runtime user.
F-02: Unauthenticated, unauthorized grade modification
Input and flow: the JSON body fields student_id, course_id, and grade go straight into find_grade, then either an append to GRADES or an overwrite of row["grade"].
Missing control: authentication, role check, and course-scope check.
Root cause (fact): the handler never reads flask.session. The role and courses values stored at login (L92, L94) are never consulted anywhere. The data model clearly anticipates course-scoped authorization (prof_srs has courses=["SRS"]), but nothing enforces it.
Preconditions and impact: only network access. Anyone can alter or create arbitrary grade records for any student and course, which is a direct integrity compromise.
Test:
Send an unauthenticated POST with a JSON body and then read the record back.
Repeat as alice (a student) and as prof_srs targeting SSD, a course not in their list.
Expected for a correct implementation: 401 for the first, 403 for the others.
CSRF note: Flask’s get_json() rejects non-JSON content types by default, which makes cross-site form CSRF harder. It is not a substitute for authentication (inferred).
Confidence: high.
F-03: Broken object-level authorization on profiles
Input and flow: the <student_id> URL segment goes through int() and a dictionary lookup, and the whole profile is returned (name, email, program).
Root cause (fact): no authentication and no ownership/role check. Identifiers are small sequential integers, and the 404 vs 200 difference lets a caller enumerate valid IDs.
Impact: disclosure of personal data (inferred sensitivity: emails are PII).
Test: request /students/1002/profile unauthenticated and as alice. A correct implementation should reject both. A professor’s access depends on policy, which is unknown (A1).
Confidence: high on the missing check. Whether the profile data is meant to be public is policy-dependent.
F-04: Broken object-level authorization on grades
Input and flow: <student_id> goes through int(), then a list filter, then a JSON response.
Root cause (fact): same as F-03. Grades are clearly the more sensitive data (inferred, as academic records). An unknown student ID returns [] rather than 404, but valid IDs are still enumerable by non-empty results.
Test: same matrix as F-03 against /grades/1001, including alice reading bob’s grades.
Confidence: high.
F-05: Debug mode exposed on all interfaces
Fact: debug=True with host="0.0.0.0".
Missing control: debug must be off outside local development, and any dev server should bind to loopback.
Impact: debug mode serves the Werkzeug interactive console at /console. Access is PIN-gated, but the PIN is derived from host-specific values (username, module paths, machine identifiers), some of which are file-readable. Hypothesis, not demonstrated: F-01 plus F-05 could chain into code execution. The catch-all handler (F-07) may suppress the in-page traceback debugger, but I would not assume it disables the console.
Preconditions: launched through the __main__ block (A3), with the port reachable.
Test: on a test instance, check whether /console responds and prompts for a PIN. Then check whether the PIN inputs are retrievable via the F-01 primitive. Do this only on your own instance.
Confidence: medium, because deployment is unknown.
F-06: Hard-coded session signing key
Fact: SECRET_KEY = "dev-secret-key", in source and guessable.
Impact: Flask sessions are client-side signed cookies. Anyone who knows the key can forge a cookie with role: "admin". Currently latent: no endpoint makes authorization decisions from the session (see F-02). It becomes critical as soon as authorization is added on top of it. The key is also readable through F-01.
Test: craft a cookie signed with this key using a standard Flask session serializer, then see whether /me accepts it as an arbitrary user.
Confidence: high on the fact. Impact is conditional.
F-07: Verbose errors and a catch-all handler
Flow: any exception goes to handle_error, which returns str(exc) and the exception class name with status 500.
Facts:
Exception text can include absolute paths (for example from a missing file in send_file), int() parse details, and KeyError field names, which helps an attacker map the server.
As far as I know, a handler registered for Exception in Flask also matches HTTPException subclasses. If so, 404, 405, and 415 responses would be rewritten as 500, which hurts clients and monitoring. I’m not certain of this version-specific behavior.
Test: request a nonexistent route, send a wrong method, and send /files?path=nope. Compare the status codes and body contents.
Confidence: high on disclosure, medium on the status-code behavior.
F-08: Missing input validation and type confusion
Facts:
int(student_id) on a URL string raises ValueError for non-numeric input (surfacing via F-07). Python’s int() also accepts forms such as " 1001" and "1_001", so several strings alias the same ID, which would undermine any string-based ACL added later.
update_grade does no type, range, or presence checks. A string "1001" will not match the integer rows in find_grade, so a duplicate record is appended. grade can be negative, huge, a string, or a nested object. Missing keys raise KeyError, and a body that isn’t valid JSON raises an error.
Mutation of the global list has no locking, so concurrent requests can race (check-then-append) on a threaded server.
Impact: data integrity corruption and uncontrolled error paths. Inferred requirement: grades should be numeric within a defined range.
Test: submit student_id as a string, grade as -5, 1e9, "A", and {}, then read the records back.
Confidence: high.
F-09: Weak credential handling and no brute-force protection
Facts:
Plaintext passwords stored and compared with != (not constant-time, not hashed).
Hard-coded, weak demo credentials in source.
No rate limiting or lockout on /login.
Notes: the error message is identical for unknown user and bad password, which is good. There is a minor timing difference because user is None short-circuits, which I rate negligible.
Impact: if these accounts exist outside a demo, trivial account takeover or credential reuse. Hashed storage and throttling are inferred requirements.
Test: send repeated failed logins and verify whether throttling kicks in. Confirm that the seeded credentials are absent from any real deployment.
Confidence: medium, since this may be intentional seed data.
F-10: Session lifecycle, cookie flags, CSRF
Facts:
No SESSION_COOKIE_SECURE or explicit SameSite setting (Flask’s defaults apply).
No session lifetime configured, and the cookie is signed but stateless.
/login and /logout are form-style POSTs with no CSRF token.
Impact:
logout only clears the client’s cookie, so a captured cookie stays valid until key rotation (no server-side revocation).
Login CSRF and forced logout are possible but low impact.
Without HTTPS (nothing here enforces it), cookies and credentials could be sniffed.
Test: replay a pre-logout cookie after logout. Inspect Set-Cookie attributes.
Confidence: medium, because the transport and deployment are unknown.
F-11: No audit logging
Inferred requirement: grade changes, logins, and failed access should be logged for accountability.
Fact: the code has no logging. Combined with F-02, unauthorized grade changes would leave no trace.
Test: perform a grade update and check for any record of who made it.
Confidence: medium, as this is a requirement inferred from the domain.
Limits of this review
Looked at but no finding: no database or SQL, no template rendering, and no shell invocation. Classic SQL injection, SSTI, and command injection surfaces are not visible. That says nothing about code not provided.
Minor: send_file infers the MIME type from the file. If an HTML file were ever reachable through F-01, content-type handling could matter. Hypothetical.
Not assessed: dependency and Flask/Werkzeug versions, deployment (reverse proxy, TLS, container user), and filesystem permissions.
Not proof of safety: the absence of a finding is not evidence that something is secure
