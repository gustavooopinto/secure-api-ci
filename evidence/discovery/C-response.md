Static Security Review: Academic-Services REST API

Scope and method. I reviewed only the supplied source and the stated requirements R1–R7. Line numbers are approximate, counted from the supplied text. “Code fact” means directly visible in the source. “Requirement” means taken from R1–R7. “Inferred” means a security expectation not stated in R1–R7, with the policy assumption given. This is not a proof of safety, and I did not examine Flask/Werkzeug internals beyond well-known behavior.

Findings table
ID	Title	Location	Req.	Severity	Confidence
SEC-01	No authentication on protected endpoints	get_profile, get_grades, update_grade, download_file (~115–148)	R1, R7	Critical	High
SEC-02	Profile access has no ownership or role check	get_profile (~115–120)	R2, R3, R4	High	High
SEC-03	Grade list is not filtered by requester	get_grades (~122–126)	R2, R3, R4	High	High
SEC-04	Grade update has no authorization or course scope	update_grade (~128–142)	R3, R4	Critical	High
SEC-05	Grade update input validation is absent, so invalid records can be created	update_grade (~130–140)	R5, R7	High	High
SEC-06	Path traversal / arbitrary file read	download_file (~144–148)	R6	Critical	High
SEC-07	Hardcoded SECRET_KEY allows session forgery	line ~8; session use ~91–94	R1–R4 (inferred)	High	High (key) / Medium (impact)
SEC-08	Catch-all handler leaks exception details and mis-codes errors	handle_error (~150–155)	R7	Medium	High
SEC-09	Student ID path parameters parsed unsafely	get_profile ~117, get_grades ~124	R5, R7	Medium	High
SEC-10	Flask debug mode bound to all interfaces	app.run (~159)	R7 (inferred)	High if deployed this way	Medium
SEC-11	Plaintext hardcoded credentials, no brute-force control	USERS ~36–43, login ~88	Inferred	Medium	Medium
SEC-12	Session cookie hardening / CSRF posture	login, logout (~82–101)	Inferred	Low	Low–Medium
SEC-13	Non-atomic in-memory read-modify-write	update_grade (~136–140)	Inferred	Low	Low–Medium
Supporting explanations
SEC-01: No authentication on protected endpoints
Location: The four handlers named above. None reads flask.session.
Input and flow: An unauthenticated HTTP request goes straight to the data access or file read.
Missing control and root cause: Code fact: authentication is checked only in me(). There is no shared guard or decorator, so each protected route lacks it.
Preconditions and impact: The attacker needs only network access. Impact: unauthenticated read of profiles, grades and files, and unauthenticated grade modification. R1 and R7 require 401 here.
Test: Without cookies, call each of the four endpoints. Expected 401 on all, and unchanged GRADES after the POST. The current code should return 200.
Assumptions and confidence: No upstream proxy or middleware is assumed, since none is in the source. High.
SEC-02: Profile access has no ownership or role check
Location: get_profile.
Input and flow: The student_id path segment goes to int() and then to the STUDENT_PROFILES lookup. The result is returned if found.
Missing control and root cause: Code fact: the session is never consulted. Requirement: students may read only their own profile (R2). Professors may read no profiles (R3). Admins may read any. An ID alone grants no permission (R4).
Preconditions and impact: Any caller, authenticated or not, can enumerate names, emails and programs. Student IDs are small sequential integers. A 404 versus 200 difference also lets callers enumerate valid IDs.
Test: Log in as alice and request /students/1002/profile, expecting 403. Log in as prof_srs and request /students/1001/profile, expecting 403. Log in as admin1 and request either profile, expecting 200.
Assumptions and confidence: R3 is read literally, so professors are denied all profiles. Whether an unauthorized request for a nonexistent ID should be 403 or 404 is unspecified, and I assume 403 to avoid an existence oracle. High.
SEC-03: Grade list is not filtered by requester
Location: get_grades.
Input and flow: student_id goes to int(), then a comprehension filters GRADES by that ID only and returns every match.
Missing control and root cause: Code fact: no filter on requester identity, role or course. Requirement: students see only their own grades. Professors see only rows for their assigned courses. Admins see all. A request with no permitted rows is denied (R4).
Preconditions and impact: Any caller can read every student’s grades, including courses a professor does not teach.
Test: As alice, request /grades/1002, expecting 403. As prof_srs, request /grades/1001, expecting only the SRS row and not SSD. Request a student who has only SSD grades, expecting 403 and not []. As admin1, request /grades/1001, expecting both rows.
Assumptions and confidence: For an authorized student whose own record set is empty, R4 is ambiguous, so I do not assert a status code. High.
SEC-04: Grade update has no authorization or course scope
Location: update_grade.
Input and flow: JSON student_id, course_id and grade go to find_grade, then either GRADES.append or an in-place overwrite.
Missing control and root cause: Code fact: no session, role or course check. Requirement: only admins, or professors for their own assigned courses, may update (R3, R4). Students must be denied.
Preconditions and impact: Any caller can set any grade, including a student changing their own. This is a direct integrity compromise.
Test: As alice, POST a grade for herself, expecting 403 and unchanged data. As prof_srs, POST a grade for SSD, expecting 403, and for SRS, expecting 200. Compare GRADES before and after each denied request.
Assumptions and confidence: Professor scope is read from courses. Whether a professor may create a grade row for a student not previously graded in that course is unspecified. High.
SEC-05: Grade update validation is absent
Location: ~130–140.
Input and flow: data is used without a type check. Fields are read by subscript, then values are stored verbatim.
Missing control and root cause: Code fact: no checks that the body is an object, that student_id is a positive existing integer, that course_id is in {SRS, SSD}, or that grade is numeric and within 0–20. Booleans are not rejected. In Python bool is a subclass of int, so true would be accepted as 1 by a naive check. Missing keys raise KeyError. A non-object body raises TypeError, which handle_error turns into a 500 (see SEC-08). A missing JSON body or wrong content type also ends in 500 through the catch-all handler.
Preconditions and impact: Anyone able to reach the endpoint, which today is anyone, can inject rows for nonexistent students or courses, out-of-range or boolean grades, or string IDs such as "1001". Because find_grade uses ==, 1001.0 matches 1001 but "1001" does not, producing duplicate or orphan rows that corrupt later reads.
Test: Send each of these as an authorized user and expect 400 with unchanged GRADES: a missing field, a list body, grade of 21, -1, true, "15", NaN or Infinity, an unknown course_id, a nonexistent student_id, and a string or float student_id.
Assumptions and confidence: Python’s default JSON parser accepts NaN and Infinity literals, which I am inferring from standard behavior. Floats between 0 and 20 are assumed valid under “numeric”. High.
SEC-06: Path traversal / arbitrary file read
Location: download_file.
Input and flow: The query parameter path is joined with MATERIALS_DIR using pathlib and passed to flask.send_file.
Missing control and root cause: Code fact: no normalization or containment check. Two relevant pathlib behaviors: .. segments are not collapsed, and joining with an absolute path (for example /etc/passwd) discards the base directory. send_file does not itself confine to a directory. Requirement R6 is violated. Other effects: an empty path resolves to the directory itself, which causes an error and a 500 (SEC-08). Symlinks inside materials/ would also not be contained.
Preconditions and impact: Needs network access, and currently no authentication (SEC-01). Impact: reading any file the process can read, including app.py (which contains SECRET_KEY), environment-adjacent files, and OS files. Combined with SEC-07 this enables privilege escalation.
Test: Request path=../app.py, path=/etc/passwd, path=..%2fapp.py, path= and path=srs-summary.txt. Expect 403 or 400 for all except the last, which should return 200 when authenticated.
Assumptions and confidence: Linux deployment is assumed. On Windows, drive-letter paths would behave similarly. High.
SEC-07: Hardcoded SECRET_KEY allows session forgery
Location: line ~8. The session contents are set at ~91–94.
Input and flow: Flask signs the session cookie with this key. The session carries user, role, student_id and courses, and the client holds the cookie.
Missing control and root cause: Code fact: the key is a fixed, guessable string in source. Anyone who has the key can forge a cookie with role: "admin". Role and scope are also stored client-side and are not revalidated against USERS, so changes to a user are not reflected until the cookie expires.
Preconditions and impact: The attacker needs the key. It is in the source, which the exercise treats as visible, and SEC-06 can also read it from a running server. Impact: complete bypass of any session-based authorization added later.
Test: Sign a cookie locally with this key and role admin, then call an admin-only path and confirm access. After remediation, confirm that the old key no longer validates.
Assumptions and confidence: I assume the source or this default may be exposed. Medium on real-world impact. Impact depends on key secrecy at deployment time.
SEC-08: Catch-all handler leaks details and mis-codes errors
Location: handle_error.
Input and flow: Any exception, including Werkzeug HTTPException subclasses, becomes a 500 JSON body containing str(exc) and the exception class name.
Missing control and root cause: Code fact: the response includes implementation detail. It also converts 400, 404, 405 and 415 into 500, because HTTPException is an Exception. Examples: KeyError: 'grade', invalid literal for int() and filesystem error text, which may include absolute paths. R7 requires appropriate client errors with no internal detail.
Preconditions and impact: Any malformed request triggers it. Impact is reconnaissance (paths, types, library behavior).
Test: Send malformed JSON, a missing field, a non-numeric ID, an empty or directory path, and an unknown route. Inspect status codes and bodies. Expect 4xx and generic messages, with no class names or paths.
Assumptions and confidence: Handler precedence behavior is from my knowledge of Flask, not verified here. High.
SEC-09: Student ID path parameters parsed unsafely
Location: int(student_id) at ~117 and ~124.
Input and flow: A raw string path segment goes straight to int().
Missing control and root cause: Code fact: no check that the ID is a positive integer (R5). Non-numeric input raises ValueError, which becomes a 500 with detail. Zero and negative values pass parsing. int() also accepts surrounding whitespace, a leading +, underscores (1_001) and non-ASCII digits, so several textual forms map to the same ID. That matters if authorization later compares strings or applies a policy keyed to the raw segment.
Preconditions and impact: Any caller. Impact is error leakage now, and a possible authorization-bypass pattern later if the check and the lookup parse differently.
Test: Request /grades/abc, /grades/0, /grades/-1, /grades/%2B1001, /grades/1_001, /grades/%201001. Expect 400 for all.
Assumptions and confidence: Whether to answer a non-positive ID with 400 or 404 is a policy choice. R5 implies 400. High.
SEC-10: Debug mode on all interfaces
Location: app.run(debug=True, host="0.0.0.0", port=5001).
Input and flow: When the file is run directly, the Werkzeug development server listens on every interface with the debugger and reloader enabled.
Missing control and root cause: Code fact: both settings are hardcoded. The interactive debugger console is a known remote-code-execution risk and is protected only by a PIN. R7 also forbids tracebacks in responses.
Preconditions and impact: Applies only if the app is started via __main__ and the port is reachable by an attacker. Impact could be code execution if the console or its PIN is compromised.
Test: Start it as written and probe /console from another host. Check whether the interactive debugger responds.
Assumptions and confidence: Whether the exercise environment is isolated is unknown. Medium.
SEC-11: Plaintext credentials and no brute-force control
Location: USERS and login.
Input and flow: Form username and password are compared in plaintext with !=.
Missing control and root cause: Code fact: passwords are stored and compared in plaintext, they are trivially guessable, and there is no rate limit or lockout. The comparison is not constant-time, and an unknown user returns faster than a wrong password. R1 does not state password policy, so this is inferred.
Preconditions and impact: Network access. Impact: account takeover by guessing, and credential exposure if the source leaks.
Test: Script repeated failed logins and confirm none is throttled. Time known versus unknown usernames.
Assumptions and confidence: Accounts are assumed demo-only. Medium.
SEC-12: Session cookie hardening and CSRF posture
Location: login and logout.
Input and flow: The session cookie is set with Flask defaults. Login takes form-encoded data and logout takes no token.
Missing control and root cause: Code fact: no explicit SESSION_COOKIE_SECURE, SAMESITE or CSRF token. update_grade reads JSON, which in current Flask normally requires an application/json content type, making cross-site form-based CSRF less likely, but this is not verified here. /logout and /login remain CSRF-able for nuisance and login-CSRF.
Preconditions and impact: Needs a victim browser and a malicious page. Impact is low today. It becomes more important once authentication is added to state-changing routes.
Test: Inspect Set-Cookie after login. Attempt a cross-origin form POST to /logout.
Assumptions and confidence: Deployment over HTTPS is unknown. Low–Medium.
SEC-13: Non-atomic in-memory read-modify-write
Location: find_grade then append or overwrite.
Input and flow: Two concurrent updates for the same (student, course) can both see “not found” and each append.
Missing control and root cause: Code fact: no locking. The threaded dev server allows this. Multi-process deployments would also diverge in state.
Preconditions and impact: Needs concurrent writes, and today anyone can write. Impact: duplicate rows, and find_grade returning only the first, giving inconsistent grade reads.
Test: Fire many parallel identical updates for a new pair and count the resulting rows.
Assumptions and confidence: Treated as a correctness issue since the datastore is stated to be a teaching simplification. Low–Medium.
Notes on coverage
Checked and not flagged: /me returning {"user": null} when unauthenticated matches R1. The index and login being public is permitted. Login redirects only to a fixed local path.
Not assessable from source: the deployment topology, reverse-proxy behavior, library versions, and the filesystem layout of materials/ such as symlinks or writable uploads.
Open policy points where I assumed a behavior: the 403 versus 404 choice for nonexistent resources, the status for an authorized requester with zero rows, and whether professors may create new grade rows.
