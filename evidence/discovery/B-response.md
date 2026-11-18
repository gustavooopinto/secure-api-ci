Static Security Review: Academic-Services Flask API

Line numbers refer to the file as supplied (159 lines). I read only the source and the stated context.

Policy assumptions. The request does not define an access policy, so I assume the following (marked [A] where used):

[A1] Students may read only their own profile and grades.
[A2] Professors may read and modify grades only for their assigned courses.
[A3] Admins may do everything.
[A4] Teaching materials need at least a logged-in user, and files outside materials/ must never be served.

Systemic fact. No handler reads flask.session except /me (lines 105-112). role, student_id, and courses are written at login (lines 91-94) and never used in an authorization decision. There is no decorator, before_request hook, or ownership check anywhere in the file.

Findings table
ID	Title	Location	Severity (under assumptions)	Confidence
SS-01	Unauthenticated, unauthorized grade modification	update_grade, L128-142	Critical	High
SS-02	Path traversal / arbitrary file read	download_file, L144-148	Critical	High
SS-03	Missing authN/authZ on grade retrieval (IDOR)	get_grades, L122-126	High	High
SS-04	Missing authN/authZ on profile retrieval (IDOR) + ID enumeration	get_profile, L115-120	High	High
SS-05	Hardcoded, guessable session signing key	L8	High (latent, chains with SS-02)	High (fact) / Medium (impact)
SS-06	Debug mode on all interfaces	L159	High if deployed as written	Medium
SS-07	Verbose exceptions and filesystem oracle	handle_error, L150-155	Medium	High
SS-08	No input validation on grade writes	L130-140	Medium	High
SS-09	Plaintext hardcoded credentials, no brute-force control	L30, L36-43, L82-96	Medium (Low if demo-only)	High (fact) / Low (impact)
SS-10	Weak session lifecycle and no CSRF defenses	L8, L91-101	Low-Medium	Medium
Supporting explanations
SS-01: Unauthenticated, unauthorized grade modification
Location: update_grade, L128-142.
Input and flow: The JSON body fields student_id, course_id, and grade (L132-134) go to find_grade (L136). The code then either overwrites row["grade"] (L140) or appends a new record to the global GRADES (L138).
Missing control: Authentication, role check, and professor-to-course check. Fact: none exist. The route accepts any HTTP client, with no session needed.
Preconditions and impact: The only precondition is network reachability. Anyone can change or create any student’s grade in any course, which breaks integrity of the core academic data. Under [A2], even a legitimate student or a professor of another course could do this.
Test: From a client with no cookie, POST /grades/update with {"student_id":1001,"course_id":"SRS","grade":20}. A 200 with a changed value on GET /grades/1001 confirms the claim. Repeat as alice (student) and as prof_srs for course SSD. The claim is rejected if all three attempts return 401/403 and leave the data unchanged.
Confidence: High. Missing authorization is directly visible in the code. Only the policy ([A2]) is assumed, and even a minimal policy requires authentication.
SS-02: Path traversal / arbitrary file read
Location: download_file, L144-148.
Input and flow: The query parameter path (L146) becomes MATERIALS_DIR / raw_path (L147), which goes straight to flask.send_file (L148). There is no normalization, containment check, extension allow-list, or authentication.
Root cause: pathlib joining does not confine paths. .. segments are not collapsed before the OS opens the file, and an absolute raw_path replaces the base directory entirely (documented pathlib behavior).
Preconditions and impact: The only precondition is that the server process can read the target file. An attacker can read any file the process can, including app.py (which holds SECRET_KEY and every password, L8 and L36-43), environment or config files, and OS files. This yields a full secret compromise and chains to SS-05 and SS-06.
Test: Request GET /files?path=../<this_file>.py, GET /files?path=/etc/hostname (benign), and a canary file placed next to materials/ that is not meant to be served. Receiving the canary’s contents confirms the claim. Also test path= (empty) and path=. to confirm directory handling (see SS-07). The claim is rejected if every out-of-directory request returns 4xx with no content.
Confidence: High for traversal and absolute-path escape. Medium-High for the Windows-specific variants (drive-relative paths), which depend on the host OS.
Note [A4]: Even for in-directory files there is no authentication or per-course entitlement. Whether this is a flaw depends on the policy.
SS-03: Missing authN/authZ on grade retrieval (IDOR)
Location: get_grades, L122-126.
Input and flow: The URL segment student_id goes through int() (L124) and filters GRADES. The result is returned as JSON.
Missing control: Authentication, plus an ownership check (session["student_id"] == sid) or a role/course check. Fact: none exist.
Impact: Anyone can read every student’s grades by iterating IDs. Under [A1] this is a confidentiality breach of student records.
Test: GET /grades/1002 unauthenticated, then as alice. The claim is rejected if the first returns 401 and the second returns 403.
Note: int() accepts inputs such as " 1001", "+1001", "1_001", and non-ASCII digits. This is harmless now, but a future string-comparison ACL on the raw segment would be bypassable. Non-numeric input raises ValueError, which becomes a 500 (SS-07). Inference.
Confidence: High.
SS-04: Missing authN/authZ on profile retrieval (IDOR) and ID enumeration
Location: get_profile, L115-120.
Input and flow: student_id goes through int() (L117) and STUDENT_PROFILES.get. The response is either 404 or the profile, which includes name, email, and program.
Missing control: Same as SS-03.
Impact: Anyone can read PII. The 404 versus 200 difference also lets an attacker enumerate valid student IDs. Whether profile visibility is restricted is a policy question ([A1]). Emails and names are personal data, so the exposure is likely significant under typical institutional privacy rules.
Test: GET /students/1001/profile with no cookie, then as bob. Then compare the response for 1001 versus 9999.
Confidence: High for the missing control. Medium for impact, since the profile policy is unknown.
SS-05: Hardcoded, guessable session signing key
Location: L8, app.config["SECRET_KEY"] = "dev-secret-key".
Facts: Flask sessions are client-side signed cookies (the data is signed, not encrypted). The key is a literal in source and a common placeholder value. SS-02 can leak it.
Impact: An attacker who knows the key can forge a cookie with any user, role, student_id, or courses. Current effect is limited, because no endpoint authorizes from the session (see the systemic fact above). It becomes critical the moment authorization is added based on session data, which is the obvious remediation for SS-01, SS-03, and SS-04. The cookie contents are also readable by the client.
Test: Sign a cookie with the known key using Flask’s session serializer in a local copy of the app (not against production). Present {"user":"admin1","role":"admin"} and check whether /me echoes it. This confirms forgeability but not authorization impact.
Confidence: High that the key is weak and hardcoded. Medium on impact, because it depends on how authorization is later implemented.
SS-06: Debug mode on all interfaces
Location: L159, app.run(debug=True, host="0.0.0.0", port=5001).
Facts: The Werkzeug debugger and reloader are enabled and the server binds to all interfaces.
Inference: The Werkzeug interactive console (/console) allows code execution and is gated by a PIN derived from host attributes. If those attributes are readable through SS-02, the PIN may be recoverable, which would chain SS-02 to remote code execution. I have not verified this. It depends on the Werkzeug version and the environment.
Preconditions: The app is started via this __main__ block and is reachable from untrusted networks. The errorhandler(Exception) at L150 means the traceback page is not shown for ordinary exceptions, but I cannot confirm from source alone that the /console route is unaffected.
Test: In a local copy, request /console and check whether it responds with the console page. Separately, read the host files that feed the PIN derivation via SS-02 and test whether the PIN can be reconstructed.
Confidence: Medium. The configuration is a fact; the exploitability is inference.
SS-07: Verbose exceptions and filesystem oracle
Location: handle_error, L150-155.
Facts: Every exception, including HTTP errors like 404 and 405 (because HTTPException subclasses Exception), becomes a 500 JSON response containing str(exc) and the class name.
Impact: Messages leak internals: absolute paths (FileNotFoundError), key names (KeyError from L132-134), and parse details. On /files, distinct exception types act as an oracle: FileNotFoundError (missing), IsADirectoryError or PermissionError (exists but not readable), and a normal 200 (readable). This lets an attacker map the filesystem even without reading file contents. The handler also masks correct status codes (404 and 405 become 500), which hurts monitoring and client behavior.
Test: Request /files?path=nonexistent, /files?path=, /files?path=../, /grades/abc, and a nonexistent route. Inspect status codes and messages. The claim is rejected if responses are generic and use correct status codes.
Confidence: High for the disclosure. The exact exception types for send_file on directories vary by Werkzeug version (assumption).
SS-08: No input validation on grade writes
Location: L130-140.
Facts: data is not checked for None (a missing or wrong content type can cause a TypeError, or a 415 on newer Flask). student_id, course_id, and grade have no type, range, or existence checks. Missing keys raise KeyError.
Impact: Even after authentication is added, a caller could write grade: -5, grade: "A", grade: null, or course_id: "ANYTHING", or create records for nonexistent students. A string student_id such as "1001" fails to match the integer records at L58 and creates a duplicate record, so reads (which compare against int) and writes diverge. Concurrent writes to the shared list have no locking. Inference: this is likely an integrity risk under a threaded server.
Test: After authentication exists (or against the current open endpoint), send {"student_id":"1001","course_id":"SRS","grade":999}, then a body with a missing field, then non-JSON. Check GET /grades/1001 for duplicates or invalid values.
Confidence: High for the missing validation. The valid grade range is an assumption (e.g. 0-20 in the Portuguese scale).
SS-09: Plaintext hardcoded credentials, no brute-force control
Location: L30, L36-43 (password: str and the USERS dict), L82-96 (login).
Facts: Passwords are stored and compared in plaintext (user.password != password, L88) with a non-constant-time comparison. There is no rate limiting, lockout, or logging. The credentials are trivially weak and committed in source (alicepw, adminpw, and so on).
Impact: Given the context (“teaching environment”), the stored credentials may be intentional seed data, so impact depends on deployment. Anyone who reads the source (including via SS-02) can log in as admin1. Without rate limiting, any real password would be guessable online. The timing leak is likely not practically exploitable here, and I rate that sub-point Low.
Test: Send repeated failed POST /login attempts and check for throttling. In a review of production configuration, check whether any of these accounts exist.
Confidence: High for the facts. Low for real-world impact, given the stated teaching scope.
SS-10: Weak session lifecycle and no CSRF defenses
Location: L8, L91-101.
Facts: Flask defaults apply. Secure and SameSite are not set. logout only clears the client’s cookie (L100), and there is no server-side session store or revocation. There are no CSRF tokens on state-changing routes (/login, /logout, /grades/update).
Inference: A copied or stolen cookie stays valid after logout until it expires (the default permanent lifetime is 31 days, assuming default configuration). CSRF against /grades/update is partly mitigated if the Flask version enforces the JSON content type, but that is a framework behavior, not an application control. Once authentication is added to SS-01, CSRF becomes relevant. Login CSRF is also possible.
Test: Capture a session cookie, log out, replay the cookie against /me. From a different origin, submit a cross-site request to /grades/update with a logged-in browser.
Confidence: Medium. These depend on deployment (HTTPS, browser SameSite defaults) and the Flask version.
Not found, and not assessed
Not present in this source: SQL or command injection sinks, template rendering (no SSTI or reflected XSS vector, since responses are JSON), and open redirects (redirect("/me") at L96 is a constant).
Not assessable from this file: dependency versions, TLS termination, reverse proxy or WAF behavior, file permissions on the host, and the real deployment topology.
Caveat: The absence of other findings is not evidence of safety. This is a single-file static review with assumed policy.
Likely attack chain

SS-02 (read app.py) → SS-05 and SS-09 (obtain the key and credentials) → SS-06 (a possible path to code execution) combined with SS-01, SS-03, and SS-04, all unauthenticated. Priority should follow that order: the missing authorization layer (SS-01, SS-03, SS-04) and the file read (SS-02) are the most urgent.
