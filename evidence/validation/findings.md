# Consolidated findings table

Model used for discovery: Claude Sonnet 5.5 (claude.ai, free plan, no tools), 2026-11-18.
SAST baseline reports: evidence/discovery/sast/ (Bandit and Semgrep).

| ID | Root cause / operation | Bandit | Semgrep | A | B | C | Status | Evidence |
|----|------------------------|--------|---------|---|---|---|--------|----------|
| F01 | Path traversal in GET /files (no containment) | not detected | not detected | yes | yes | yes | Confirmed | tests_security/test_file_access.py; before-patch.md; https://github.com/gustavooopinto/secure-api-ci/actions/runs/44379397460 |
| F02 | No authN/authZ (role + course) in POST /grades/update | not detected | not detected | yes | yes | yes | Confirmed | tests_security/test_grade_authorization.py; before-patch.md; https://github.com/gustavooopinto/secure-api-ci/actions/runs/44379397460 |
| F03 | No authN/ownership check in GET /students/<id>/profile | not detected | not detected | yes | yes | yes | To confirm | |
| F04 | No authN/ownership/course filter in GET /grades/<id> | not detected | not detected | yes | yes | yes | To confirm | |
| F05 | No input validation in grade update | not detected | not detected | yes | yes | yes | To confirm | |
| F06 | student_id parsed with int() (0, negatives, aliases) | not detected | not detected | partial | partial | yes | To confirm | |
| F07 | Catch-all handler leaks details, 4xx become 500 | not detected | not detected | yes | yes | yes | To confirm (check in Flask) | |
| F08 | Debug mode + bind 0.0.0.0 | B201, B104 | avoid_app_run_with_bad_host, debug-enabled | yes | yes | yes | Confirmed | line 159, SAST reports |
| F09 | Hardcoded SECRET_KEY | B105 | not detected | yes | yes | yes | Confirmed | line 8, bandit.json |
| F10 | Plaintext hardcoded credentials, no rate limit | B106 (hardcoded only) | not detected | yes | yes | yes | Confirmed (hardcoded); rate limit to confirm | lines 37-42 |
| F11 | Cookie flags, CSRF, no server-side logout | not detected | not detected | yes | yes | yes | Unverified | |
| F12 | No audit logging | not detected | not detected | yes | no | no | Policy-dependent | not in R1-R7 |
| F13 | Race condition on GRADES | not detected | not detected | partial | partial | yes | Unverified | |
