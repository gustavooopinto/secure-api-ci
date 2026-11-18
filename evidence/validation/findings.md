# Consolidated findings table

Model used for discovery: Claude Sonnet 5.5 (claude.ai, free plan, no tools), 2026-11-18.
SAST baseline reports: evidence/discovery/sast/ (Bandit and Semgrep).

Runs:
- Before patch (security tests failing, build skipped): https://github.com/gustavooopinto/secure-api-ci/actions/runs/44379397460
- After patch (all jobs green): https://github.com/gustavooopinto/secure-api-ci/actions/runs/44388406343

| ID | Root cause / operation | Bandit | Semgrep | A | B | C | Status | Evidence |
|----|------------------------|--------|---------|---|---|---|--------|----------|
| F01 | Path traversal in GET /files (no containment, no authentication) | not detected | not detected | yes | yes | yes | Confirmed, repaired | tests_security/test_file_access.py; before-patch.md; after-patch.md; before and after runs above |
| F02 | No authN/authZ (role + course) in POST /grades/update | not detected | not detected | yes | yes | yes | Confirmed, repaired | tests_security/test_grade_authorization.py; before-patch.md; after-patch.md; before and after runs above |
| F03 | No authN/ownership check in GET /students/<id>/profile | not detected | not detected | yes | yes | yes | Confirmed (code reasoning), not repaired | get_profile never reads the session; LLM repair answers also flag it as the same class of flaw |
| F04 | No authN/ownership/course filter in GET /grades/<id> | not detected | not detected | yes | yes | yes | Confirmed (code reasoning), not repaired | get_grades never reads the session; same note as F03 |
| F05 | No input validation in grade update | not detected | not detected | yes | yes | yes | Confirmed (code), repaired as part of F02; no dedicated test | update_grade validation added in the F02 patch |
| F06 | student_id parsed with int() (0, negatives, aliases, 500 on non-numeric) | not detected | not detected | partial | partial | yes | Unverified | not tested; still present in /grades/<id> and /profile |
| F07 | Catch-all handler leaks details, 4xx become 500 | not detected | not detected | yes | yes | yes | Confirmed, partially repaired | leak of str(exc) and class name removed (F01 test checks no path leak); 404/405 still become 500 |
| F08 | Debug mode + bind 0.0.0.0 | B201, B104 | avoid_app_run_with_bad_host, debug-enabled | yes | yes | yes | Confirmed, not repaired | line 159, SAST reports |
| F09 | Hardcoded SECRET_KEY | B105 | not detected | yes | yes | yes | Confirmed, not repaired | line 8, bandit.json |
| F10 | Plaintext hardcoded credentials, no rate limit | B106 (hardcoded only) | not detected | yes | yes | yes | Confirmed (hardcoded credentials); rate limit Unverified | lines 37-42, bandit.json |
| F11 | Cookie flags, CSRF, no server-side logout | not detected | not detected | yes | yes | yes | Unverified | not tested |
| F12 | No audit logging | not detected | not detected | yes | no | no | Policy-dependent | not required by R1-R7 |
| F13 | Race condition on GRADES (no locking) | not detected | not detected | partial | partial | yes | Unverified | not tested; low impact in this teaching setup |