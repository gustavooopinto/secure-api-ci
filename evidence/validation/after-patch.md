# After patch

Run (all jobs green, image published to GHCR):
https://github.com/gustavooopinto/secure-api-ci/actions/runs/44388406343

Local: python -m pytest -v tests tests_security -> 20 passed
(5 original functional tests + 15 security tests).

## F02 (grade update authorization): R1, R3, R4, R7
All 6 previously failing tests now pass:
- unauthenticated update: 401, data unchanged
- update after logout: 401, data unchanged
- student updating own or another student's grade: 403, data unchanged
- professor of SRS updating SSD (existing row and new row): 403, data unchanged
Legitimate updates (assigned professor, admin) still pass.

## F01 (path traversal / file access): R1, R6, R7
All 6 previously failing tests now pass:
- unauthenticated download: 401
- "..", absolute path, nested traversal and symlink escape: 4xx (404), outside file not disclosed
- missing file: 4xx without leaking internal paths
Legitimate authenticated download still passes.

Positive tests (legitimate operations): 3 of 3 still pass.
Totals: 20 passed, 0 failed (locally and in CI).