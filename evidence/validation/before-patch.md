# Before patch

Run (security tests failing, build skipped):
https://github.com/gustavooopinto/secure-api-ci/actions/runs/44379397460

## F02 (grade update authorization): violates R1, R3, R4, R7
- test_unauthenticated_update_denied_and_unchanged: expected 401, got 200
- test_student_cannot_update_own_grade: expected 403, got 200
- test_student_cannot_update_another_student: expected 403, got 200
- test_professor_cannot_update_unassigned_course: expected 403, got 200
- test_professor_cannot_create_row_in_unassigned_course: expected 403, got 200
- test_update_denied_after_logout: expected 401, got 200

## F01 (path traversal / file access): violates R1, R6, R7
- test_unauthenticated_download_denied: expected 401, got 200
- test_dotdot_traversal_blocked: expected 4xx, got 200 (file outside materials/ served)
- test_absolute_path_blocked: expected 4xx, got 200
- test_nested_traversal_blocked: expected 4xx, got 200
- test_symlink_escape_blocked: expected 4xx, got 200
- test_missing_file_error_does_not_leak_internal_path: expected 4xx, got 500

Positive tests (legitimate operations): 3 of 3 pass
(assigned professor update, admin update, authenticated download).
Totals: 12 failed, 3 passed (same locally and in CI).