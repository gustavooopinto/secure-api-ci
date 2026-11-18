# F02: final implementation notes

Applied the LLM patch by hand (the hunk offsets were hand-written, so git apply was not used).
Changes vs the original suggestion: none in logic.

Review: returns 401/403 directly (no abort(), since the catch-all handler would turn them into 500);
course is checked from the request, so creating a new row in an unassigned course is denied;
validation runs before any mutation.
Result locally: the 6 F02 security tests pass, the 5 original functional tests still pass;
only the 6 F01 file-access tests still fail (F01 not yet repaired).