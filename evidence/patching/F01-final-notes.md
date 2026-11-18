# F01: final implementation notes

Applied by hand (hunk offsets were hand-written; git apply not used).
Manual correction vs the LLM suggestion: the LLM computed MATERIALS_ROOT once at
import time, which ignores monkeypatching of api.MATERIALS_DIR in the tests and
would make the tests exercise the real materials/ folder. I resolve the root
inside _resolve_material from the current MATERIALS_DIR instead. Other logic
unchanged.

Review: login required before reading input (401); resolve(strict=True) +
is_relative_to handles "..", absolute paths, nested traversal and symlinks;
uniform 404 avoids a filesystem oracle; no abort(), so the catch-all handler
does not turn responses into 500.
Result locally: 20 passed (5 original, 15 security).
Note: the first push after applying the patch (commit fd48680) referenced _resolve_material before the helper was defined; it was fixed in the next commit (7add7ba), after which all 20 tests passed.
