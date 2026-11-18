# SAST baseline vs after patch

Same 9 findings (Bandit B104, B105, B106 x4, B201; Semgrep avoid_app_run_with_bad_host, debug-enabled).
Only line numbers changed (app.run: 159 -> 232) because the patches added code.
Neither tool detected F01 or F02 before or after; the authorization and
path-traversal repairs therefore do not change the scanner output.