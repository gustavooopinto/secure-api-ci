# Selected vulnerabilities

1. F02, authorization: POST /grades/update has no authentication, role or
   course check (violates R1, R3, R4, R7). Not detected by Bandit or Semgrep;
   detected by LLM conditions A, B and C.
2. F01, file access: GET /files has no path containment
   (violates R1, R6, R7). Not detected by Bandit or Semgrep;
   detected by LLM conditions A, B and C.

Different root causes: missing per-user/per-course authorization versus
missing path containment.
