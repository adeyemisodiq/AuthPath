# Changes since the first upload

Fixed
- `in` / `not_in` never matched role lists (`subject.roles`). Now list-aware; added `contains`.
- Non-applicable policies returned `deny`; now `not_applicable`, combined by a policy set with deny-overrides + default-deny.
- Tests only printed PASS/FAIL and always exited 0; replaced with pytest asserts.
- Executor: added timeout, transport-error handling, no redirect following, no proxies, request bodies, scope guard.
- Analyzer: 404 -> deny; 2xx with JSON error body -> deny; 3xx -> unknown.
- Renamed `engine/test_generator.py` -> `generator.py` and `TestCase` -> `AuthzCase` (pytest collection traps).

Added
- Scenario loader (JSON) with validation; `policies/lab_scenario.json`.
- Evaluator (PASS / VIOLATION / OVER_RESTRICTION / INCONCLUSIVE, OWASP category).
- Runner, evidence recorder with `manifest.sha256`, markdown report, retest comparison, CLI.
- Lab API: PUT/DELETE/admin endpoints, users/roles, vulnerable/patched/regressed modes, reset endpoint.
