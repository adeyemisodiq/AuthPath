# AuthPath

**Automated API authorization testing.** You write down who should be able to do what (a policy). AuthPath turns that into test cases, sends the real requests, and reports every place the API's behaviour disagrees with the policy, with reproducible evidence, severity ratings, remediation advice, a fix-and-retest workflow and regression detection.

**Problem:** APIs often authenticate correctly but authorize incorrectly (BOLA/IDOR, function-level access, over-shared fields). Generic scanners cannot know the intended access rules, so they miss these.

**Impact:** intended access rules become executable tests. Unauthorized access is found before release, and a later change that silently reopens it is caught.

**Proof:** Attack -> Evidence -> Fix -> Retest -> Regression against the bundled Lab API (see Demo), plus a run against a second, separate application (see Real-target validation). Every run writes hashed evidence any reviewer can re-verify.

## Architecture

```
policies/lab_scenario.json   (subjects, resources, policies, endpoint bindings)
            |
  authpath/config.py         load + validate
            |
  engine/generator.py        policy set  ->  expected allow/deny per case
            |                (engine/policy_evaluator.py, engine/condition.py)
  runner.py  ---- api/executor.py ----> target API   (scope-guarded)
            |         |                 (header identity or session-cookie login)
            |   api/response_analyzer.py   HTTP response -> allow/deny/unknown
            |
  engine/evaluator.py        expected vs observed -> PASS / VIOLATION /
            |                OVER_RESTRICTION / INCONCLUSIVE (+ OWASP category)
            |                + data-exposure check on the response body (API3)
  evidence/recorder.py       results.json, results.csv, report.md, report.html,
            |                manifest.sha256
  reporting/report.py        findings with severity, remediation, curl reproduction
  reporting/retest.py        FIXED / STILL_FAILING / REGRESSION comparison
```

## Quick start (Windows PowerShell, Python 3.10+)

```
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt     # only needed for the tests
python -m pytest -q                           # 144 tests
```

AuthPath itself uses only the Python standard library.

## Demo: attack -> fix -> retest -> regression

Run each Lab API mode on its own port, so you never have to restart a server mid-demo. Use three terminals.

```
# Terminal 1
python -m lab_api.main --mode vulnerable --port 8001

# Terminal 2
python -m lab_api.main --mode patched --port 8002

# Terminal 3
# 1. Vulnerable release
python -m authpath run --scenario policies\lab_scenario.json --label demo-vulnerable --base-url http://127.0.0.1:8001
#   -> 28 cases, 16 pass, 12 VIOLATION, 8 data-exposure findings

# 2. Patched release
python -m authpath run --scenario policies\lab_scenario.json --label demo-patched --base-url http://127.0.0.1:8002
#   -> 28 cases, 28 pass, 0 VIOLATION (4 data-exposure findings remain, see below)

python -m authpath compare --before reports\demo-vulnerable\results.json --after reports\demo-patched\results.json
#   -> FIXED: 12, PASS_UNCHANGED: 16
```

Regression check (a later release that reopens a hole):

```
python -m lab_api.main --mode regressed --port 8003          # separate terminal
python -m authpath run --scenario policies\lab_scenario.json --label demo-regressed --base-url http://127.0.0.1:8003
python -m authpath compare --before reports\demo-patched\results.json --after reports\demo-regressed\results.json
#   -> REGRESSION: 4
```

Evidence integrity:

```
python -m authpath verify reports\demo-vulnerable
```

Each run also writes `report.html` (open it in a browser). Add `--strict` to `run` / `compare` to get exit code 1 on findings or regressions (for CI).

## Real-target validation (SecurePay)

AuthPath was also pointed at SecurePay, a separate Flask application that logs users in with session cookies. SecurePay is not bundled in this repository. The scenario file is `policies/securepay_scenario.json` and expects the app on `http://127.0.0.1:5000`.

Result: `total=12 pass=8 violation=4 data_exposure=2`.

- A non-owner could read another user's transactions (BOLA, API1).
- Ordinary users could call the admin-only user list (BFLA, API5).
- That same response leaked every user's `password_hash` (API3, High).

The findings match vulnerabilities already annotated in that application's own code. AuthPath was not told where they were.

## Verdicts

| Expected | Observed | Verdict | Meaning |
|---|---|---|---|
| deny | allow | VIOLATION | security failure (BOLA API1:2023 for object-level, BFLA API5:2023 for function-level bindings) |
| allow | deny | OVER_RESTRICTION | functional failure, legitimate access broken |
| same | same | PASS | |
| any | unknown | INCONCLUSIVE | never a silent pass |

A PASS can still carry a data-exposure finding (see below).

## Policy model

A policy applies when subject type, action and resource type match and its optional condition is true. Otherwise it is `not_applicable` (silent). Policy sets use **deny-overrides** and **default-deny**.

Condition operators: `equals`, `not_equals`, `in`, `not_in`, `contains`, `exists`, `all`, `any`. Operands starting with `subject.` / `resource.` are paths; anything else is a literal.

## Severity, data exposure and remediation

**Severity.** Every finding gets a label:

- **High**: destructive or admin actions allowed, a function-level bypass on a sensitive resource, or any exposed sensitive field.
- **Medium**: an object-level violation (for example reading someone else's record) that is a plain read.
- **Low**: an OVER_RESTRICTION (a functional bug, not a security one).

**Excessive data exposure (OWASP API3:2023).** BOLA/BFLA testing only asks whether a subject should be let through the door at all. It can pass completely while the response body still hands back a field only a more privileged role should see. Declare this in the scenario:

```json
"admin_roles": ["admin"],
"sensitive_fields":  { "account": ["balance"] },
"admin_only_fields": { "account": ["internal_risk_score"] }
```

- `sensitive_fields`: visible to the resource's owner or an admin role, hidden from everyone else.
- `admin_only_fields`: visible to an admin role only, even the resource's own owner should not see it.

The Lab API demonstrates this deliberately. In patched mode object-level authorization is fully correct (28/28 PASS), yet every owner who reads or updates their own account still receives `internal_risk_score`. AuthPath flags this as a High-severity finding on a PASS verdict. A clean allow/deny scorecard is not the same as "nothing is wrong." The check also inspects list-shaped responses (for example `{"users": [...]}`).

**Remediation.** Every finding carries short, specific fix notes in `report.md` and `report.html`:

- BOLA (API1): add a server-side ownership or relationship check, not just an authentication check.
- BFLA (API5): add a role/permission check on the endpoint itself.
- OVER_RESTRICTION: the policy or endpoint logic is likely too strict for a legitimate case.
- Data exposure (API3): strip the named field for subjects who are not entitled to it, and build responses per role.

A finding can need two fixes at once. AuthPath lists both, because fixing only one would leave the other bug in place.

## Authentication modes

- **Header identity** (Lab API): the scenario names an identity header such as `X-User-ID`.
- **Session-cookie login** (SecurePay): the scenario's `auth` block logs each subject in once and reuses the session cookie. See `policies/securepay_scenario.json` for a working example.

## Building a scenario faster

The scenario file is written once per target and reused on every run. Three helpers reduce the typing:

1. **OpenAPI import.** If the target has a Swagger/OpenAPI spec saved as JSON:
   ```
   python -m authpath import-openapi --spec my_api_openapi.json --out policies\draft_bindings.json
   ```
   It drafts each endpoint's action, resource type and authorization level from the URL shape, marked as guesses to review. It can only draft what exists, never who should be allowed to use it.
2. **Owner-based defaults.** Instead of one policy per action, add:
   ```json
   "policy_defaults": [
     { "resource": "account", "actions": ["read", "update"], "admin_roles": ["admin"] }
   ]
   ```
   This expands into real policies at load time. A hand-written `"decision": "deny"` policy still overrides a default allow.
3. **Guided wizard (experimental).** `python -m authpath init --out policies\my_scenario.json` asks plain questions and writes the file. It works, but interactive input is fiddly, and hand-written JSON is the recommended path.

## Design decisions

- **Separation of duties.** The executor records what happened, the analyzer decides what authorization behaviour that indicates, and the evaluator checks whether it matches the policy. Each is unit-tested alone.
- **Default-deny + deny-overrides** is the standard fail-safe combination.
- **404 = deny.** Every tested resource is known to exist in the scenario, so a 404 means the API hides it from that subject.
- **State reset before every case.** Destructive tests (DELETE) cannot corrupt later results, and runs are deterministic.
- **Scope guard.** Requests are loopback-only unless a scenario explicitly opts out with `allow_non_loopback`, checked before any network call. Redirects are not followed and system proxies are ignored. Only unlock this for systems you are authorized to test.
- **Evidence.** Each result stores the exact request, status, body excerpt and body SHA-256. The run directory is sealed with `manifest.sha256`.

## Limitations

- Denial is classified from the HTTP status (plus a JSON `"error"` body heuristic on 2xx). APIs that signal denial another way (for example an HTML login page with status 200) need a custom analyzer.
- AuthPath tests authorization, not authentication. Identity is assumed valid, and token forgery or session fixation are out of scope.
- Coverage is exactly the policy x subject x resource matrix you define. It does not discover endpoints on its own or invent attack payloads.
- Field-level checks use the sensitive and admin-only field lists you declare; it does not infer which fields are sensitive.
- Multi-step workflows, mass assignment, OAuth flows and ID enumeration are future work.
- `lab_api` is deliberately vulnerable and must stay on loopback.

## Layout

```
authpath/    the tool                 lab_api/   the vulnerable target
policies/    scenarios                reports/   generated evidence (per label)
tests/       144 pytest tests         docs/      notes
```
