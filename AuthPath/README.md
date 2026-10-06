# AuthPath

**Automated API authorization testing.** You write down *who should be able to
do what* (a policy). AuthPath turns that into test cases, sends the real
requests, and reports every place the API's behaviour disagrees with the policy
- with reproducible evidence, a fix-and-retest workflow and regression
detection.

- **Problem:** APIs often authenticate correctly but authorize incorrectly
  (BOLA/IDOR, function-level access). Generic scanners cannot know the *intended*
  access rules, so they miss these.
- **Impact:** intended access rules become executable tests; unauthorized
  access is found before release, and a later change that silently reopens it
  is caught.
- **Proof:** `Attack -> Evidence -> Fix -> Retest -> Regression` against the
  bundled Lab API (see *Demo*). Every run writes hashed evidence any reviewer
  can re-verify.

## Architecture

```
policies/lab_scenario.json   (subjects, resources, policies, endpoint bindings)
            |
  authpath/config.py         load + validate
            |
  engine/generator.py        policy set  ->  expected allow/deny per case
            |                (engine/policy_evaluator.py, engine/condition.py)
  runner.py  ---- api/executor.py ----> target API   (scope-guarded)
            |         |
            |   api/response_analyzer.py   HTTP response -> allow/deny/unknown
            |
  engine/evaluator.py        expected vs observed -> PASS / VIOLATION /
            |                OVER_RESTRICTION / INCONCLUSIVE (+ OWASP category)
  evidence/recorder.py       results.json, results.csv, report.md, manifest.sha256
  reporting/report.py        findings with curl reproduction
  reporting/retest.py        FIXED / STILL_FAILING / REGRESSION comparison
```

## Quick start (Windows PowerShell, Python 3.10+)

```powershell
pip install -r requirements.txt        # only needed for the tests
python -m pytest -q --junitxml=test-results.xml
```

### Demo: attack -> fix -> retest -> regression

Terminal 1 (server), Terminal 2 (AuthPath):

```powershell
# 1. Vulnerable release
python -m lab_api.main --mode vulnerable          # terminal 1
python -m authpath run --scenario policies\lab_scenario.json --label vulnerable
#   -> 28 cases, 16 pass, 12 VIOLATION

# 2. Patched release   (Ctrl+C terminal 1, then)
python -m lab_api.main --mode patched
python -m authpath run --scenario policies\lab_scenario.json --label patched
python -m authpath compare --before reports\vulnerable\results.json --after reports\patched\results.json
#   -> FIXED: 12, PASS_UNCHANGED: 16

# 3. A later release that reopens a hole
python -m lab_api.main --mode regressed
python -m authpath run --scenario policies\lab_scenario.json --label regressed
python -m authpath compare --before reports\patched\results.json --after reports\regressed\results.json
#   -> REGRESSION: 4

# Evidence integrity
python -m authpath verify reports\vulnerable
```

Add `--strict` to `run` / `compare` to get exit code 1 on findings or
regressions (for CI).

## Verdicts

| Expected | Observed | Verdict | Meaning |
|---|---|---|---|
| deny | allow | **VIOLATION** | security failure (BOLA API1:2023 for object-level, BFLA API5:2023 for function-level bindings) |
| allow | deny | **OVER_RESTRICTION** | functional failure - legitimate access broken |
| same | same | PASS | |
| any | unknown | **INCONCLUSIVE** | never a silent pass |

## Policy model

- A policy applies when subject *type*, action and resource type match and its
  optional condition is true. Otherwise it is `not_applicable` (silent).
- Policy sets use **deny-overrides** and **default-deny**.
- Condition operators: `equals`, `not_equals`, `in`, `not_in`, `contains`,
  `exists`, `all`, `any`. Operands starting with `subject.` / `resource.` are
  paths; anything else is a literal.

## Design decisions (for the defense)

- **Separation of duties.** Executor = *what happened*; analyzer = *what
  authorization behaviour that indicates*; evaluator = *does it match policy*.
  Each is unit-tested alone.
- **Default-deny + deny-overrides** is the standard fail-safe combination.
- **404 = deny.** Every tested resource is known to exist in the scenario, so
  a 404 means the API hides it from that subject.
- **State reset before every case.** Destructive tests (DELETE) cannot corrupt
  later results. Deterministic: two runs produce identical statuses and body
  hashes.
- **Scope guard.** Loopback-only unless a scenario explicitly opts out;
  checked before any network call. Redirects are not followed; system proxies
  are ignored.
- **Evidence.** Each result stores the exact request, status, body excerpt and
  body SHA-256; the run directory is sealed with `manifest.sha256`.

## Limitations (say these before the judges do)

- Classification uses HTTP status (plus a JSON `"error"` body heuristic on
  2xx). APIs that signal denial another way (e.g. HTML login page with 200,
  custom envelopes) need a custom analyzer.
- Tests authorization only. The Lab API trusts `X-User-ID`; identity is
  assumed valid. Token forgery, session fixation etc. are out of scope.
- Coverage is exactly the policy x subject x resource matrix you define; it
  does not discover endpoints or invent attack payloads.
- Read-style and simple JSON mutations only; multi-step workflows, mass
  assignment and field-level authorization are future work.
- Lab-only: `lab_api` is deliberately vulnerable and must stay on loopback.

## Layout

```
authpath/        the tool          lab_api/   the vulnerable target
policies/        scenarios         reports/   generated evidence (per label)
tests/           94 pytest tests   docs/      notes
```

## Getting started faster (no hand-written JSON required)

Three ways to build a scenario without typing everything from scratch:

**1. Import endpoints from an OpenAPI/Swagger spec** (if your target has one,
often at `/docs`, `/swagger`, or `/openapi.json` - export/save it as JSON):

```powershell
python -m authpath import-openapi --spec my_api_openapi.json --out policies\draft_bindings.json
```

This guesses each endpoint's action, resource type and authorization level
from the URL shape and prints them for review - it can only draft *what
exists*, never *who should be allowed to use it*. Paste the bindings you
want into your scenario's `"bindings"` list.

**2. The guided wizard** - answers plain questions and writes the scenario
file for you (it can call the OpenAPI importer partway through):

```powershell
python -m authpath init --out policies\my_scenario.json
```

**3. Owner-based defaults** - instead of writing "user may read own account"
and "user may update own account" by hand, add to the scenario:

```json
"policy_defaults": [
  { "resource": "account", "actions": ["read", "update"], "admin_roles": ["admin"] }
]
```

This expands into real policies at load time. A hand-written policy with
`"decision": "deny"` still overrides a default `"allow"` (deny-overrides),
so defaults give you a sane starting point - you only write the exceptions.

## Severity, data exposure, and the HTML report

Three additions beyond the core allow/deny engine:

**Severity.** Every finding gets a label:
- **High** — destructive/admin actions allowed, a function-level bypass on a
  sensitive resource, or any exposed sensitive field.
- **Medium** — an object-level violation (e.g. reading someone else's
  record) that is a plain read.
- **Low** — an OVER_RESTRICTION (a functional bug, not a security one).

**Excessive data exposure (OWASP API3:2023 - Broken Object Property Level
Authorization).** BOLA/BFLA testing only asks "should this subject be let
through the door at all?" It can completely pass while the response body
still hands back a field only a more privileged role should see - ownership
does not automatically mean entitlement to *every* field on a resource.
Declare this in the scenario:

```json
"admin_roles": ["admin"],
"sensitive_fields":   { "account": ["balance"] },
"admin_only_fields":  { "account": ["internal_risk_score"] }
```

- `sensitive_fields` - visible to the resource's owner OR an admin role;
  hidden from everyone else.
- `admin_only_fields` - visible to an admin role ONLY, even the resource's
  own owner should not see it.

The bundled Lab API demonstrates this deliberately: in **patched** mode,
object-level authorization is fully correct (28/28 PASS) - but every owner
who reads or updates their own account still receives `internal_risk_score`,
an admin-only field. AuthPath flags this as a **High-severity, PASS-verdict**
finding, which is exactly the point: a clean allow/deny scorecard is not the
same as "nothing is wrong."

**HTML report.** Every `authpath run` now writes `report.html` next to
`report.md` in the evidence folder - same findings, styled with
severity/verdict badges, meant for screen-recording or sharing rather than
reading as plain text. It's a single self-contained file (no external
assets), so it opens correctly offline.

## Remediation

Every finding — a VIOLATION, an OVER_RESTRICTION, or a data-exposure result
— now carries one or more short, specific **"how to fix this"** notes in
both `report.md` and `report.html`:

- **BOLA (API1)** → add a server-side ownership/relationship check, not
  just an authentication check.
- **BFLA (API5)** → add a role/permission check on the endpoint itself.
- **OVER_RESTRICTION** → the policy or endpoint logic is likely too strict
  for a legitimate case.
- **Data exposure (API3)** → strip the named field for subjects who are
  not entitled to it; build responses per-role rather than returning the
  full stored record.

A finding can need **two** fixes at once — e.g. a BOLA violation whose
response also happens to leak an admin-only field needs both the ownership
check *and* the field strip; fixing only one would leave the other bug in
place. AuthPath lists both in that case.
