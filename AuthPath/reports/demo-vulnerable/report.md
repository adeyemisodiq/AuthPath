# AuthPath report: `demo-vulnerable`

- Scenario: AuthPath Lab API - banking scenario
- Target: http://127.0.0.1:8001
- Started: 2026-10-06T16:22:37+00:00  |  Finished: 2026-10-06T16:22:37+00:00
- Tool: AuthPath 0.1.0

## Summary

| Total | Pass | Violation | Over-restriction | Inconclusive | Data exposure |
|---|---|---|---|---|---|
| 28 | 16 | 12 | 0 | 0 | 8 |

- **VIOLATION**: policy says deny, API allowed it (security failure).
- **OVER_RESTRICTION**: policy says allow, API denied it (functional failure).
- **INCONCLUSIVE**: response could not be classified; review manually.
- **Data exposure**: the response body contained a field this subject should not see, independent of the allow/deny decision.

## Violations

### TC-002: user_001 read account/account_002  — **High severity**

- Category: API1:2023 Broken Object Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Exposed fields: internal_risk_score
- Response body SHA-256: `46974b1f55ae8218f01e0b4938a2512518c1bbb05b57ea032ba57a4feb479d22`
- **Remediation:** Add an ownership (or relationship) check before returning this resource - verify the resource belongs to the authenticated subject (or that they otherwise have a legitimate relationship to it), not just that they are logged in. Enforce this server-side, on every request - never trust an ID supplied by the client alone.
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X GET -H 'X-User-ID: user_001' 'http://127.0.0.1:8001/api/accounts/account_002'
```

### TC-003: user_002 read account/account_001  — **High severity**

- Category: API1:2023 Broken Object Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Exposed fields: internal_risk_score
- Response body SHA-256: `8ebdf2866fcd9bc1ea1abe8e56a2d9a5110a9b984a32c0c1e491737c1ec924bc`
- **Remediation:** Add an ownership (or relationship) check before returning this resource - verify the resource belongs to the authenticated subject (or that they otherwise have a legitimate relationship to it), not just that they are logged in. Enforce this server-side, on every request - never trust an ID supplied by the client alone.
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X GET -H 'X-User-ID: user_002' 'http://127.0.0.1:8001/api/accounts/account_001'
```

### TC-010: user_001 update account/account_002  — **High severity**

- Category: API1:2023 Broken Object Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Exposed fields: internal_risk_score
- Response body SHA-256: `5ca160913628733a377db757ba6629a41217bfb56d5ed2a34c216f4ce1e31d59`
- **Remediation:** Add an ownership (or relationship) check before returning this resource - verify the resource belongs to the authenticated subject (or that they otherwise have a legitimate relationship to it), not just that they are logged in. Enforce this server-side, on every request - never trust an ID supplied by the client alone.
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X PUT -H 'X-User-ID: user_001' -H 'Content-Type: application/json' -d '{"nickname": "authpath-probe"}' 'http://127.0.0.1:8001/api/accounts/account_002'
```

### TC-011: user_002 update account/account_001  — **High severity**

- Category: API1:2023 Broken Object Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Exposed fields: internal_risk_score
- Response body SHA-256: `584a9c73c9d8f06640c596de376af5d1377ce71f866d3ca661da783373dd5b5b`
- **Remediation:** Add an ownership (or relationship) check before returning this resource - verify the resource belongs to the authenticated subject (or that they otherwise have a legitimate relationship to it), not just that they are logged in. Enforce this server-side, on every request - never trust an ID supplied by the client alone.
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X PUT -H 'X-User-ID: user_002' -H 'Content-Type: application/json' -d '{"nickname": "authpath-probe"}' 'http://127.0.0.1:8001/api/accounts/account_001'
```

### TC-013: admin_001 update account/account_001  — **High severity**

- Category: API1:2023 Broken Object Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Response body SHA-256: `584a9c73c9d8f06640c596de376af5d1377ce71f866d3ca661da783373dd5b5b`
- **Remediation:** Add an ownership (or relationship) check before returning this resource - verify the resource belongs to the authenticated subject (or that they otherwise have a legitimate relationship to it), not just that they are logged in. Enforce this server-side, on every request - never trust an ID supplied by the client alone.

Reproduce:

```
curl -i -X PUT -H 'X-User-ID: admin_001' -H 'Content-Type: application/json' -d '{"nickname": "authpath-probe"}' 'http://127.0.0.1:8001/api/accounts/account_001'
```

### TC-014: admin_001 update account/account_002  — **High severity**

- Category: API1:2023 Broken Object Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Response body SHA-256: `5ca160913628733a377db757ba6629a41217bfb56d5ed2a34c216f4ce1e31d59`
- **Remediation:** Add an ownership (or relationship) check before returning this resource - verify the resource belongs to the authenticated subject (or that they otherwise have a legitimate relationship to it), not just that they are logged in. Enforce this server-side, on every request - never trust an ID supplied by the client alone.

Reproduce:

```
curl -i -X PUT -H 'X-User-ID: admin_001' -H 'Content-Type: application/json' -d '{"nickname": "authpath-probe"}' 'http://127.0.0.1:8001/api/accounts/account_002'
```

### TC-017: user_001 delete account/account_001  — **High severity**

- Category: API5:2023 Broken Function Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Response body SHA-256: `422dadd428342afacf6b8f5bead08af3d37d8db5fa420f5407d99d8a6a35ab87`
- **Remediation:** Add a role/permission check on this endpoint - verify the subject holds the required role or permission before performing the action, not just that they are authenticated. Apply the check at the start of the handler (or via middleware/decorator), before any work is done.

Reproduce:

```
curl -i -X DELETE -H 'X-User-ID: user_001' 'http://127.0.0.1:8001/api/accounts/account_001'
```

### TC-018: user_001 delete account/account_002  — **High severity**

- Category: API5:2023 Broken Function Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Response body SHA-256: `aa14dd42e8e187c5594034c9a1dfe7fddde04e59340d068bc9675bfa27143087`
- **Remediation:** Add a role/permission check on this endpoint - verify the subject holds the required role or permission before performing the action, not just that they are authenticated. Apply the check at the start of the handler (or via middleware/decorator), before any work is done.

Reproduce:

```
curl -i -X DELETE -H 'X-User-ID: user_001' 'http://127.0.0.1:8001/api/accounts/account_002'
```

### TC-019: user_002 delete account/account_001  — **High severity**

- Category: API5:2023 Broken Function Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Response body SHA-256: `422dadd428342afacf6b8f5bead08af3d37d8db5fa420f5407d99d8a6a35ab87`
- **Remediation:** Add a role/permission check on this endpoint - verify the subject holds the required role or permission before performing the action, not just that they are authenticated. Apply the check at the start of the handler (or via middleware/decorator), before any work is done.

Reproduce:

```
curl -i -X DELETE -H 'X-User-ID: user_002' 'http://127.0.0.1:8001/api/accounts/account_001'
```

### TC-020: user_002 delete account/account_002  — **High severity**

- Category: API5:2023 Broken Function Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Response body SHA-256: `aa14dd42e8e187c5594034c9a1dfe7fddde04e59340d068bc9675bfa27143087`
- **Remediation:** Add a role/permission check on this endpoint - verify the subject holds the required role or permission before performing the action, not just that they are authenticated. Apply the check at the start of the handler (or via middleware/decorator), before any work is done.

Reproduce:

```
curl -i -X DELETE -H 'X-User-ID: user_002' 'http://127.0.0.1:8001/api/accounts/account_002'
```

### TC-025: user_001 list_users user_directory/all  — **High severity**

- Category: API5:2023 Broken Function Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Response body SHA-256: `5822ad0c9ba03a8caf4435eae81dd1324a8a641522e30973aebdf3c34c97dc40`
- **Remediation:** Add a role/permission check on this endpoint - verify the subject holds the required role or permission before performing the action, not just that they are authenticated. Apply the check at the start of the handler (or via middleware/decorator), before any work is done.

Reproduce:

```
curl -i -X GET -H 'X-User-ID: user_001' 'http://127.0.0.1:8001/api/admin/users'
```

### TC-026: user_002 list_users user_directory/all  — **High severity**

- Category: API5:2023 Broken Function Level Authorization
- Expected: **deny** (No policy grants this access (default deny).)
- Observed: **allow** (HTTP 200: request succeeded.)
- HTTP status: 200
- Response body SHA-256: `5822ad0c9ba03a8caf4435eae81dd1324a8a641522e30973aebdf3c34c97dc40`
- **Remediation:** Add a role/permission check on this endpoint - verify the subject holds the required role or permission before performing the action, not just that they are authenticated. Apply the check at the start of the handler (or via middleware/decorator), before any work is done.

Reproduce:

```
curl -i -X GET -H 'X-User-ID: user_002' 'http://127.0.0.1:8001/api/admin/users'
```


## Excessive data exposure (OWASP API3)

A correct allow/deny decision is not enough if the response body still hands back a field this subject should not see.

### TC-001: user_001 read account/account_001  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: PASS
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X GET -H 'X-User-ID: user_001' 'http://127.0.0.1:8001/api/accounts/account_001'
```

### TC-002: user_001 read account/account_002  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: VIOLATION
- **Remediation:** Add an ownership (or relationship) check before returning this resource - verify the resource belongs to the authenticated subject (or that they otherwise have a legitimate relationship to it), not just that they are logged in. Enforce this server-side, on every request - never trust an ID supplied by the client alone.
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X GET -H 'X-User-ID: user_001' 'http://127.0.0.1:8001/api/accounts/account_002'
```

### TC-003: user_002 read account/account_001  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: VIOLATION
- **Remediation:** Add an ownership (or relationship) check before returning this resource - verify the resource belongs to the authenticated subject (or that they otherwise have a legitimate relationship to it), not just that they are logged in. Enforce this server-side, on every request - never trust an ID supplied by the client alone.
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X GET -H 'X-User-ID: user_002' 'http://127.0.0.1:8001/api/accounts/account_001'
```

### TC-004: user_002 read account/account_002  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: PASS
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X GET -H 'X-User-ID: user_002' 'http://127.0.0.1:8001/api/accounts/account_002'
```

### TC-009: user_001 update account/account_001  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: PASS
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X PUT -H 'X-User-ID: user_001' -H 'Content-Type: application/json' -d '{"nickname": "authpath-probe"}' 'http://127.0.0.1:8001/api/accounts/account_001'
```

### TC-010: user_001 update account/account_002  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: VIOLATION
- **Remediation:** Add an ownership (or relationship) check before returning this resource - verify the resource belongs to the authenticated subject (or that they otherwise have a legitimate relationship to it), not just that they are logged in. Enforce this server-side, on every request - never trust an ID supplied by the client alone.
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X PUT -H 'X-User-ID: user_001' -H 'Content-Type: application/json' -d '{"nickname": "authpath-probe"}' 'http://127.0.0.1:8001/api/accounts/account_002'
```

### TC-011: user_002 update account/account_001  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: VIOLATION
- **Remediation:** Add an ownership (or relationship) check before returning this resource - verify the resource belongs to the authenticated subject (or that they otherwise have a legitimate relationship to it), not just that they are logged in. Enforce this server-side, on every request - never trust an ID supplied by the client alone.
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X PUT -H 'X-User-ID: user_002' -H 'Content-Type: application/json' -d '{"nickname": "authpath-probe"}' 'http://127.0.0.1:8001/api/accounts/account_001'
```

### TC-012: user_002 update account/account_002  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: PASS
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X PUT -H 'X-User-ID: user_002' -H 'Content-Type: application/json' -d '{"nickname": "authpath-probe"}' 'http://127.0.0.1:8001/api/accounts/account_002'
```


## All results

| Case | Subject | Action | Resource | Expected | Observed | HTTP | Verdict | Severity | Exposed fields |
|---|---|---|---|---|---|---|---|---|---|
| TC-001 | user_001 | read | account/account_001 | allow | allow | 200 | PASS | High | internal_risk_score |
| TC-002 | user_001 | read | account/account_002 | deny | allow | 200 | VIOLATION | High | internal_risk_score |
| TC-003 | user_002 | read | account/account_001 | deny | allow | 200 | VIOLATION | High | internal_risk_score |
| TC-004 | user_002 | read | account/account_002 | allow | allow | 200 | PASS | High | internal_risk_score |
| TC-005 | admin_001 | read | account/account_001 | allow | allow | 200 | PASS |  |  |
| TC-006 | admin_001 | read | account/account_002 | allow | allow | 200 | PASS |  |  |
| TC-007 | anonymous | read | account/account_001 | deny | deny | 401 | PASS |  |  |
| TC-008 | anonymous | read | account/account_002 | deny | deny | 401 | PASS |  |  |
| TC-009 | user_001 | update | account/account_001 | allow | allow | 200 | PASS | High | internal_risk_score |
| TC-010 | user_001 | update | account/account_002 | deny | allow | 200 | VIOLATION | High | internal_risk_score |
| TC-011 | user_002 | update | account/account_001 | deny | allow | 200 | VIOLATION | High | internal_risk_score |
| TC-012 | user_002 | update | account/account_002 | allow | allow | 200 | PASS | High | internal_risk_score |
| TC-013 | admin_001 | update | account/account_001 | deny | allow | 200 | VIOLATION | High |  |
| TC-014 | admin_001 | update | account/account_002 | deny | allow | 200 | VIOLATION | High |  |
| TC-015 | anonymous | update | account/account_001 | deny | deny | 401 | PASS |  |  |
| TC-016 | anonymous | update | account/account_002 | deny | deny | 401 | PASS |  |  |
| TC-017 | user_001 | delete | account/account_001 | deny | allow | 200 | VIOLATION | High |  |
| TC-018 | user_001 | delete | account/account_002 | deny | allow | 200 | VIOLATION | High |  |
| TC-019 | user_002 | delete | account/account_001 | deny | allow | 200 | VIOLATION | High |  |
| TC-020 | user_002 | delete | account/account_002 | deny | allow | 200 | VIOLATION | High |  |
| TC-021 | admin_001 | delete | account/account_001 | allow | allow | 200 | PASS |  |  |
| TC-022 | admin_001 | delete | account/account_002 | allow | allow | 200 | PASS |  |  |
| TC-023 | anonymous | delete | account/account_001 | deny | deny | 401 | PASS |  |  |
| TC-024 | anonymous | delete | account/account_002 | deny | deny | 401 | PASS |  |  |
| TC-025 | user_001 | list_users | user_directory/all | deny | allow | 200 | VIOLATION | High |  |
| TC-026 | user_002 | list_users | user_directory/all | deny | allow | 200 | VIOLATION | High |  |
| TC-027 | admin_001 | list_users | user_directory/all | allow | allow | 200 | PASS |  |  |
| TC-028 | anonymous | list_users | user_directory/all | deny | deny | 401 | PASS |  |  |
