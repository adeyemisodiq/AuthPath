# AuthPath report: `demo-patched`

- Scenario: AuthPath Lab API - banking scenario
- Target: http://127.0.0.1:8002
- Started: 2026-10-06T16:23:52+00:00  |  Finished: 2026-10-06T16:23:52+00:00
- Tool: AuthPath 0.1.0

## Summary

| Total | Pass | Violation | Over-restriction | Inconclusive | Data exposure |
|---|---|---|---|---|---|
| 28 | 28 | 0 | 0 | 0 | 4 |

- **VIOLATION**: policy says deny, API allowed it (security failure).
- **OVER_RESTRICTION**: policy says allow, API denied it (functional failure).
- **INCONCLUSIVE**: response could not be classified; review manually.
- **Data exposure**: the response body contained a field this subject should not see, independent of the allow/deny decision.

## Excessive data exposure (OWASP API3)

A correct allow/deny decision is not enough if the response body still hands back a field this subject should not see.

### TC-001: user_001 read account/account_001  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: PASS
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X GET -H 'X-User-ID: user_001' 'http://127.0.0.1:8002/api/accounts/account_001'
```

### TC-004: user_002 read account/account_002  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: PASS
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X GET -H 'X-User-ID: user_002' 'http://127.0.0.1:8002/api/accounts/account_002'
```

### TC-009: user_001 update account/account_001  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: PASS
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X PUT -H 'X-User-ID: user_001' -H 'Content-Type: application/json' -d '{"nickname": "authpath-probe"}' 'http://127.0.0.1:8002/api/accounts/account_001'
```

### TC-012: user_002 update account/account_002  — **High severity**

- Exposed fields: internal_risk_score
- Main verdict for this request: PASS
- **Remediation:** Strip `internal_risk_score` from the response for subjects who are not entitled to it - build the response per-role/per-relationship (an explicit allow-list of fields, or a serializer per role) rather than returning the full stored record as-is.

Reproduce:

```
curl -i -X PUT -H 'X-User-ID: user_002' -H 'Content-Type: application/json' -d '{"nickname": "authpath-probe"}' 'http://127.0.0.1:8002/api/accounts/account_002'
```


## All results

| Case | Subject | Action | Resource | Expected | Observed | HTTP | Verdict | Severity | Exposed fields |
|---|---|---|---|---|---|---|---|---|---|
| TC-001 | user_001 | read | account/account_001 | allow | allow | 200 | PASS | High | internal_risk_score |
| TC-002 | user_001 | read | account/account_002 | deny | deny | 403 | PASS |  |  |
| TC-003 | user_002 | read | account/account_001 | deny | deny | 403 | PASS |  |  |
| TC-004 | user_002 | read | account/account_002 | allow | allow | 200 | PASS | High | internal_risk_score |
| TC-005 | admin_001 | read | account/account_001 | allow | allow | 200 | PASS |  |  |
| TC-006 | admin_001 | read | account/account_002 | allow | allow | 200 | PASS |  |  |
| TC-007 | anonymous | read | account/account_001 | deny | deny | 401 | PASS |  |  |
| TC-008 | anonymous | read | account/account_002 | deny | deny | 401 | PASS |  |  |
| TC-009 | user_001 | update | account/account_001 | allow | allow | 200 | PASS | High | internal_risk_score |
| TC-010 | user_001 | update | account/account_002 | deny | deny | 403 | PASS |  |  |
| TC-011 | user_002 | update | account/account_001 | deny | deny | 403 | PASS |  |  |
| TC-012 | user_002 | update | account/account_002 | allow | allow | 200 | PASS | High | internal_risk_score |
| TC-013 | admin_001 | update | account/account_001 | deny | deny | 403 | PASS |  |  |
| TC-014 | admin_001 | update | account/account_002 | deny | deny | 403 | PASS |  |  |
| TC-015 | anonymous | update | account/account_001 | deny | deny | 401 | PASS |  |  |
| TC-016 | anonymous | update | account/account_002 | deny | deny | 401 | PASS |  |  |
| TC-017 | user_001 | delete | account/account_001 | deny | deny | 403 | PASS |  |  |
| TC-018 | user_001 | delete | account/account_002 | deny | deny | 403 | PASS |  |  |
| TC-019 | user_002 | delete | account/account_001 | deny | deny | 403 | PASS |  |  |
| TC-020 | user_002 | delete | account/account_002 | deny | deny | 403 | PASS |  |  |
| TC-021 | admin_001 | delete | account/account_001 | allow | allow | 200 | PASS |  |  |
| TC-022 | admin_001 | delete | account/account_002 | allow | allow | 200 | PASS |  |  |
| TC-023 | anonymous | delete | account/account_001 | deny | deny | 401 | PASS |  |  |
| TC-024 | anonymous | delete | account/account_002 | deny | deny | 401 | PASS |  |  |
| TC-025 | user_001 | list_users | user_directory/all | deny | deny | 403 | PASS |  |  |
| TC-026 | user_002 | list_users | user_directory/all | deny | deny | 403 | PASS |  |  |
| TC-027 | admin_001 | list_users | user_directory/all | allow | allow | 200 | PASS |  |  |
| TC-028 | anonymous | list_users | user_directory/all | deny | deny | 401 | PASS |  |  |
