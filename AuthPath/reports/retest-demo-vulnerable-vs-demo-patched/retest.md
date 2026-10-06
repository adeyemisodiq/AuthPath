# Retest: `demo-vulnerable` -> `demo-patched`

| Status | Cases |
|---|---|
| FIXED | 12 |
| STILL_FAILING | 0 |
| REGRESSION | 0 |
| PASS_UNCHANGED | 16 |
| NEEDS_REVIEW | 0 |
| NOT_COMPARABLE | 0 |

## Fixed

| Subject | Action | Resource | Before | After |
|---|---|---|---|---|
| admin_001 | update | account/account_001 | VIOLATION (HTTP 200) | PASS (HTTP 403) |
| admin_001 | update | account/account_002 | VIOLATION (HTTP 200) | PASS (HTTP 403) |
| user_001 | delete | account/account_001 | VIOLATION (HTTP 200) | PASS (HTTP 403) |
| user_001 | delete | account/account_002 | VIOLATION (HTTP 200) | PASS (HTTP 403) |
| user_001 | list_users | user_directory/all | VIOLATION (HTTP 200) | PASS (HTTP 403) |
| user_001 | read | account/account_002 | VIOLATION (HTTP 200) | PASS (HTTP 403) |
| user_001 | update | account/account_002 | VIOLATION (HTTP 200) | PASS (HTTP 403) |
| user_002 | delete | account/account_001 | VIOLATION (HTTP 200) | PASS (HTTP 403) |
| user_002 | delete | account/account_002 | VIOLATION (HTTP 200) | PASS (HTTP 403) |
| user_002 | list_users | user_directory/all | VIOLATION (HTTP 200) | PASS (HTTP 403) |
| user_002 | read | account/account_001 | VIOLATION (HTTP 200) | PASS (HTTP 403) |
| user_002 | update | account/account_001 | VIOLATION (HTTP 200) | PASS (HTTP 403) |
