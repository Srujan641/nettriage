# Security review

Checks run on 2026-11-11 before the first public push. Each one can be re-run with the command shown.

## Results

| Check | Tool | Result |
|---|---|---|
| Secrets in the files to be published | gitleaks 8.24.3 | **0 findings** (after the fix below) |
| Python code, static analysis | bandit | **0 high, 0 medium**, 4 low (explained below) |
| Python dependencies, known CVEs | pip-audit | **0 vulnerabilities** |
| JavaScript dependencies, known CVEs | npm audit | **0 vulnerabilities** |
| Personal data in published files | manual grep | none: no local paths, emails, keys, or home-network addresses |
| Addresses inside the packet captures | NetTriage's own pcap decoder | lab addresses only (10.77.0.0/24, 10.78.0.0/24) |
| Attacks against the running API | curl probes | all rejected (table below) |

## Issue found and fixed

**TLS session secrets were stored in reports.** After a successful TLS 1.2 handshake, `openssl s_client` prints the session's `Master-Key`, session ID and session ticket. NetTriage keeps each command's output as evidence, so those values were written to saved reports. Anyone holding a report and a recording of that session could decrypt it.

gitleaks caught this in a locally saved report, which was never committed. The TLS check now replaces those lines with `[redacted]` before storing or displaying anything (`redact_secrets` in `backend/nettriage/checks/tls.py`), and `test_session_secrets_are_redacted_from_evidence` keeps it fixed. The affected local reports were deleted.

## bandit's four low-severity notes

All four say the same thing: the code starts external programs (`subprocess`). Running `dig`, `ping`, `openssl` and the rest is the tool's job. They are run safely:

- always as an argument list, never through a shell, so `;`, `|` and `$( )` have no special meaning;
- only after the target has passed `parse_target`, which rejects anything that is not a plain hostname, IP address or http(s) URL, including values starting with `-` that a program could read as an option.

## API attack probes

Run against the API on `127.0.0.1:8000`:

| Attempt | Response |
|---|---|
| `target=example.com;id` (command injection) | 422 rejected |
| `target=$(id).example.com` (command substitution) | 422 rejected |
| `target=-oProxyCommand=id` (option injection) | 422 rejected |
| `resolver=1.1.1.1;id` | 422 rejected |
| `ports=80;id` | 422 rejected |
| `target=file:///etc/passwd` | 422 rejected |
| Report, scenario and capture names containing `../` | 404 |
| 27 MB capture upload (limit 25 MB) | 413 rejected |
| Request from a foreign website (CORS) | no `Access-Control-Allow-Origin` header returned |
| Listening address | `127.0.0.1` only |

The same cases are covered by automated tests in `backend/tests/test_api.py` and `backend/tests/test_util.py`.

## Kept out of the repository

`.gitignore` excludes:

- `backend/data/`: saved reports from your own diagnoses, which describe your network;
- `.coverage`: the coverage database, which records absolute local paths;
- `.venv/`, `node_modules/`, build output and editor files.

The lab's TLS certificates and private keys are generated when the lab starts and live only in a Docker volume. No key material is in the repository.

## Re-running the checks

```bash
docker run --rm -v "$PWD:/repo:ro" zricethezav/gitleaks:v8.24.3 dir /repo --redact
cd backend && ./.venv/bin/pip install bandit pip-audit
./.venv/bin/bandit -r nettriage
./.venv/bin/pip-audit --skip-editable
cd ../frontend && npm audit
```

Every push also runs gitleaks and the offline test suite in GitHub Actions (`.github/workflows/ci.yml`).
