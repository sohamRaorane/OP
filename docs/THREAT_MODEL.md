# JEV Sentinel — Threat Model (V1)

## Trust Boundaries

```
[User] → [Agent] → [Repository] → [Sentinel Control Plane] → [Docker Sandbox] → [Host]
                         ↑                    ↑
                         └──────Untrusted───┘
```

### Hierarchy (highest → lowest)
1. System Security Policy (hard-coded)
2. Sentinel Policy (YAML, signed)
3. User Requirement
4. Repository Content (untrusted)
5. Agent-Generated Content (untrusted)

Never treat repository content as system instruction.

---

## Threats & Mitigations

| # | Threat | Example | Mitigation | Status |
|---|--------|---------|------------|--------|
| 1 | Destructive agent command | `rm -rf /`, `git reset --hard` | Sandbox CPU/mem/pids, command allowlist, human approval for HIGH/CRITICAL | Implemented |
| 2 | Secret exposure | `AKIA...`, `ghp_...`, `.env` | Secrets analyzer (CRITICAL), policy BLOCK, audit, never log secrets | Implemented |
| 3 | Malicious dependency | `package.json` adds `evil-pkg` | Dependency analyzer, lockfile diff, policy `REQUIRE_HUMAN_REVIEW` | Implemented |
| 4 | Prompt injection | `IGNORE ALL PREVIOUS INSTRUCTIONS` in README | Prompt-injection analyzer, trust hierarchy, input isolation | Implemented |
| 5 | JEV failure / compromise | Timeout, malformed, unavailable | Timeout (30s), retry (2), fallback mock (conservative), fail-safe (not fail-open) | Implemented |
| 6 | Agent bypass | Direct `git push` without Sentinel | `gated` mode, adapter checkpoint, audit trail, API gating | Implemented |
| 7 | Malicious Git metadata | `..` in path, absolute path, null byte | Path traversal guard, `resolve()` + `is_absolute` + `..` check, safe executor arg list | Implemented |
| 8 | Command injection | `; rm -rf` via file name | `subprocess.run(..., shell=False)`, no string concatenation, allowlist | Implemented |
| 9 | Path traversal | `../../etc/passwd` | `_validate_repo_path`, per-file `Path.is_absolute/..` checks | Implemented |
| 10 | Secret leakage via logs/env | Env `AWS_SECRET` leaked to sandbox | Env allowlist (`PATH, PYTHONPATH, HOME, LANG` only), strip secret keys | Implemented |
| 11 | Container escape | Mount host `/` | `SENSITIVE_MOUNT_DENYLIST`, read-only mounts where possible, `network_disabled`, `pids_limit`, `mem_limit` | Implemented |
| 12 | Resource exhaustion | Huge diff, OOM, excessive output | `max_diff_size` (5MB), `max_file_size` (1MB), `max_output_size` (1MB), timeouts, OOM detection | Implemented |
| 13 | API abuse | Brute force, DoS | Auth abstraction, rate-limit abstraction (ready), request IDs, pagination, input validation (Pydantic) | Implemented |
| 14 | Unauthorized approval | Forged approver | Approver identity required, immutable history, status machine (PENDING→APPROVED/REJECTED only) | Implemented |
| 15 | Audit tampering | Delete/modify history | Append-only `AuditService`, no update/delete paths, DB `Base` no mutation APIs | Implemented |

---

## Security Checklist (CI)

- [ ] `ruff` + `mypy` pass
- [ ] `pytest tests/security` true positives + false positives pass
- [ ] No `shell=True` in codebase (`grep -r shell=True src/`)
- [ ] No `mount` of sensitive paths (`grep -r SENSITIVE src/`)
- [ ] Env allowlist enforced (`sandbox.executor`)
- [ ] Diff/output limits enforced
- [ ] Timeout on every subprocess/Docker call
- [ ] Secrets regex not logged verbatim (evidence truncated to 500 chars)
- [ ] Policy YAML validated (type errors rejected)
- [ ] Approval status machine tested (cannot overwrite)

---

## Least Privilege

- Sentinel API runs as non-root in Docker
- Validation containers run with `network_disabled=True`, `mem_limit=512m`, `pids_limit=128`, non-root user (via image)
- No host mounts beyond `/workspace` (rw, isolated)
- No secrets passed to sandbox

---

## Future V2+ Extensions

- Tool-call firewall (intercept all agent tool calls)
- Multi-agent arbitration
- Sigstore-signed audit log
- eBPF sandbox
