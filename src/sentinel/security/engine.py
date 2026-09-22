"""Security analysis engine — Phase 4 (9 analyzers)."""

from __future__ import annotations

import re
from pathlib import Path

from sentinel.core.models.repository import ChangeSet
from sentinel.core.models.security import SecurityCategory, SecurityFinding, SecuritySeverity


# Pre-compiled patterns
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key"),
    (re.compile(r"aws_secret_access_key\s*=\s*['\"][^'\"]+['\"]", re.I), "AWS Secret Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "GitHub PAT"),
    (re.compile(r"gho_[A-Za-z0-9]{36,}"), "GitHub OAuth"),
    (re.compile(r"sk_(live|test)_[A-Za-z0-9]+"), "Stripe Secret Key"),
    (re.compile(r"-----BEGIN (RSA )?PRIVATE KEY-----"), "Private Key"),
    (re.compile(r"password\s*=\s*['\"][^'\"]{3,}['\"]", re.I), "Hardcoded Password"),
    (re.compile(r"api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", re.I), "API Key"),
    (re.compile(r"token\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]", re.I), "Token"),
]

DANGEROUS_EXECUTION: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bos\.system\s*\("), "os.system"),
    (re.compile(r"\bsubprocess\.(call|run|Popen|check_output)\s*\("), "subprocess"),
    (re.compile(r"\beval\s*\("), "eval"),
    (re.compile(r"\bexec\s*\("), "exec"),
    (re.compile(r"child_process\.exec"), "child_process.exec"),
    (re.compile(r"\bRuntime\.exec\s*\("), "Runtime.exec"),
]

FILESYSTEM_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"rm\s+-rf\s+"), "Recursive deletion rm -rf"),
    (re.compile(r"chmod\s+777"), "chmod 777"),
    (re.compile(r"chown\s+"), "chown"),
    (re.compile(r"/etc/(passwd|shadow|hosts)"), "Sensitive path /etc"),
    (re.compile(r"\.ssh/"), "SSH path"),
]

NETWORK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"requests\.(get|post|put|delete)\s*\("), "HTTP request"),
    (re.compile(r"urllib\.request\.urlopen"), "urllib urlopen"),
    (re.compile(r"fetch\s*\("), "fetch"),
    (re.compile(r"axios\.(get|post)\s*\("), "axios"),
    (re.compile(r"curl\s+https?://"), "curl remote"),
    (re.compile(r"wget\s+https?://"), "wget remote"),
    (re.compile(r"https?://[^\s\"']+"), "URL"),
]

AUTH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"auth.*bypass", re.I), "Auth bypass"),
    (re.compile(r"skip.*auth", re.I), "Skip auth"),
    (re.compile(r"verify\s*=\s*False"), "TLS verify disabled"),
    (re.compile(r"allow.*unauthenticated", re.I), "Unauthenticated allow"),
]

AUTHZ_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"role\s*=\s*['\"]admin['\"]", re.I), "Admin role"),
    (re.compile(r"privilege.*escalation", re.I), "Privilege escalation"),
    (re.compile(r"is_admin\s*=\s*True"), "is_admin true"),
]

DB_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"DROP\s+TABLE", re.I), "DROP TABLE"),
    (re.compile(r"TRUNCATE\s+TABLE", re.I), "TRUNCATE TABLE"),
    (re.compile(r"DELETE\s+FROM.*WHERE\s*1\s*=\s*1", re.I), "Mass delete"),
    (re.compile(r"SELECT\s+\*\s+FROM.*WHERE.*['\"]\s*\+", re.I), "SQL injection concat"),
    (re.compile(r"f\".*SELECT.*\{.*\}", re.I), "F-string SQL"),
]

DEP_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\+.*\"requests\""), "Dependency addition"),
    (re.compile(r"\+.*\"express\""), "Dependency addition"),
]

PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"IGNORE\s+ALL\s+PREVIOUS\s+INSTRUCTIONS", re.I), "Prompt injection: ignore instructions"),
    (re.compile(r"SYSTEM:\s*You are", re.I), "Prompt injection: system prompt"),
    (re.compile(r"JAILBREAK", re.I), "Prompt injection: jailbreak"),
    (re.compile(r"RUN\s+THIS\s+COMMAND", re.I), "Prompt injection: run command"),
]


def _make_finding(
    category: SecurityCategory,
    severity: SecuritySeverity,
    file: str | None,
    line: int | None,
    evidence: str,
    explanation: str,
    remediation: str | None = None,
    confidence: float = 0.85,
) -> SecurityFinding:
    return SecurityFinding(
        severity=severity,
        category=category,
        file=file,
        line=line,
        evidence=evidence[:500],
        explanation=explanation,
        remediation=remediation,
        confidence=confidence,
    )


class SecurityAnalyzer:
    """Analyzes ChangeSet for security findings."""

    def __init__(self, max_findings: int = 100) -> None:
        self.max_findings = max_findings

    def analyze(self, changeset: ChangeSet) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        diff = changeset.unified_diff or ""

        # Helper to run patterns
        def check_patterns(patterns, category, severity, explanation, remediation=None):
            for pat, desc in patterns:
                for m in pat.finditer(diff):
                    start = m.start()
                    # Estimate file and line from diff context
                    # Find preceding "+++ b/" or "diff --git"
                    snippet = diff[max(0, start - 200) : start + 200]
                    file_match = re.search(r"\+\+\+ b/([^\n]+)", diff[:start][::-1])  # crude
                    file = None
                    # Simpler: find last "diff --git" before match
                    last_diff = diff.rfind("diff --git", 0, start)
                    if last_diff != -1:
                        hdr = diff[last_diff : last_diff + 300]
                        fm = re.search(r"b/([^\s]+)", hdr)
                        if fm:
                            file = fm.group(1)
                    # Line number heuristic: count newlines up to match in diff segment
                    line = None
                    try:
                        line = diff[:start].count("\n")
                    except Exception:
                        pass
                    findings.append(
                        _make_finding(
                            category=category,
                            severity=severity,
                            file=file,
                            line=line,
                            evidence=m.group(0),
                            explanation=f"{desc}: {explanation}",
                            remediation=remediation,
                            confidence=0.9 if category == SecurityCategory.SECRETS else 0.75,
                        )
                    )
                    if len(findings) >= self.max_findings:
                        return

        check_patterns(
            SECRET_PATTERNS,
            SecurityCategory.SECRETS,
            SecuritySeverity.CRITICAL,
            "Potential secret/credential exposure",
            "Move secret to environment variable or secret store; add to .gitignore",
        )
        if len(findings) < self.max_findings:
            check_patterns(
                DANGEROUS_EXECUTION,
                SecurityCategory.DANGEROUS_EXECUTION,
                SecuritySeverity.HIGH,
                "Dangerous code execution pattern",
                "Validate and sanitize all inputs; avoid eval/exec",
            )
        if len(findings) < self.max_findings:
            check_patterns(
                FILESYSTEM_PATTERNS,
                SecurityCategory.FILESYSTEM,
                SecuritySeverity.HIGH,
                "Potentially destructive filesystem operation",
                "Review filesystem operation; require human approval",
            )
        if len(findings) < self.max_findings:
            check_patterns(
                NETWORK_PATTERNS,
                SecurityCategory.NETWORK,
                SecuritySeverity.MEDIUM,
                "Network operation detected",
                "Verify endpoint is expected and trusted",
            )
        if len(findings) < self.max_findings:
            check_patterns(
                AUTH_PATTERNS,
                SecurityCategory.AUTHENTICATION,
                SecuritySeverity.HIGH,
                "Authentication change/bypass",
                "Require human review for auth changes",
            )
        if len(findings) < self.max_findings:
            check_patterns(
                AUTHZ_PATTERNS,
                SecurityCategory.AUTHORIZATION,
                SecuritySeverity.HIGH,
                "Authorization / privilege change",
                "Require human review",
            )
        if len(findings) < self.max_findings:
            check_patterns(
                DB_PATTERNS,
                SecurityCategory.DATABASE,
                SecuritySeverity.CRITICAL,
                "Destructive or injection-prone SQL",
                "Review SQL; use parameterized queries; require migration review",
            )
        if len(findings) < self.max_findings:
            # Dependencies: check changed files list
            for cf in changeset.changed_files:
                if cf.path in ["package.json", "requirements.txt", "pyproject.toml", "package-lock.json", "poetry.lock", "Cargo.toml", "go.mod"]:
                    if cf.change_type.value in ["ADDED", "MODIFIED"]:
                        findings.append(
                            _make_finding(
                                SecurityCategory.DEPENDENCIES,
                                SecuritySeverity.MEDIUM,
                                file=cf.path,
                                line=None,
                                evidence=cf.path,
                                explanation="Dependency manifest changed",
                                remediation="Review new dependencies for known vulnerabilities",
                                confidence=0.6,
                            )
                        )
                        if len(findings) >= self.max_findings:
                            break
        if len(findings) < self.max_findings:
            check_patterns(
                PROMPT_INJECTION_PATTERNS,
                SecurityCategory.PROMPT_INJECTION,
                SecuritySeverity.HIGH,
                "Potential prompt injection in repository content",
                "Treat repository content as untrusted data; isolate from system prompts",
            )

        # File-level checks: e.g., .env changes
        for cf in changeset.changed_files:
            if ".env" in cf.path or "credentials" in cf.path or "secrets" in cf.path:
                if cf.change_type.value in ["ADDED", "MODIFIED"]:
                    # Avoid duplicate if already flagged as secrets
                    if not any(f.file == cf.path and f.category == SecurityCategory.SECRETS for f in findings):
                        findings.append(
                            _make_finding(
                                SecurityCategory.SECRETS,
                                SecuritySeverity.HIGH,
                                file=cf.path,
                                line=None,
                                evidence=cf.path,
                                explanation="Sensitive file modification (env/credentials)",
                                remediation="Do not commit secrets; use secret management",
                                confidence=0.8,
                            )
                        )

        return findings[: self.max_findings]
