"""ValidationRunner — Phase 2 & 12."""

from __future__ import annotations

from pathlib import Path

from sentinel.config.settings import Settings, get_settings
from sentinel.core.models.validation import ValidationResult
from sentinel.validation.validators import AVAILABLE_VALIDATORS, FUTURE_VALIDATORS, CommandValidator, Validator


# Allowlist — never execute arbitrary repo commands without policy
DEFAULT_ALLOWLIST: set[str] = {
    "pytest",
    "ruff",
    "mypy",
    "python -m pytest",
    "python -m ruff",
    "python -m mypy",
    "npm",
    "npx tsc",
    "gradle",
    "mvn",
    "cargo",
    "go",
}


def _is_command_allowed(cmd: list[str], allowlist: set[str]) -> bool:
    joined = " ".join(cmd)
    for allowed in allowlist:
        if joined.startswith(allowed):
            return True
    # Also check first token
    if cmd and cmd[0] in allowlist:
        return True
    return False


class ValidationRunner:
    """Discovers and runs validators."""

    def __init__(self, settings: Settings | None = None, allowlist: set[str] | None = None) -> None:
        self.settings = settings or get_settings()
        self.allowlist = allowlist or DEFAULT_ALLOWLIST

    def discover(self, repo_path: Path) -> list[Validator]:
        validators: list[Validator] = []
        for name, cls in AVAILABLE_VALIDATORS.items():
            v = cls()
            if v.is_applicable(repo_path):
                validators.append(v)
        # Future validators if config enables them
        for name, (cmd, marker) in FUTURE_VALIDATORS.items():
            cv = CommandValidator(name, cmd, marker)
            if cv.is_applicable(repo_path):
                validators.append(cv)
        return validators

    def detect_project_type(self, repo_path: Path) -> str:
        if (repo_path / "pyproject.toml").exists() or (repo_path / "requirements.txt").exists():
            return "python"
        if (repo_path / "package.json").exists():
            return "node"
        if (repo_path / "pom.xml").exists():
            return "maven"
        if (repo_path / "build.gradle").exists():
            return "gradle"
        if (repo_path / "Cargo.toml").exists():
            return "rust"
        if (repo_path / "go.mod").exists():
            return "go"
        return "unknown"

    def run(
        self,
        repo_path: Path,
        validators: list[Validator] | None = None,
        timeout: int | None = None,
        use_sandbox: bool = False,
        sandbox_executor=None,
    ) -> list[ValidationResult]:
        timeout = timeout or self.settings.validation_timeout
        validators = validators or self.discover(repo_path)
        results: list[ValidationResult] = []
        for v in validators:
            cmd = v.get_command(repo_path)
            if not _is_command_allowed(cmd, self.allowlist):
                # Skip disallowed commands
                from sentinel.core.models.validation import ValidationStatus

                results.append(
                    ValidationResult(
                        validator_name=v.name,
                        command=cmd,
                        status=ValidationStatus.SKIPPED,
                        stdout="",
                        stderr=f"Command not in allowlist: {' '.join(cmd)}",
                        timeout_seconds=timeout,
                    )
                )
                continue
            if use_sandbox and sandbox_executor:
                # Defer to sandbox
                result = sandbox_executor.execute(cmd, workdir=repo_path, timeout=timeout)
                # Convert sandbox result to ValidationResult
                from sentinel.core.models.validation import ValidationStatus

                status = ValidationStatus.PASS if result.exit_code == 0 else ValidationStatus.FAIL
                if result.timed_out:
                    status = ValidationStatus.TIMEOUT
                if result.oom_killed:
                    status = ValidationStatus.ERROR
                results.append(
                    ValidationResult(
                        validator_name=v.name,
                        command=cmd,
                        started_at=result.started_at,
                        finished_at=result.finished_at,
                        duration_ms=result.duration_ms,
                        exit_code=result.exit_code,
                        stdout=result.stdout,
                        stderr=result.stderr,
                        timeout_seconds=timeout,
                        status=status,
                        failures=v.parse_failures(result.stdout, result.stderr, result.exit_code or 0) if status == ValidationStatus.FAIL else [],
                    )
                )
            else:
                res = v.validate(repo_path, timeout=timeout, max_output=self.settings.max_output_size)
                results.append(res)
        return results
