"""Validator interface and built-in validators — Phase 2."""

from __future__ import annotations

import subprocess
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path

from sentinel.core.models.validation import ValidationResult, ValidationStatus


class Validator(ABC):
    """Abstract validator."""

    name: str = "base"

    @abstractmethod
    def is_applicable(self, repo_path: Path) -> bool:
        """Whether validator applies to repo."""

    @abstractmethod
    def get_command(self, repo_path: Path) -> list[str]:
        """Return command as arg list (never shell string)."""

    def parse_failures(self, stdout: str, stderr: str, exit_code: int) -> list[str]:
        return []

    def validate(self, repo_path: Path, timeout: int = 120, max_output: int = 1_048_576) -> ValidationResult:
        cmd = self.get_command(repo_path)
        start = datetime.now(UTC)
        start_monotonic = time.monotonic()
        try:
            result = subprocess.run(
                cmd,
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
            )
            finished = datetime.now(UTC)
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            truncated_out = False
            truncated_err = False
            if len(stdout.encode("utf-8")) > max_output:
                stdout = stdout[:max_output]
                truncated_out = True
            if len(stderr.encode("utf-8")) > max_output:
                stderr = stderr[:max_output]
                truncated_err = True
            # Parse status — never assume zero means pass without checking output
            status = self._determine_status(result.returncode, stdout, stderr)
            failures = self.parse_failures(stdout, stderr, result.returncode) if status == ValidationStatus.FAIL else []
            duration = int((time.monotonic() - start_monotonic) * 1000)
            return ValidationResult(
                validator_name=self.name,
                command=cmd,
                started_at=start,
                finished_at=finished,
                duration_ms=duration,
                exit_code=result.returncode,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=truncated_out,
                stderr_truncated=truncated_err,
                timeout_seconds=timeout,
                status=status,
                failures=failures,
            )
        except subprocess.TimeoutExpired as e:
            finished = datetime.now(UTC)
            stdout = (e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout or ""))[:max_output]
            stderr = (e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr or ""))[:max_output]
            duration = int((time.monotonic() - start_monotonic) * 1000)
            return ValidationResult(
                validator_name=self.name,
                command=cmd,
                started_at=start,
                finished_at=finished,
                duration_ms=duration,
                exit_code=None,
                stdout=stdout,
                stderr=stderr,
                timeout_seconds=timeout,
                status=ValidationStatus.TIMEOUT,
                failures=[f"Timeout after {timeout}s"],
            )
        except FileNotFoundError:
            finished = datetime.now(UTC)
            return ValidationResult(
                validator_name=self.name,
                command=cmd,
                started_at=start,
                finished_at=finished,
                duration_ms=int((time.monotonic() - start_monotonic) * 1000),
                exit_code=None,
                stdout="",
                stderr=f"Command not found: {cmd[0]}",
                timeout_seconds=timeout,
                status=ValidationStatus.SKIPPED,
                failures=[],
            )
        except Exception as e:
            finished = datetime.now(UTC)
            return ValidationResult(
                validator_name=self.name,
                command=cmd,
                started_at=start,
                finished_at=finished,
                duration_ms=int((time.monotonic() - start_monotonic) * 1000),
                exit_code=None,
                stdout="",
                stderr=str(e),
                timeout_seconds=timeout,
                status=ValidationStatus.ERROR,
                failures=[str(e)],
            )

    def _determine_status(self, exit_code: int, stdout: str, stderr: str) -> ValidationStatus:
        # Default: exit 0 = PASS, else FAIL
        # Subclasses can override for more nuance
        if exit_code == 0:
            return ValidationStatus.PASS
        return ValidationStatus.FAIL


class PytestValidator(Validator):
    name = "pytest"

    def is_applicable(self, repo_path: Path) -> bool:
        return any(
            [
                (repo_path / "pytest.ini").exists(),
                (repo_path / "pyproject.toml").exists(),
                (repo_path / "tests").exists(),
                any(repo_path.glob("test_*.py")),
                any(repo_path.glob("*_test.py")),
            ]
        )

    def get_command(self, repo_path: Path) -> list[str]:
        # Prefer python -m pytest
        return ["python", "-m", "pytest", "-q"]

    def parse_failures(self, stdout: str, stderr: str, exit_code: int) -> list[str]:
        failures: list[str] = []
        combined = stdout + "\n" + stderr
        for line in combined.splitlines():
            if "FAILED" in line or "AssertionError" in line or "ERROR" in line:
                failures.append(line.strip())
                if len(failures) >= 10:
                    break
        if not failures and exit_code != 0:
            failures.append(combined.strip()[:500])
        return failures


class RuffValidator(Validator):
    name = "ruff"

    def is_applicable(self, repo_path: Path) -> bool:
        return True  # always applicable for Python repos

    def get_command(self, repo_path: Path) -> list[str]:
        return ["python", "-m", "ruff", "check", "."]

    def parse_failures(self, stdout: str, stderr: str, exit_code: int) -> list[str]:
        failures: list[str] = []
        for line in (stdout + "\n" + stderr).splitlines():
            line = line.strip()
            if line and (".py:" in line or "error" in line.lower()):
                failures.append(line)
                if len(failures) >= 10:
                    break
        return failures


class MypyValidator(Validator):
    name = "mypy"

    def is_applicable(self, repo_path: Path) -> bool:
        return (repo_path / "mypy.ini").exists() or (repo_path / ".mypy.ini").exists() or any(repo_path.glob("**/*.py"))

    def get_command(self, repo_path: Path) -> list[str]:
        return ["python", "-m", "mypy", "."]

    def parse_failures(self, stdout: str, stderr: str, exit_code: int) -> list[str]:
        failures: list[str] = []
        for line in (stdout + "\n" + stderr).splitlines():
            if "error:" in line:
                failures.append(line.strip())
                if len(failures) >= 10:
                    break
        return failures


class CommandValidator(Validator):
    """Generic command validator for future ecosystems (npm, tsc, gradle, etc.)."""

    def __init__(self, name: str, command: list[str], applicable_check: str | None = None) -> None:
        self.name = name
        self._command = command
        self._applicable_check = applicable_check

    def is_applicable(self, repo_path: Path) -> bool:
        if not self._applicable_check:
            return False
        return (repo_path / self._applicable_check).exists()

    def get_command(self, repo_path: Path) -> list[str]:
        return self._command


# Registry
AVAILABLE_VALIDATORS: dict[str, type[Validator]] = {
    "pytest": PytestValidator,
    "ruff": RuffValidator,
    "mypy": MypyValidator,
}

# Future validators via CommandValidator factory
FUTURE_VALIDATORS: dict[str, tuple[list[str], str]] = {
    "npm": (["npm", "test"], "package.json"),
    "tsc": (["npx", "tsc", "--noEmit"], "tsconfig.json"),
    "gradle": (["./gradlew", "test"], "build.gradle"),
    "maven": (["mvn", "test"], "pom.xml"),
    "cargo": (["cargo", "test"], "Cargo.toml"),
    "go": (["go", "test", "./..."], "go.mod"),
}
