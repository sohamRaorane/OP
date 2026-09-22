"""Safe Git command execution — Phase 1."""

from __future__ import annotations

import subprocess
from pathlib import Path

from sentinel.core.exceptions import GitCommandError


class SafeGitExecutor:
    """Executes git commands safely — no shell, no string concatenation."""

    DEFAULT_TIMEOUT = 30

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    def run(
        self,
        repo_path: Path,
        args: list[str],
        check: bool = True,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run `git <args>` in repo_path. Always uses arg list, never shell."""
        if not isinstance(args, list):
            raise ValueError("args must be a list")
        if any(not isinstance(a, str) for a in args):
            raise ValueError("all args must be strings")
        # Prevent injection via args starting with dangerous chars? Git handles, but we validate.
        # We allow any string as git arg; we just never invoke shell.
        cmd: list[str] = ["git", *args]
        try:
            result = subprocess.run(
                cmd,
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                shell=False,  # critical: never shell
                env=env,
            )
        except subprocess.TimeoutExpired as e:
            raise GitCommandError(
                f"Git command timed out: {' '.join(cmd)}",
                command=cmd,
                stderr=str(e),
            ) from e
        except FileNotFoundError as e:
            raise GitCommandError("git executable not found", command=cmd) from e
        except OSError as e:
            raise GitCommandError(f"Git execution failed: {e}", command=cmd) from e

        if check and result.returncode != 0:
            raise GitCommandError(
                f"Git command failed: {' '.join(cmd)}: {result.stderr.strip()}",
                command=cmd,
                exit_code=result.returncode,
                stderr=result.stderr,
            )
        return result

    def run_no_check(self, repo_path: Path, args: list[str], timeout: int | None = None) -> subprocess.CompletedProcess[str]:
        return self.run(repo_path, args, check=False, timeout=timeout)
