"""Sandbox executors — Phase 3."""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from sentinel.config.settings import Settings, get_settings
from sentinel.core.exceptions import SandboxError


class SandboxResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    command: list[str]
    exit_code: int | None = Field(default=None)
    stdout: str = Field(default="")
    stderr: str = Field(default="")
    stdout_truncated: bool = Field(default=False)
    stderr_truncated: bool = Field(default=False)
    timed_out: bool = Field(default=False)
    oom_killed: bool = Field(default=False)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = Field(default=None)
    duration_ms: int | None = Field(default=None)

    def compute_duration(self) -> None:
        if self.started_at and self.finished_at:
            self.duration_ms = int((self.finished_at - self.started_at).total_seconds() * 1000)


class SandboxExecutor(ABC):
    @abstractmethod
    def execute(self, command: list[str], workdir: Path, timeout: int = 120, env: dict[str, str] | None = None) -> SandboxResult:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...


SENSITIVE_MOUNT_DENYLIST = {
    Path.home() / ".ssh",
    Path.home() / ".aws",
    Path.home() / ".gcloud",
    Path.home() / ".gnupg",
    Path("/etc/shadow"),
    Path("/etc/passwd"),
    Path("/root"),
}


class DockerSandboxExecutor(SandboxExecutor):
    """Docker-based sandbox — production safety mechanism."""

    def __init__(
        self,
        settings: Settings | None = None,
        image: str | None = None,
        cpu_limit: float = 1.0,
        memory_limit: str = "512m",
        network_disabled: bool = True,
    ) -> None:
        self.settings = settings or get_settings()
        self.image = image or self.settings.sandbox_image
        self.cpu_limit = cpu_limit
        self.memory_limit = memory_limit
        self.network_disabled = network_disabled
        self._docker_available: bool | None = None

    def is_available(self) -> bool:
        if self._docker_available is not None:
            return self._docker_available
        try:
            import docker  # type: ignore[import-untyped]

            client = docker.from_env()
            client.ping()
            self._docker_available = True
        except Exception:
            self._docker_available = False
        return self._docker_available

    def execute(self, command: list[str], workdir: Path, timeout: int = 120, env: dict[str, str] | None = None) -> SandboxResult:
        """Execute command in isolated Docker container."""
        if not isinstance(command, list) or any(not isinstance(c, str) for c in command):
            raise SandboxError("Command must be list[str]")
        if any("\x00" in c for c in command):
            raise SandboxError("Null byte in command")
        # Validate workdir not sensitive
        resolved = workdir.resolve()
        for denied in SENSITIVE_MOUNT_DENYLIST:
            try:
                if resolved == denied.resolve() or denied.resolve() in resolved.parents:
                    raise SandboxError(f"Refusing to mount sensitive path: {resolved}")
            except OSError:
                pass

        start = datetime.now(UTC)
        time.monotonic()
        result = SandboxResult(command=command, started_at=start)

        if not self.is_available():
            result.stderr = "Docker unavailable"
            result.finished_at = datetime.now(UTC)
            result.compute_duration()
            raise SandboxError("Docker unavailable — cannot execute in sandbox")

        try:
            import docker  # type: ignore[import-untyped]
            from docker.errors import ImageNotFound  # type: ignore[import-untyped]

            client = docker.from_env()
            # Ensure image — local first, pull second; never silently substitute another image
            try:
                client.images.get(self.image)
            except ImageNotFound:
                try:
                    client.images.pull(self.image)
                except Exception as e:
                    raise SandboxError(
                        f"Sandbox image '{self.image}' not available locally and pull failed: {e}. "
                        f"Build it with: docker build -f docker/sandbox.Dockerfile -t {self.image} ."
                    ) from e

            # Read-only workspace + writable tmpfs /tmp: agent code cannot touch the
            # real repo, drop all capabilities, run as unprivileged user.
            allowed_env = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",  # noqa: S108 -- container-internal path
                "PYTHONPATH": "/workspace/src:/workspace",
                "HOME": "/tmp",  # noqa: S108 -- container-internal path (tmpfs)
                "LANG": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            if env:
                # Only allow explicitly permitted keys
                cfg_env: list[str] = self.settings.load_yaml_overrides().get("sandbox", {}).get("allowed_env", [])
                filtered_env = {k: v for k, v in env.items() if k in allowed_env or k in cfg_env}
                allowed_env.update(filtered_env)

            # Security: never expose host env secrets
            # Remove any potential secret keys
            for key in list(allowed_env.keys()):
                if any(s in key.lower() for s in ["secret", "token", "key", "password", "credential"]):
                    allowed_env.pop(key, None)

            # Run container
            container = client.containers.run(
                image=self.image,
                command=command,
                working_dir="/workspace",
                volumes={str(resolved): {"bind": "/workspace", "mode": "ro"}},
                environment=allowed_env,
                network_disabled=self.network_disabled,
                mem_limit=self.memory_limit,
                nano_cpus=int(self.cpu_limit * 1_000_000_000),
                pids_limit=128,
                user="1000:1000",
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                read_only=True,
                tmpfs={"/tmp": "size=256m"},  # noqa: S108 -- container-internal tmpfs
                detach=True,
                auto_remove=False,
                stdout=True,
                stderr=True,
            )
            try:
                exit_info = container.wait(timeout=timeout)
                exit_code = exit_info.get("StatusCode", 1)
                logs = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                err_logs = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
                # Truncate output
                max_out = self.settings.max_output_size
                stdout_trunc = False
                stderr_trunc = False
                if len(logs.encode("utf-8")) > max_out:
                    logs = logs[:max_out]
                    stdout_trunc = True
                if len(err_logs.encode("utf-8")) > max_out:
                    err_logs = err_logs[:max_out]
                    stderr_trunc = True
                result.exit_code = exit_code
                result.stdout = logs
                result.stderr = err_logs
                result.stdout_truncated = stdout_trunc
                result.stderr_truncated = stderr_trunc
                # Docker reports OOM in container state, not in the wait() payload
                try:
                    container.reload()
                    result.oom_killed = bool(container.attrs.get("State", {}).get("OOMKilled", False))
                except Exception:  # noqa: S110 -- best-effort; state may be unavailable after removal
                    result.oom_killed = False
            except Exception as e:
                # Timeout or other
                if "timeout" in str(e).lower():
                    result.timed_out = True
                    try:
                        container.kill()
                    except Exception:  # noqa: S110 -- container may already be dead
                        pass
                    result.stderr = f"Container timeout after {timeout}s"
                else:
                    result.stderr = str(e)
            finally:
                try:
                    container.remove(force=True)
                except Exception:  # noqa: S110 -- best-effort cleanup
                    pass

        except SandboxError:
            raise
        except Exception as e:
            result.stderr = str(e)
            result.exit_code = None

        result.finished_at = datetime.now(UTC)
        result.compute_duration()
        if result.timed_out:
            # Also mark exit_code None
            pass
        return result


class SubprocessFallbackExecutor(SandboxExecutor):
    """Restricted subprocess fallback — only for development/testing, never production."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        if self.settings.is_production and not self.settings.sandbox_fallback_enabled:
            # In production this should not be used
            pass

    def is_available(self) -> bool:
        # Only available if fallback enabled
        if self.settings.is_production and not self.settings.sandbox_fallback_enabled:
            return False
        return True

    def execute(self, command: list[str], workdir: Path, timeout: int = 120, env: dict[str, str] | None = None) -> SandboxResult:
        if self.settings.is_production and not self.settings.sandbox_fallback_enabled:
            raise SandboxError("Subprocess fallback disabled in production")
        if not isinstance(command, list):
            raise SandboxError("Command must be list[str]")
        # Allowlist check — never allow destructive commands
        DENY = {"rm", "sudo", "chmod", "chown", "mkfs", "dd", "shutdown", "reboot"}
        if command and command[0] in DENY:
            raise SandboxError(f"Command denied in fallback: {command[0]}")
        # Prevent sensitive path access
        resolved = workdir.resolve()
        for denied in SENSITIVE_MOUNT_DENYLIST:
            try:
                if resolved == denied.resolve() or denied.resolve() in resolved.parents:
                    raise SandboxError(f"Refusing to execute in sensitive path: {resolved}")
            except OSError:
                pass

        start = datetime.now(UTC)
        time.monotonic()
        result = SandboxResult(command=command, started_at=start)
        # Filter env — allowlist only. PATH must never be empty: an empty PATH
        # makes the child unable to resolve executables (broke on Linux where
        # an unset caller env produced PATH="" and every command "failed").
        safe_env: dict[str, str] = {"HOME": str(Path.home()), "LANG": "C.UTF-8"}
        if env:
            for k, v in env.items():
                if k in ["PATH", "PYTHONPATH", "HOME", "LANG", "VIRTUAL_ENV"]:
                    safe_env[k] = v
        if not safe_env.get("PATH"):
            safe_env["PATH"] = os.environ.get("PATH", "")

        try:
            proc = subprocess.run(
                command,
                cwd=str(resolved),
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                env=safe_env if safe_env else None,
            )
            max_out = self.settings.max_output_size
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            if len(stdout.encode("utf-8")) > max_out:
                stdout = stdout[:max_out]
                result.stdout_truncated = True
            if len(stderr.encode("utf-8")) > max_out:
                stderr = stderr[:max_out]
                result.stderr_truncated = True
            result.stdout = stdout
            result.stderr = stderr
            result.exit_code = proc.returncode
        except subprocess.TimeoutExpired as e:
            result.timed_out = True
            result.stdout = (e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout or "")) if e.stdout else ""
            result.stderr = f"Timeout after {timeout}s"
            result.exit_code = None
        except Exception as e:
            result.stderr = str(e)
            result.exit_code = None

        result.finished_at = datetime.now(UTC)
        result.compute_duration()
        return result
