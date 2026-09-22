# Windows + Docker Desktop Requirements — JEV Sentinel

## Required

- Windows 10/11 Pro/Enterprise (or Home with WSL2)
- Docker Desktop 4.30+ (tested with 27.0.3)
- WSL2 backend enabled
- 8GB+ RAM, 20GB disk

## Installation

1. Install Docker Desktop: https://docs.docker.com/desktop/install/windows-install/
2. Enable WSL2: `wsl --install` then restart
3. In Docker Desktop → Settings → General → Enable `Use the WSL 2 based engine`
4. Verify:

```powershell
docker --version
docker context ls
docker --context default info  # should succeed if engine running
docker ps
```

## Sentinel Sandbox Modes

| Mode | When | Behavior |
|------|------|----------|
| `DockerSandboxExecutor` | Production (default) | Ephemeral `python:3.12-slim` containers, `network_disabled`, `mem_limit=512m`, `cpu=1`, `pids_limit=128`, mounts only `/workspace` |
| `SubprocessFallbackExecutor` | Development/testing only | Restricted `subprocess.run` with env allowlist, deny `rm/sudo/chmod`, disabled in `production` |

## Configuration

`sentinel.yaml`:

```yaml
sandbox:
  enabled: true
  image: python:3.12-slim
  cpu_limit: 1.0
  memory_limit: 512m
  network_disabled: true
  fallback_enabled: false  # MUST be false in production
```

`.env`:

```
DOCKER_ENABLED=true
SANDBOX_IMAGE=python:3.12-slim
SENTINEL_ENV=development  # or production
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Docker unavailable` | Engine not running | Start Docker Desktop, wait for green status |
| `open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified` | WSL2 not running | `wsl --shutdown && wsl` then restart Docker |
| `docker context ls` shows `desktop-linux *` but `docker info` fails | Context mismatch | `docker context use default` or restart Docker |
| `Image missing` | First run | `docker pull python:3.12-slim` manually |

## CI / Headless

On Windows CI without Docker Desktop, Sentinel falls back to `SubprocessFallbackExecutor` only if `SENTINEL_ENV != production` and `SANDBOX_FALLBACK_ENABLED=true`. Production CI must have Docker.

## Verification

```powershell
jev-sentinel validate --repo C:\path\to\repo --sandbox
jev-sentinel verify --repo C:\path\to\repo --task "Add feature"
```
