"""Sentinel CLI — Phase 12 (all commands)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.json import JSON
from rich.table import Table

app = typer.Typer(
    name="jev-sentinel",
    help="JEV Sentinel — AI Coding Agent Guardian",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()

# For testability, we keep global settings
def _print_json(data, pretty: bool = True):
    if pretty:
        console.print(JSON.from_data(data))
    else:
        print(json.dumps(data))


@app.command("init")
def init(
    path: str = typer.Option(".", "--path", "-p", help="Path to initialize"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
):
    """Initialize Sentinel in a repository."""
    p = Path(path).resolve()
    sentinel_dir = p / ".sentinel"
    sentinel_dir.mkdir(exist_ok=True)
    config_path = p / "sentinel.yaml"
    if not config_path.exists():
        # Copy default from package sentinel.yaml
        default = Path("sentinel.yaml")
        if default.exists():
            import shutil

            shutil.copy(default, config_path)
        else:
            config_path.write_text(
                "sentinel:\n  mode: gated\n  max_agent_retries: 3\n",
                encoding="utf-8",
            )
    msg = {"status": "initialized", "path": str(p), "config": str(config_path)}
    if json_output:
        _print_json(msg, pretty=False)
    else:
        console.print(f"[green]Initialized Sentinel in {p}[/green]")
        console.print(f"Config: {config_path}")


@app.command("inspect")
def inspect(
    repo: str = typer.Option(".", "--repo", "-r", help="Repository path"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
):
    """Inspect repository Git state."""
    from sentinel.git.repository import GitRepository

    git = GitRepository()
    try:
        repository = git.discover(Path(repo))
        snapshot = git.snapshot(repository)
        data = {
            "repository": repository.model_dump(mode="json"),
            "snapshot": snapshot.model_dump(mode="json"),
        }
        if json_output:
            print(json.dumps(data, indent=2, default=str))
        else:
            console.print(f"[bold]Repository:[/bold] {repository.path} ({repository.name})")
            console.print(f"Branch: {snapshot.branch} {'(detached)' if snapshot.is_detached else ''}")
            console.print(f"HEAD: {snapshot.head_commit}")
            console.print(f"Dirty: {snapshot.is_dirty}")
            if snapshot.staged_files:
                console.print(f"Staged: {snapshot.staged_files}")
            if snapshot.unstaged_files:
                console.print(f"Unstaged: {snapshot.unstaged_files}")
            if snapshot.untracked_files:
                console.print(f"Untracked: {snapshot.untracked_files}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("status")
def status(
    repo: str = typer.Option(".", "--repo", "-r", help="Repository path"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
):
    """Show repository status and ChangeSet summary."""
    from sentinel.git.repository import GitRepository

    git = GitRepository()
    try:
        repository = git.discover(Path(repo))
        changeset = git.changeset(repository)
        snapshot = git.snapshot(repository)
        data = {
            "repository": repository.model_dump(mode="json"),
            "snapshot": snapshot.model_dump(mode="json"),
            "changeset": changeset.model_dump(mode="json"),
            "summary": changeset.to_summary_dict(),
        }
        if json_output:
            print(json.dumps(data, indent=2, default=str))
        else:
            table = Table(title="Sentinel Status")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="magenta")
            table.add_row("Repository", repository.path)
            table.add_row("Branch", str(snapshot.branch))
            table.add_row("HEAD", str(snapshot.head_commit or "none (empty repo)"))
            table.add_row("Dirty", str(snapshot.is_dirty))
            table.add_row("Files changed", str(len(changeset.changed_files)))
            table.add_row("Lines added", str(sum(f.additions for f in changeset.changed_files)))
            table.add_row("Lines removed", str(sum(f.deletions for f in changeset.changed_files)))
            table.add_row("Binary", str(any(f.is_binary for f in changeset.changed_files)))
            console.print(table)
            if changeset.changed_files:
                console.print("\n[bold]Changed files:[/bold]")
                for cf in changeset.changed_files:
                    console.print(f"  {cf.change_type.value:8} {cf.path} (+{cf.additions}/-{cf.deletions}){' [binary]' if cf.is_binary else ''}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("diff")
def diff_cmd(
    repo: str = typer.Option(".", "--repo", "-r", help="Repository path"),
    baseline: Optional[str] = typer.Option(None, "--baseline", help="Baseline commit"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
):
    """Show unified diff."""
    from sentinel.git.repository import GitRepository

    git = GitRepository()
    try:
        repository = git.discover(Path(repo))
        changeset = git.changeset(repository, baseline=baseline)
        if json_output:
            print(json.dumps({"diff": changeset.unified_diff, "truncated": changeset.diff_truncated}, indent=2))
        else:
            if changeset.unified_diff:
                console.print(changeset.unified_diff)
                if changeset.diff_truncated:
                    console.print("[yellow][Diff truncated due to size limit][/yellow]")
            else:
                console.print("[dim]No changes[/dim]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("validate")
def validate(
    repo: str = typer.Option(".", "--repo", "-r", help="Repository path"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
    use_sandbox: bool = typer.Option(False, "--sandbox", help="Use Docker sandbox"),
):
    """Run deterministic validation (pytest, ruff, mypy)."""
    from pathlib import Path as _Path

    from sentinel.validation.engine import ValidationRunner

    runner = ValidationRunner()
    repo_path = _Path(repo).resolve()
    # Sandbox optional
    sandbox = None
    if use_sandbox:
        from sentinel.sandbox.executor import DockerSandboxExecutor

        sandbox = DockerSandboxExecutor()
        if not sandbox.is_available():
            console.print("[yellow]Docker not available, falling back to subprocess[/yellow]")
            from sentinel.sandbox.executor import SubprocessFallbackExecutor

            sandbox = SubprocessFallbackExecutor()

    results = runner.run(repo_path, use_sandbox=bool(sandbox), sandbox_executor=sandbox)
    data = [r.model_dump(mode="json") for r in results]
    if json_output:
        print(json.dumps(data, indent=2, default=str))
    else:
        table = Table(title="Validation Results")
        table.add_column("Validator", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Duration", style="green")
        table.add_column("Failures", style="red")
        for r in results:
            status_style = "green" if r.status.value == "PASS" else "red" if r.status.value == "FAIL" else "yellow"
            table.add_row(r.validator_name, f"[{status_style}]{r.status.value}[/{status_style}]", f"{r.duration_ms or 0}ms", "; ".join(r.failures[:2]) if r.failures else "-")
        console.print(table)
        # CI exit code: non-zero if any FAIL
        if any(r.status.value in ("FAIL", "TIMEOUT", "ERROR") for r in results):
            raise typer.Exit(code=1)


@app.command("analyze")
def analyze(
    repo: str = typer.Option(".", "--repo", "-r", help="Repository path"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
):
    """Run security analysis."""
    from sentinel.git.repository import GitRepository
    from sentinel.security.engine import SecurityAnalyzer

    git = GitRepository()
    analyzer = SecurityAnalyzer()
    try:
        repo_obj = git.discover(Path(repo))
        changeset = git.changeset(repo_obj)
        findings = analyzer.analyze(changeset)
        data = [f.model_dump(mode="json") for f in findings]
        if json_output:
            print(json.dumps(data, indent=2, default=str))
        else:
            if not findings:
                console.print("[green]No security findings[/green]")
            else:
                table = Table(title="Security Findings")
                table.add_column("Severity", style="red")
                table.add_column("Category", style="cyan")
                table.add_column("File", style="magenta")
                table.add_column("Evidence", style="yellow")
                for f in findings:
                    table.add_row(f.severity.value, f.category.value, f.file or "-", f.evidence[:60])
                console.print(table)
            # Exit non-zero if HIGH/CRITICAL
            if any(f.severity.value in ("HIGH", "CRITICAL") for f in findings):
                raise typer.Exit(code=2)
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("verify")
def verify(
    repo: str = typer.Option(".", "--repo", "-r", help="Repository path"),
    task: Optional[str] = typer.Option(None, "--task", "-t", help="User task description"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
    fixture: str = typer.Option("high_confidence_safe", "--fixture", help="JEV fixture for testing"),
):
    """Full verification: validation + security + JEV + risk + policy + decision."""
    import asyncio

    from sentinel.core.service import SentinelService

    service = SentinelService()
    try:
        result = asyncio.run(service.verify(repo, task=task, jev_fixture=fixture))
        decision = result["decision"]
        # Prepare output
        data = {
            "changeset": result["changeset"].model_dump(mode="json"),
            "validation_results": [r.model_dump(mode="json") for r in result["validation_results"]],
            "security_findings": [f.model_dump(mode="json") for f in result["security_findings"]],
            "jev_evaluation": result["jev_evaluation"].model_dump(mode="json"),
            "risk_assessment": result["risk_assessment"].model_dump(mode="json"),
            "policy_evaluation": result["policy_evaluation"].model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "approval": result["approval"].model_dump(mode="json") if result["approval"] else None,
        }
        if json_output:
            print(json.dumps(data, indent=2, default=str))
        else:
            # Human output
            console.print(f"\n[bold]Changeset:[/bold] {result['changeset'].id} ({len(result['changeset'].changed_files)} files)")
            # Validation
            table = Table(title="Validation")
            table.add_column("Validator")
            table.add_column("Status")
            for r in result["validation_results"]:
                table.add_row(r.validator_name, r.status.value)
            console.print(table)
            # Security
            sec = result["security_findings"]
            if sec:
                console.print(f"\n[bold]Security:[/bold] {len(sec)} findings")
                for f in sec[:5]:
                    console.print(f"  [{f.severity.value}] {f.category.value} — {f.file}: {f.evidence[:60]}")
            else:
                console.print("\n[green]Security: no findings[/green]")
            # JEV
            jev = result["jev_evaluation"]
            console.print(f"\n[bold]JEV:[/bold] overall risk {jev.overall_risk:.2f} (fixture: {fixture})")
            for s in jev.scores:
                console.print(f"  {s.dimension.value:25} {s.score:.2f} conf={s.confidence:.2f}")
            # Risk
            risk = result["risk_assessment"]
            console.print(f"\n[bold]Risk:[/bold] {risk.level.value} (score {risk.score:.1f})")
            console.print(f"  {risk.explanation}")
            # Policy
            pol = result["policy_evaluation"]
            if pol.triggered:
                console.print(f"\n[bold]Policy triggered:[/bold] {[r.rule_name for r in pol.triggered if r.matched]}")
            # Decision
            color = {"ACCEPT": "green", "REVISE": "yellow", "REJECT": "red", "REQUIRE_HUMAN_REVIEW": "magenta", "BLOCK": "red"}.get(decision.action.value, "white")
            console.print(f"\n[bold {color}]Decision: {decision.action.value}[/bold {color}]")
            console.print(f"Reason: {decision.reason}")
            if result["approval"]:
                console.print(f"Approval required: {result['approval'].id}")

        # CI exit codes: 0=accept, 1=revise/reject, 2=human_review/block
        if decision.action.value == "ACCEPT":
            raise typer.Exit(code=0)
        elif decision.action.value in ("REVISE", "REJECT"):
            raise typer.Exit(code=1)
        else:  # REQUIRE_HUMAN_REVIEW, BLOCK
            raise typer.Exit(code=2)
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback

        traceback.print_exc()
        raise typer.Exit(code=1)


@app.command("rollback")
def rollback(
    repo: str = typer.Option(".", "--repo", "-r", help="Repository path"),
    commit: Optional[str] = typer.Option(None, "--commit", help="Commit to rollback to"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
):
    """Safe rollback of repository changes."""
    from sentinel.git.repository import GitRepository

    git = GitRepository()
    try:
        repository = git.discover(Path(repo))
        git.rollback(repository, commit=commit)
        msg = {"status": "rolled_back", "commit": commit or "working_tree_cleaned"}
        if json_output:
            print(json.dumps(msg))
        else:
            console.print(f"[green]Rolled back: {msg['commit']}[/green]")
    except Exception as e:
        console.print(f"[red]Rollback failed: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("history")
def history(
    repo: str = typer.Option(".", "--repo", "-r", help="Repository path (unused, for compatibility)"),
    limit: int = typer.Option(20, "--limit", help="Number of events"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
):
    """Show audit history."""
    try:
        from sentinel.core.db import get_session_factory

        Session = get_session_factory()
        from sentinel.audit.service import AuditService

        with Session() as db:
            svc = AuditService()
            events = svc.query(db, limit=limit)
            data = [e.model_dump(mode="json") for e in events]
            if json_output:
                print(json.dumps(data, indent=2, default=str))
            else:
                table = Table(title="Audit History")
                table.add_column("Time", style="cyan")
                table.add_column("Event", style="magenta")
                table.add_column("Actor", style="green")
                table.add_column("Payload", style="yellow")
                for e in data[:limit]:
                    table.add_row(e["timestamp"], e["event_type"], e["actor"], str(e["payload"])[:60])
                console.print(table)
    except Exception as e:
        # Fallback if DB not configured
        if json_output:
            print(json.dumps([], indent=2))
        else:
            console.print(f"[dim]No audit history available: {e}[/dim]")


@app.command("approve")
def approve_cmd(
    approval_id: str = typer.Argument(..., help="Approval ID"),
    approver: str = typer.Option("admin", "--approver", help="Approver identity"),
):
    """Approve a pending decision."""
    from sentinel.approval.service import ApprovalService

    svc = ApprovalService()
    # For CLI, we use in-memory global — but in real usage, need persistent store.
    # Try to load from shared singleton
    from sentinel.api.routes.approvals import _approval_service

    try:
        req = _approval_service.approve(approval_id, approver)
        console.print(f"[green]Approved {approval_id} by {approver}[/green]")
        console.print(req.model_dump_json(indent=2))
    except Exception as e:
        console.print(f"[red]Approve failed: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("reject")
def reject_cmd(
    approval_id: str = typer.Argument(..., help="Approval ID"),
    approver: str = typer.Option("admin", "--approver", help="Approver identity"),
    reason: str = typer.Option("", "--reason", help="Reason"),
):
    """Reject a pending decision."""
    from sentinel.api.routes.approvals import _approval_service

    try:
        req = _approval_service.reject(approval_id, approver, reason)
        console.print(f"[red]Rejected {approval_id} by {approver}[/red]")
        console.print(req.model_dump_json(indent=2))
    except Exception as e:
        console.print(f"[red]Reject failed: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("policy")
def policy_cmd(
    path: str = typer.Option("sentinel.yaml", "--path", help="Policy file path"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
):
    """Show loaded policy."""
    from sentinel.policy.engine import PolicyEngine

    engine = PolicyEngine(policy_file=Path(path) if Path(path).exists() else None)
    data = [{"name": r.name, "action": r.action.value, "when": r.when.model_dump(), "precedence": r.precedence} for r in engine.rules]
    if json_output:
        print(json.dumps(data, indent=2, default=str))
    else:
        table = Table(title="Policy Rules")
        table.add_column("Name", style="cyan")
        table.add_column("Action", style="magenta")
        table.add_column("When", style="yellow")
        table.add_column("Prec", style="green")
        for r in engine.rules:
            table.add_row(r.name, r.action.value, str(r.when.model_dump(exclude_none=True)), str(r.precedence))
        console.print(table)


@app.command("config")
def config_cmd(
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON"),
):
    """Show current config."""
    from sentinel.config.settings import get_settings

    s = get_settings()
    data = s.model_dump()
    if json_output:
        print(json.dumps(data, indent=2, default=str))
    else:
        console.print(JSON.from_data(data))


@app.command("start")
def start(
    host: str = typer.Option("0.0.0.0", "--host", help="Host"),
    port: int = typer.Option(8000, "--port", help="Port"),
    reload: bool = typer.Option(False, "--reload", help="Reload"),
):
    """Start API server."""
    import uvicorn

    console.print(f"[green]Starting Sentinel API on {host}:{port}[/green]")
    uvicorn.run("sentinel.api.main:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
