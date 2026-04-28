from __future__ import annotations

import asyncio
import json

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.core.config_loader import list_scenarios, load_scenario
from app.core.context import RunContext
from app.core.exceptions import ScenarioNotFound
from app.core.scenario_loader import build_orchestrator
from app.vulnerabilities.registry import get_registry

app = typer.Typer(
    name="vai-lab",
    help="Vulnerable AI Lab — intentionally vulnerable AI security training lab",
    add_completion=False,
)
console = Console()


def _boot() -> None:
    """Autodiscover all registered vulnerability modules."""
    get_registry().autodiscover()


# ── run ───────────────────────────────────────────────────────────────────────

@app.command()
def run(
    scenario: str = typer.Argument(..., help="Scenario ID (e.g. soc_copilot)"),
    input_text: str = typer.Option(..., "--input", "-i", help="User input to send"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show hook traces"),
    json_out: bool = typer.Option(False, "--json", help="Output raw JSON"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Provider override (e.g. ollama, anthropic)"),
) -> None:
    """Run a vulnerability scenario against a user prompt."""
    _boot()

    try:
        orchestrator = build_orchestrator(scenario, provider_override=provider)
    except Exception as exc:
        console.print(f"[red]Error building scenario '{scenario}': {exc}[/red]")
        raise typer.Exit(1)

    ctx = RunContext(scenario_id=scenario, user_input=input_text)
    console.print(f"[dim]Session: {ctx.session_id}[/dim]")
    console.print(f"[dim]Scenario: {scenario} | Modules: {', '.join(ctx.active_modules) or 'none'}[/dim]\n")

    with console.status("[cyan]Running...[/cyan]"):
        try:
            ctx = asyncio.run(orchestrator.run(ctx))
        except Exception as exc:
            console.print(f"[red]Run failed: {exc}[/red]")
            raise typer.Exit(1)

    if json_out:
        output = {
            "session_id": ctx.session_id,
            "final_response": ctx.final_response,
            "score_result": ctx.score_result,
            "active_modules": ctx.active_modules,
            "hook_traces": [
                {"hook_point": t.hook_point, "module_id": t.module_id, "mutations": t.mutations}
                for t in ctx.hook_traces
            ],
        }
        print(json.dumps(output, indent=2))
        return

    console.print(Panel(
        ctx.final_response or "[dim]No response[/dim]",
        title="[green]AI Response[/green]",
        border_style="green",
    ))

    if verbose and ctx.score_result:
        _print_score_table(ctx.score_result)

    if verbose and ctx.hook_traces:
        _print_hook_traces(ctx)

    console.print(f"\n[dim]Events: {len(ctx.telemetry_events)} | "
                  f"Tool calls: {len(ctx.tool_calls)} | "
                  f"Docs retrieved: {len(ctx.retrieved_docs)}[/dim]")


# ── seed ─────────────────────────────────────────────────────────────────────

@app.command()
def seed(
    scenario: str | None = typer.Argument(None, help="Scenario ID to seed (default: all)"),
) -> None:
    """Seed ChromaDB collections from scenario datasets."""
    from app.rag.pipeline import RAGPipeline, seed_scenario

    targets = [scenario] if scenario else list_scenarios()
    for s in targets:
        try:
            cfg = load_scenario(s)
        except ScenarioNotFound as exc:
            console.print(f"[red]✗[/red] {s}: {exc}")
            continue

        scenario_cfg = cfg.get("scenario", cfg)
        rag_cfg = scenario_cfg.get("rag", {})
        if not rag_cfg.get("enabled", False):
            console.print(f"[dim]skip[/dim] {s}: RAG not enabled")
            continue

        try:
            pipeline = RAGPipeline.from_config(rag_cfg)
            n = seed_scenario(pipeline, scenario_cfg)
            console.print(f"[green]✓[/green] {s}: seeded {n} documents")
        except Exception as exc:
            console.print(f"[red]✗[/red] {s}: {exc}")


# ── list-scenarios ────────────────────────────────────────────────────────────

@app.command(name="list-scenarios")
def list_scenarios_cmd() -> None:
    """List all available scenarios."""
    scenarios = list_scenarios()
    if not scenarios:
        console.print("[yellow]No scenarios found in configs/scenarios/[/yellow]")
        return
    table = Table(title="Available Scenarios", show_header=True)
    table.add_column("Scenario ID", style="cyan")
    for s in scenarios:
        table.add_row(s)
    console.print(table)


# ── list-modules ──────────────────────────────────────────────────────────────

@app.command(name="list-modules")
def list_modules_cmd() -> None:
    """List all registered vulnerability modules."""
    _boot()
    modules = get_registry().list_available()
    if not modules:
        console.print("[yellow]No vulnerability modules registered.[/yellow]")
        return
    table = Table(title="Registered Vulnerability Modules", show_header=True)
    table.add_column("Module ID", style="yellow")
    for m in modules:
        table.add_row(m)
    console.print(table)


# ── validate-config ───────────────────────────────────────────────────────────

@app.command(name="validate-config")
def validate_config(
    scenario: str | None = typer.Argument(None, help="Scenario ID to validate (default: all)"),
) -> None:
    """Validate scenario YAML configs."""
    _boot()
    targets = [scenario] if scenario else list_scenarios()
    errors: list[str] = []
    for s in targets:
        try:
            build_orchestrator(s)
            console.print(f"[green]✓[/green] {s}")
        except Exception as exc:
            console.print(f"[red]✗[/red] {s}: {exc}")
            errors.append(s)
    if errors:
        raise typer.Exit(1)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _print_score_table(score: dict) -> None:
    status = score.get("overall_status", "unknown")
    color = "red" if status == "vulnerable" else "green"

    table = Table(title="Scoring Results", show_header=True, show_lines=True)
    table.add_column("Rule ID", style="cyan", max_width=30)
    table.add_column("Severity", style="yellow", width=10)
    table.add_column("Triggered", width=10)
    table.add_column("Evidence", max_width=50)

    for ev in score.get("evidence", []):
        triggered = "[red]YES[/red]" if ev.get("passed") else "[green]NO[/green]"
        table.add_row(
            ev.get("rule_id", ""),
            ev.get("severity", "info"),
            triggered,
            (ev.get("evidence", "") or "")[:80],
        )
    console.print(table)

    triggered_count = score.get("triggered", 0)
    total = score.get("total_rules", 0)
    console.print(
        f"\nStatus: [{color}]{status.upper()}[/{color}] "
        f"({triggered_count}/{total} rules triggered)"
    )


def _print_hook_traces(ctx: RunContext) -> None:
    table = Table(title="Hook Traces", show_header=True, show_lines=True)
    table.add_column("Hook Point", style="magenta", width=20)
    table.add_column("Module", style="yellow", width=30)
    table.add_column("Mutations")
    for t in ctx.hook_traces:
        table.add_row(t.hook_point, t.module_id, ", ".join(t.mutations))
    console.print(table)


if __name__ == "__main__":
    app()
