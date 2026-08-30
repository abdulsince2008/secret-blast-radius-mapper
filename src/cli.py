"""CLI for Secret Blast-Radius Mapper."""
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.json import JSON

from src.detector import run_gitleaks, enrich_with_git_info
from src.git_tracer import find_secret_origin
from src.config_parser import parse_all_configs
from src.graph_builder import (
    build_service_graph, infer_dependencies, calculate_blast_radius, build_blast_radius_graph
)
from src.models import BlastRadiusResult

console = Console()


@click.command()
@click.argument('repo_path', type=click.Path(exists=True, path_type=Path), default='.')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output JSON file')
@click.option('--gitleaks-config', '-c', type=click.Path(exists=True, path_type=Path), help='Gitleaks config file')
@click.option('--min-score', '-s', type=int, default=0, help='Minimum blast radius score to display')
@click.option('--format', '-f', 'output_format', type=click.Choice(['table', 'json', 'tree']), default='table', help='Output format')
@click.option('--no-graph', is_flag=True, help='Skip building dependency graph')
@click.version_option(version='0.1.0')
def main(
    repo_path: Path,
    output: Optional[Path],
    gitleaks_config: Optional[Path],
    min_score: int,
    output_format: str,
    no_graph: bool,
):
    """
    Secret Blast-Radius Mapper - Trace secret exposure impact across your codebase.
    
    Detects secrets with gitleaks, traces their git history origin, and maps
    which services are affected through config file references.
    """
    repo_path = repo_path.resolve()
    
    if not (repo_path / '.git').exists():
        console.print(f"[red]Error:[/red] {repo_path} is not a git repository")
        sys.exit(1)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Step 1: Detect secrets
        task1 = progress.add_task("Running gitleaks...", total=None)
        try:
            findings = run_gitleaks(repo_path, gitleaks_config)
        except RuntimeError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
        progress.update(task1, completed=True)
        
        if not findings:
            console.print("[green]No secrets detected![/green]")
            if output:
                output.write_text(json.dumps({"findings": []}, indent=2))
            return
        
        # Step 2: Enrich with git info
        task2 = progress.add_task("Enriching with git history...", total=None)
        findings = enrich_with_git_info(repo_path, findings)
        progress.update(task2, completed=True)
        
        # Step 3: Parse config files
        task3 = progress.add_task("Parsing config files...", total=None)
        config_refs = parse_all_configs(repo_path)
        progress.update(task3, completed=True)
        
        # Step 4: Build service graph
        task4 = progress.add_task("Building service graph...", total=None)
        services = build_service_graph(config_refs)
        infer_dependencies(services, config_refs)
        progress.update(task4, completed=True)
        
        # Step 5: Calculate blast radius for each finding
        task5 = progress.add_task("Calculating blast radius...", total=None)
        results = []
        for finding in findings:
            origin_commit, author, date = find_secret_origin(repo_path, finding)
            result = calculate_blast_radius(finding, config_refs, services)
            result.origin_commit = origin_commit
            result.introduced_by = author
            result.introduced_date = date
            results.append(result)
        progress.update(task5, completed=True)
    
    # Filter by min score
    results = [r for r in results if r.blast_radius_score >= min_score]
    
    if not results:
        console.print(f"[yellow]No findings with score >= {min_score}[/yellow]")
        return
    
    # Output
    if output_format == 'json':
        output_json(results, output)
    elif output_format == 'tree':
        output_tree(results)
    else:
        output_table(results)
    
    # Write JSON output if requested
    if output:
        output_json(results, output)


def output_table(results: list[BlastRadiusResult]) -> None:
    """Output results as a rich table."""
    table = Table(title="Secret Blast-Radius Analysis", show_header=True, header_style="bold magenta")
    table.add_column("Secret", style="cyan", width=20)
    table.add_column("File", style="blue", width=30)
    table.add_column("Line", justify="right", width=6)
    table.add_column("Origin", style="yellow", width=25)
    table.add_column("Config Refs", justify="right", width=10)
    table.add_column("Services", justify="right", width=10)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Risk", style="bold", width=10)
    
    for result in results:
        secret = result.secret
        origin = f"{result.origin_commit or 'unknown'} ({result.introduced_by or '?'})"
        
        risk_style = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(result.risk_level, "white")
        
        table.add_row(
            secret.rule_id,
            secret.file_path,
            str(secret.line_number),
            origin,
            str(len(result.config_references)),
            str(len(result.affected_services)),
            str(result.blast_radius_score),
            f"[{risk_style}]{result.risk_level}[/{risk_style}]",
        )
    
    console.print(table)
    
    # Print details for each finding
    for result in results:
        print_finding_details(result)


def print_finding_details(result: BlastRadiusResult) -> None:
    """Print detailed information for a finding."""
    secret = result.secret
    
    console.print()
    console.print(Panel.fit(
        f"[bold]{secret.rule_id}[/bold] in [cyan]{secret.file_path}:{secret.line_number}[/cyan]\n"
        f"Type: {secret.secret_type.value} | Preview: {secret.secret_preview}\n"
        f"Origin: {result.origin_commit or 'unknown'} by {result.introduced_by or 'unknown'} on {result.introduced_date or 'unknown'}\n"
        f"Blast Radius Score: [bold]{result.blast_radius_score}[/bold] ({result.risk_level})",
        title="Finding Details",
        border_style="blue",
    ))
    
    if result.config_references:
        ref_table = Table(title="Config References", show_header=True)
        ref_table.add_column("File", style="cyan")
        ref_table.add_column("Type", style="blue")
        ref_table.add_column("Service", style="green")
        ref_table.add_column("Variable", style="yellow")
        ref_table.add_column("Line", justify="right")
        ref_table.add_column("Hardcoded", justify="center")
        
        for ref in result.config_references:
            ref_table.add_row(
                ref.config_file,
                ref.config_type,
                ref.service_name or "-",
                ref.variable_name,
                str(ref.line_number) if ref.line_number else "-",
                "✓" if ref.is_hardcoded else "✗",
            )
        console.print(ref_table)
    
    if result.affected_services:
        svc_table = Table(title="Affected Services", show_header=True)
        svc_table.add_column("Service", style="cyan")
        svc_table.add_column("Type", style="blue")
        svc_table.add_column("Config Files", style="green")
        svc_table.add_column("Env Vars", style="yellow")
        svc_table.add_column("Depends On", style="magenta")
        
        for svc in result.affected_services:
            svc_table.add_row(
                svc.name,
                svc.type,
                str(len(svc.config_files)),
                str(len(svc.environment_variables)),
                ", ".join(svc.depends_on) if svc.depends_on else "-",
            )
        console.print(svc_table)


def output_tree(results: list[BlastRadiusResult]) -> None:
    """Output results as a tree."""
    for result in results:
        secret = result.secret
        tree = Tree(f"[bold red]{secret.rule_id}[/bold red] ({result.risk_level}, score: {result.blast_radius_score})")
        
        # Secret info
        secret_branch = tree.add("[cyan]Secret[/cyan]")
        secret_branch.add(f"File: {secret.file_path}:{secret.line_number}")
        secret_branch.add(f"Type: {secret.secret_type.value}")
        secret_branch.add(f"Preview: {secret.secret_preview}")
        secret_branch.add(f"Origin: {result.origin_commit or 'unknown'} by {result.introduced_by or 'unknown'}")
        
        # Config references
        if result.config_references:
            config_branch = tree.add("[blue]Config References[/blue]")
            for ref in result.config_references:
                ref_node = config_branch.add(f"[green]{ref.config_file}[/green] ({ref.config_type})")
                ref_node.add(f"Service: {ref.service_name or 'unknown'}")
                ref_node.add(f"Variable: {ref.variable_name}")
                ref_node.add(f"Hardcoded: {'Yes' if ref.is_hardcoded else 'No'}")
        
        # Affected services
        if result.affected_services:
            svc_branch = tree.add("[yellow]Affected Services[/yellow]")
            for svc in result.affected_services:
                svc_node = svc_branch.add(f"[magenta]{svc.name}[/magenta] ({svc.type})")
                svc_node.add(f"Config files: {len(svc.config_files)}")
                svc_node.add(f"Env vars: {len(svc.environment_variables)}")
                if svc.depends_on:
                    dep_node = svc_node.add("Depends on:")
                    for dep in svc.depends_on:
                        dep_node.add(dep)
        
        console.print(tree)
        console.print()


def output_json(results: list[BlastRadiusResult], output_path: Optional[Path] = None) -> None:
    """Output results as JSON."""
    data = {
        "findings": [r.to_dict() for r in results],
        "summary": {
            "total": len(results),
            "critical": sum(1 for r in results if r.risk_level == "CRITICAL"),
            "high": sum(1 for r in results if r.risk_level == "HIGH"),
            "medium": sum(1 for r in results if r.risk_level == "MEDIUM"),
            "low": sum(1 for r in results if r.risk_level == "LOW"),
        }
    }
    
    json_str = json.dumps(data, indent=2)
    
    if output_path:
        output_path.write_text(json_str)
        console.print(f"[green]Results written to {output_path}[/green]")
    else:
        console.print(JSON(json_str))


if __name__ == '__main__':
    main()