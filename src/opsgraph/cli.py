"""Command line entry point:  python -m opsgraph --help"""

from __future__ import annotations

import json
from typing import Annotated

import typer

from opsgraph.config import PROJECT_ROOT, get_settings, load_app_config, load_sources
from opsgraph.http import HttpClient
from opsgraph.logging import configure_logging
from opsgraph.scope import load_scope
from opsgraph.storage.repository import CollectStats, make_engine

app = typer.Typer(no_args_is_help=True, help="opsgraph: collection and database commands")
db_app = typer.Typer(no_args_is_help=True, help="database schema")
collect_app = typer.Typer(no_args_is_help=True, help="run collectors (approved sources only)")
osv_app = typer.Typer(no_args_is_help=True, help="OSV helpers")
app.add_typer(db_app, name="db")
app.add_typer(collect_app, name="collect")
app.add_typer(osv_app, name="osv")

Dry = Annotated[bool, typer.Option("--dry-run", help="read and filter, but write nothing")]
Limit = Annotated[int | None, typer.Option("--limit", help="stop after N records (smoke test)")]


@app.callback()
def _main() -> None:
    configure_logging(get_settings().log_level)


def _approved(source_id: str):
    sources = load_sources()
    try:
        return sources.get(source_id), sources
    except KeyError as e:
        typer.secho(str(e.args[0]), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from e


def _http() -> HttpClient:
    cfg = load_app_config().http
    try:
        return HttpClient(cfg, get_settings().http_contact, cache_dir=PROJECT_ROOT / cfg.cache_dir)
    except ValueError as e:
        typer.secho(f"{e} (set HTTP_CONTACT in .env)", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from e


def _report(stats: CollectStats) -> None:
    typer.echo(json.dumps(stats.as_dict(), ensure_ascii=False, indent=2))
    if stats.errors:
        raise typer.Exit(1)


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Apply migrations (runs as the owner role)."""
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config(str(PROJECT_ROOT / "alembic.ini")), "head")
    typer.echo("database is at the latest revision")


@osv_app.command("ecosystems")
def osv_ecosystems() -> None:
    """List OSV ecosystems and check that the scope file only names existing ones."""
    from opsgraph.collectors.osv import OsvCollector

    source, sources = _approved("osv")
    http = _http()
    scope = load_scope()
    col = OsvCollector(http, make_engine(get_settings()), scope, source, sources.license_policy,
                       PROJECT_ROOT / "data")
    remote = col.remote_ecosystems()
    typer.echo(f"{len(remote)} ecosystems in the bucket")
    for eco in scope.ecosystems:
        mark = "ok     " if eco in remote else "MISSING"
        typer.echo(f"  [{mark}] {eco}")
    typer.echo("all ecosystems: " + ", ".join(remote))


@collect_app.command("osv")
def collect_osv(
    ecosystem: Annotated[list[str] | None, typer.Option("--ecosystem", "-e")] = None,
    limit: Limit = None,
    dry_run: Dry = False,
) -> None:
    """OSV records for the target products (config/osv_scope.yaml)."""
    from opsgraph.collectors.osv import OsvCollector

    source, sources = _approved("osv")
    col = OsvCollector(_http(), make_engine(get_settings()), load_scope(), source,
                       sources.license_policy, PROJECT_ROOT / "data")
    _report(col.collect(ecosystems=ecosystem, limit=limit, dry_run=dry_run))


@collect_app.command("postgresql-security")
def collect_postgresql_security(limit: Limit = None, dry_run: Dry = False) -> None:
    """PostgreSQL security index and per-CVE pages."""
    from opsgraph.collectors.postgresql_security import PostgresSecurityCollector

    source, _ = _approved("postgresql")
    col = PostgresSecurityCollector(_http(), make_engine(get_settings()), source)
    _report(col.collect(limit=limit, dry_run=dry_run))


if __name__ == "__main__":  # pragma: no cover
    app()
