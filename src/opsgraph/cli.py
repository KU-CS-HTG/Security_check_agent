"""Command line entry point:  python -m opsgraph --help"""

from __future__ import annotations

import json
from typing import Annotated

import typer

from opsgraph.config import (
    PROJECT_ROOT,
    get_settings,
    load_app_config,
    load_docs_corpus,
    load_sources,
)
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
normalize_app = typer.Typer(no_args_is_help=True, help="raw -> core (rule based, no LLM)")
app.add_typer(osv_app, name="osv")
app.add_typer(normalize_app, name="normalize")
docs_app = typer.Typer(no_args_is_help=True, help="documentation corpus: clauses")
app.add_typer(docs_app, name="docs")

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


@collect_app.command("postgresql-docs")
def collect_postgresql_docs(limit: Limit = None, dry_run: Dry = False) -> None:
    """PostgreSQL documentation pages listed in config/docs_corpus.yaml (corpus A)."""
    from opsgraph.collectors.postgresql_docs import PostgresDocsCollector

    source, _ = _approved("postgresql")
    col = PostgresDocsCollector(_http(), make_engine(get_settings()), source, load_docs_corpus())
    _report(col.collect(limit=limit, dry_run=dry_run))


Force = Annotated[bool, typer.Option("--force", help="rebuild even if the raw data is unchanged")]


@normalize_app.command("osv")
def normalize_osv_cmd(force: Force = False, limit: Limit = None) -> None:
    """raw.osv_vulnerability -> core.vulnerability / affected_package / version_range / ..."""
    from opsgraph.normalize.osv import normalize_osv

    sources = load_sources()
    stats = normalize_osv(make_engine(get_settings(), "pipeline"), sources.license_policy,
                          force=force, limit=limit)
    typer.echo(json.dumps(stats.as_dict(), ensure_ascii=False, indent=2))
    if stats.errors:
        raise typer.Exit(1)


@normalize_app.command("pg")
def normalize_pg_cmd(force: Force = False, limit: Limit = None) -> None:
    """raw.web_page (PostgreSQL security pages) -> core.pg_advisory, plus a coverage report."""
    from opsgraph.normalize.pg_advisory import normalize_pg_advisories, parse_coverage

    engine = make_engine(get_settings(), "pipeline")
    stats = normalize_pg_advisories(engine, load_sources().license_policy, force=force, limit=limit)
    typer.echo(json.dumps(stats.as_dict(), ensure_ascii=False, indent=2))
    typer.echo("\nparser coverage (pages where the field was found):")
    for name, (found, total) in parse_coverage(engine).items():
        pct = f"{100 * found / total:.0f}%" if total else "-"
        typer.echo(f"  {name:<15} {found:>4}/{total:<4} {pct}")
    if stats.errors:
        raise typer.Exit(1)


@app.command("inspect-page")
def inspect_page(cve: Annotated[str, typer.Argument(help="e.g. CVE-2021-23214")]) -> None:
    """Show what the parser sees on one stored PostgreSQL security page (for tuning the parser)."""
    from sqlalchemy import text

    from opsgraph.normalize.pg_advisory import parse_advisory

    engine = make_engine(get_settings(), "pipeline")
    with engine.connect() as conn:
        row = conn.execute(text("SELECT url, body FROM raw.web_page WHERE url LIKE :u"),
                           {"u": f"%/{cve}/%"}).first()
    if row is None:
        typer.secho(f"no stored page for {cve}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    parsed = parse_advisory(row.body, row.url)
    text_view = parsed.pop("full_text")
    typer.echo(json.dumps(parsed, ensure_ascii=False, indent=2, default=str))
    typer.echo("\n--- page text as the parser sees it (first 60 lines) ---")
    typer.echo("\n".join(text_view.splitlines()[:60]))


@docs_app.command("parse")
def docs_parse(force: Force = False, limit: Limit = None) -> None:
    """raw documentation pages -> core.document / core.clause, plus a per-page report."""
    from opsgraph.normalize.docs import doc_report, normalize_docs

    engine = make_engine(get_settings(), "pipeline")
    stats = normalize_docs(engine, load_sources().license_policy, force=force, limit=limit)
    typer.echo(json.dumps(stats.as_dict(), ensure_ascii=False, indent=2))
    typer.echo("\nper page (clauses / chars / longest clause):")
    for r in doc_report(engine):
        flag = "  <-- no clauses" if r["clauses"] == 0 else ""
        typer.echo(f"  {r['url'].split('/docs/', 1)[-1]:<45} {r['clauses']:>4} {r['chars']:>7} "
                   f"{r['longest']:>6}{flag}")
    if stats.errors:
        raise typer.Exit(1)


@docs_app.command("show")
def docs_show(page: Annotated[str, typer.Argument(help="page name, e.g. auth-pg-hba-conf")],
              full: Annotated[bool, typer.Option("--full", help="print whole clause text")] = False,
              ) -> None:
    """List the clauses of one stored page (heading path, size, text start)."""
    from sqlalchemy import text

    engine = make_engine(get_settings(), "pipeline")
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT c.ordinal, c.key, c.heading_path, c.text, c.source_url
            FROM core.clause c JOIN core.document d ON d.id = c.document_id
            WHERE d.url LIKE :u ORDER BY c.ordinal"""), {"u": f"%/{page}.html"}).all()
    if not rows:
        typer.secho(f"no clauses for {page}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    for r in rows:
        path = " > ".join(r.heading_path)
        typer.echo(f"[{r.ordinal}] {path}  ({len(r.text)} chars)  {r.source_url}")
        body = r.text if full else r.text[:200].replace("\n", " / ")
        typer.echo(f"    {body}")


if __name__ == "__main__":  # pragma: no cover
    app()
