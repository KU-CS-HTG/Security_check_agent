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
    load_models,
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
llm_app = typer.Typer(no_args_is_help=True, help="local LLM runtime")
app.add_typer(llm_app, name="llm")
extract_app = typer.Typer(no_args_is_help=True, help="check-item extraction (local LLM)")
app.add_typer(extract_app, name="extract")

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
    stats = normalize_docs(engine, load_sources().license_policy, force=force, limit=limit,
                           keep_urls=set(load_docs_corpus().urls()))
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


def _llm_client():
    from opsgraph.llm.ollama import LlmError, build_client

    try:
        return build_client(load_models())
    except LlmError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from e


@llm_app.command("check")
def llm_check() -> None:
    """Is the local model reachable, and does it follow the extraction schema? (sample clause)"""
    from opsgraph.extract.prompt import EXAMPLE_CLAUSE
    from opsgraph.extract.runner import extract_clause
    from opsgraph.llm.ollama import LlmError

    cfg = load_models().llm
    client = _llm_client()
    try:
        names = client.list_models()
    except LlmError as e:
        typer.secho(f"{e}\nIs Ollama running? (tray icon, or: ollama serve)", fg=typer.colors.RED,
                    err=True)
        raise typer.Exit(1) from e
    typer.echo(f"endpoint {client.endpoint}: {len(names)} model(s): {', '.join(names) or '-'}")
    if not any(n == cfg.model or n.split(":")[0] == str(cfg.model).split(":")[0] for n in names):
        typer.secho(f"model {cfg.model!r} not found. Run: ollama pull {cfg.model}",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    # the sample clause is deliberately made-up: it must NOT be answered from memory
    out = extract_clause(client, doc_title="(sample)", heading_path=["sample"], source_url="-",
                         text=EXAMPLE_CLAUSE, max_attempts=cfg.max_attempts)
    rate = out.completion_tokens / (out.duration_ms / 1000) if out.duration_ms else 0
    typer.echo(f"status={out.status} attempts={out.attempts} tokens(prompt/answer)="
               f"{out.prompt_tokens}/{out.completion_tokens} time={out.duration_ms / 1000:.1f}s "
               f"speed={rate:.0f} tok/s")
    for it in out.items:
        typer.echo(f"  item: {it.payload['title']} [{it.payload['category']}] "
                   f"evidence={'OK ' + str(it.evidence_match) if it.verified else 'NOT FOUND'}")
    if out.status == "failed":
        typer.secho(f"failed: {out.error}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


@extract_app.command("run")
def extract_run(
    page: Annotated[list[str] | None, typer.Option("--page", "-p", help="page name(s)")] = None,
    limit: Annotated[int | None, typer.Option("--limit", help="max clauses this run")] = None,
    min_chars: Annotated[int, typer.Option("--min-chars", help="skip shorter clauses")] = 80,
    force: Annotated[bool, typer.Option("--force", help="redo clauses that already have a result")]
    = False,
) -> None:
    """Extract check items from clauses. Resumable: finished clauses are skipped."""
    from opsgraph.extract.service import run_extraction

    cfg = load_models().llm
    client = _llm_client()
    engine = make_engine(get_settings(), "pipeline")

    def progress(i, n, clause, out):
        verified = sum(1 for it in out.items if it.verified)
        typer.echo(f"[{i}/{n}] {out.status:<6} attempts={out.attempts} items={len(out.items)} "
                   f"verified={verified} {out.duration_ms / 1000:.1f}s  {clause.key}")

    stats = run_extraction(engine, client, model=str(cfg.model), pages=page, limit=limit,
                           min_chars=min_chars, force=force, max_attempts=cfg.max_attempts,
                           on_progress=progress)
    typer.echo(json.dumps(stats.as_dict(), indent=2))
    if stats.failed:
        raise typer.Exit(1)


@extract_app.command("show")
def extract_show(
    page: Annotated[str, typer.Argument(help="page name, e.g. runtime-config-logging")],
    problems: Annotated[bool, typer.Option("--problems", help="only failed/rejected")] = False,
    limit: Annotated[int, typer.Option("--limit")] = 30,
) -> None:
    """Show results for the clauses of one page: items with their evidence, side by side."""
    from sqlalchemy import text

    from opsgraph.extract.prompt import PROMPT_VERSION

    engine = make_engine(get_settings(), "pipeline")
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT c.key, c.ordinal, r.status, r.attempts, r.error, i.payload, i.evidence_match,
                   i.evidence_verified, i.target_found
            FROM core.clause c JOIN core.document d ON d.id = c.document_id
            JOIN core.extraction_result r ON r.clause_id = c.id AND r.text_hash = c.text_hash
              AND r.model = :model AND r.prompt_version = :pv
            LEFT JOIN core.extracted_item i ON i.result_id = r.id
            WHERE d.url LIKE :u ORDER BY c.ordinal, i.id"""),
                            {"u": f"%/{page}.html", "model": str(load_models().llm.model),
                             "pv": PROMPT_VERSION}).all()
    shown = 0
    last = None
    for r in rows:
        bad = r.status == "failed" or (r.payload is not None and not r.evidence_verified)
        if problems and not bad:
            continue
        if r.key != last:
            if shown >= limit:
                break
            shown += 1
            last = r.key
            typer.echo(f"\n[{r.ordinal}] {r.key}  status={r.status} attempts={r.attempts}"
                       + (f"  error={r.error}" if r.error else ""))
        if r.payload is not None:
            p = r.payload
            mark = f"verified({r.evidence_match})" if r.evidence_verified else "NOT VERIFIED"
            missing = "" if r.target_found else " (target not in clause!)"
            risk = p["risk_level"]
            if p.get("risk_level_claimed"):
                risk += f" (model claimed {p['risk_level_claimed']}: no supporting quote)"
            typer.echo(f"   - {p['title']} [{p['category']}] target={p['target']}{missing} "
                       f"risk={risk}  {mark}")
            typer.echo(f"       evidence: {p['evidence_quote']}")
            if p.get("remediation"):
                typer.echo(f"       remediation: {p['remediation']}")
    if not rows:
        typer.secho(f"no extraction results for {page}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


@extract_app.command("stats")
def extract_stats() -> None:
    """Quality numbers of the stored results (feeds docs/ops/PHASE2.md and the evaluation)."""
    from sqlalchemy import text

    from opsgraph.extract.prompt import PROMPT_VERSION

    engine = make_engine(get_settings(), "pipeline")
    cur = {"model": str(load_models().llm.model), "pv": PROMPT_VERSION}
    typer.echo(f"model {cur['model']}, prompt version {cur['pv']}")
    with engine.connect() as conn:
        res = conn.execute(text("""
            SELECT status, count(*) AS n, round(avg(attempts), 2) AS avg_attempts,
                   round(avg(duration_ms) / 1000.0, 1) AS avg_seconds,
                   count(*) FILTER (WHERE attempts > 1) AS retried
            FROM core.extraction_result WHERE model = :model AND prompt_version = :pv
            GROUP BY status ORDER BY status"""), cur).all()
        items = conn.execute(text("""
            SELECT count(*) AS total, count(*) FILTER (WHERE i.evidence_verified) AS verified,
                   count(*) FILTER (WHERE i.evidence_match = 'loose') AS loose,
                   count(*) FILTER (WHERE NOT i.target_found) AS target_missing,
                   count(*) FILTER (WHERE i.status = 'approved') AS approved,
                   count(*) FILTER (WHERE i.status = 'pending') AS pending,
                   count(*) FILTER (WHERE i.payload ? 'risk_level_claimed') AS risk_dropped,
                   count(*) FILTER (WHERE i.risk_source = 'document') AS risk_kept
            FROM core.extracted_item i JOIN core.extraction_result r ON r.id = i.result_id
            WHERE r.model = :model AND r.prompt_version = :pv"""), cur).one()
        cats = conn.execute(text("""
            SELECT i.payload->>'category' AS category, count(*) AS n
            FROM core.extracted_item i JOIN core.extraction_result r ON r.id = i.result_id
            WHERE i.evidence_verified AND r.model = :model AND r.prompt_version = :pv
            GROUP BY 1 ORDER BY 2 DESC"""), cur).all()
    typer.echo("clause results (status / n / avg attempts / avg seconds / retried):")
    for r in res:
        typer.echo(f"  {r.status:<7} {r.n:>5}  {r.avg_attempts}  {r.avg_seconds}s  {r.retried}")
    pct = f"{100 * items.verified / items.total:.1f}%" if items.total else "-"
    typer.echo(f"items: {items.total}  evidence verified: {items.verified} ({pct})  "
               f"loose matches: {items.loose}  target missing: {items.target_missing}  "
               f"pending: {items.pending}  approved: {items.approved}")
    typer.echo(f"risk: kept (quote verified) {items.risk_kept}, "
               f"dropped (claimed without support) {items.risk_dropped}")
    typer.echo("verified items by category: " + ", ".join(f"{c.category}={c.n}" for c in cats))


if __name__ == "__main__":  # pragma: no cover
    app()
