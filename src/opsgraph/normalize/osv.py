"""OSV record -> normalized core tables. Rule based, no LLM.

raw.osv_vulnerability keeps one row per (osv_id, export_ecosystem); core.vulnerability has one
row per osv_id (the most recently modified raw row is canonical, all export ecosystems are
listed). Rebuilding is skipped when the hash of the contributing raw rows did not change.
"""

from __future__ import annotations

from datetime import datetime
from itertools import groupby

from sqlalchemy import Engine, text
from sqlalchemy.engine import Connection

from opsgraph.collectors.osv import parse_ts
from opsgraph.config import LicensePolicy
from opsgraph.licensing import UNKNOWN
from opsgraph.logging import get_logger
from opsgraph.normalize.common import NormalizeStats
from opsgraph.normalize.cvss import cvss3_base_score, severity_label
from opsgraph.storage.repository import canonical_hash

log = get_logger(__name__)

_DB_SEVERITY = {"LOW": "LOW", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "IMPORTANT": "HIGH",
                "HIGH": "HIGH", "CRITICAL": "CRITICAL"}


def range_intervals(events: list[dict]) -> list[dict]:
    """OSV range events -> intervals. [{introduced:0},{fixed:1.2},{introduced:2.0},{fixed:2.3}]
    becomes two intervals; an interval that is never closed stays open-ended."""
    out: list[dict] = []
    cur: dict | None = None
    for ev in events:
        if "introduced" in ev:
            if cur is not None:
                out.append(cur)
            cur = {"introduced": ev["introduced"]}
            continue
        for key, col in (("fixed", "fixed"), ("last_affected", "last_affected"),
                         ("limit", "limit_")):
            if key in ev:
                cur = cur if cur is not None else {"introduced": None}
                cur[col] = ev[key]
                out.append(cur)
                cur = None
                break
    if cur is not None:
        out.append(cur)
    return out


def pick_severity(rec: dict) -> dict:
    """CVSS v3 (score computed from the vector) > other CVSS (vector only) > database label.
    Never invents a value: a record without severity information gets NULLs."""
    entries = rec.get("severity") or []
    v3 = next((s for s in entries if str(s.get("score", "")).startswith("CVSS:3")), None)
    if v3:
        score = cvss3_base_score(v3["score"])
        if score is not None:
            return {"severity_vector": v3["score"], "severity_score": score,
                    "severity_label": severity_label(score), "severity_source": "cvss3_computed"}
    other = next((s for s in entries if s.get("score")), None)
    label = _DB_SEVERITY.get(str((rec.get("database_specific") or {}).get("severity", "")).upper())
    if other:
        return {"severity_vector": other["score"], "severity_score": None,
                "severity_label": label, "severity_source": "cvss_vector_only"}
    if label:
        return {"severity_vector": None, "severity_score": None, "severity_label": label,
                "severity_source": "database_specific"}
    return {"severity_vector": None, "severity_score": None, "severity_label": None,
            "severity_source": None}


def _ts(value: str | None) -> datetime | None:
    return parse_ts(value) if value else None


def normalize_record(rec: dict) -> dict:
    affected = []
    for i, aff in enumerate(rec.get("affected") or []):
        pkg = aff.get("package") or {}
        eco = pkg.get("ecosystem")
        ranges = []
        for rng in aff.get("ranges") or []:
            for iv in range_intervals(rng.get("events") or []):
                ranges.append({"range_type": rng.get("type"), "repo": rng.get("repo"),
                               "introduced": iv.get("introduced"), "fixed": iv.get("fixed"),
                               "last_affected": iv.get("last_affected"),
                               "limit_": iv.get("limit_")})
        affected.append({"ordinal": i, "ecosystem": eco,
                         "ecosystem_base": eco.split(":")[0] if eco else None,
                         "package": pkg.get("name"), "purl": pkg.get("purl"),
                         "versions": [str(v) for v in aff.get("versions") or []],
                         "ranges": ranges})
    return {
        "osv_id": rec["id"],
        "aliases": sorted(set(rec.get("aliases") or [])),
        "summary": rec.get("summary"),
        "details": rec.get("details"),
        **pick_severity(rec),
        "published": _ts(rec.get("published")),
        "modified": _ts(rec["modified"]),
        "withdrawn": _ts(rec.get("withdrawn")),
        "affected": affected,
        "references": [{"ref_type": r.get("type"), "url": r["url"]}
                       for r in rec.get("references") or [] if r.get("url")],
    }


def _insert(conn: Connection, norm: dict, *, export_ecosystems: list[str], products: list[str],
            license_: str, publishable: bool, source_url: str, raw_hash: str) -> None:
    conn.execute(text("""
        INSERT INTO core.vulnerability
          (osv_id, aliases, summary, details, severity_vector, severity_score, severity_label,
           severity_source, published, modified, withdrawn, export_ecosystems, matched_products,
           license, publishable, source_url, raw_hash)
        VALUES
          (:osv_id, :aliases, :summary, :details, :severity_vector, :severity_score,
           :severity_label, :severity_source, :published, :modified, :withdrawn,
           :export_ecosystems, :matched_products, :license, :publishable, :source_url, :raw_hash)
    """), {**{k: norm[k] for k in ("osv_id", "aliases", "summary", "details", "severity_vector",
                                   "severity_score", "severity_label", "severity_source",
                                   "published", "modified", "withdrawn")},
           "export_ecosystems": export_ecosystems, "matched_products": products,
           "license": license_, "publishable": publishable, "source_url": source_url,
           "raw_hash": raw_hash})
    for aff in norm["affected"]:
        aid = conn.execute(text("""
            INSERT INTO core.affected_package
              (osv_id, ordinal, ecosystem, ecosystem_base, package, purl, versions)
            VALUES (:osv_id, :ordinal, :ecosystem, :ecosystem_base, :package, :purl, :versions)
            RETURNING id"""), {"osv_id": norm["osv_id"], **{k: aff[k] for k in (
                "ordinal", "ecosystem", "ecosystem_base", "package", "purl", "versions")}}
        ).scalar_one()
        for rng in aff["ranges"]:
            conn.execute(text("""
                INSERT INTO core.version_range
                  (affected_id, range_type, repo, introduced, fixed, last_affected, limit_)
                VALUES (:aid, :range_type, :repo, :introduced, :fixed, :last_affected, :limit_)"""),
                         {"aid": aid, **rng})
    for ref in norm["references"]:
        conn.execute(text("INSERT INTO core.vuln_reference (osv_id, ref_type, url) "
                          "VALUES (:osv_id, :ref_type, :url)"), {"osv_id": norm["osv_id"], **ref})


def normalize_osv(engine: Engine, policy: LicensePolicy, *, force: bool = False,
                  limit: int | None = None) -> NormalizeStats:
    stats = NormalizeStats()
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT osv_id, export_ecosystem, modified, license, content_hash, source_url,
                   matched_products, payload
            FROM raw.osv_vulnerability ORDER BY osv_id, modified DESC, export_ecosystem
        """)).mappings().all()
        existing = dict(conn.execute(text("SELECT osv_id, raw_hash FROM core.vulnerability")).all())
        for osv_id, grp in groupby(rows, key=lambda r: r["osv_id"]):
            group = list(grp)
            if limit and stats.processed >= limit:
                break
            stats.processed += 1
            canonical = group[0]
            raw_hash = canonical_hash(sorted((r["export_ecosystem"], r["content_hash"])
                                             for r in group))
            if osv_id in existing and existing[osv_id] == raw_hash and not force:
                stats.unchanged += 1
                continue
            try:
                with conn.begin_nested():
                    norm = normalize_record(canonical["payload"])
                    conn.execute(text("DELETE FROM core.vulnerability WHERE osv_id = :i"),
                                 {"i": osv_id})  # children go with it (ON DELETE CASCADE)
                    lic = canonical["license"]
                    _insert(
                        conn, norm,
                        export_ecosystems=sorted({r["export_ecosystem"] for r in group}),
                        products=sorted({p for r in group for p in r["matched_products"]}),
                        license_=lic,
                        publishable=lic != UNKNOWN and policy.spdx_allowed(lic),
                        source_url=canonical["source_url"], raw_hash=raw_hash)
                stats.updated += osv_id in existing
                stats.inserted += osv_id not in existing
            except Exception as e:  # one bad record must not stop the run
                stats.errors += 1
                stats.notes.append(f"{osv_id}: {type(e).__name__}: {e}")
                log.warning("normalize_osv_failed", osv_id=osv_id, error=str(e))
    return stats

