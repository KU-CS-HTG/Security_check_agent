"""PostgreSQL security page (raw HTML) -> core.pg_advisory. Rule based, no LLM.

The parser is label driven and conservative: a field is filled only when its label (or, for CVSS,
a recognisable vector) is present; everything else stays NULL and is reported in `parse_flags`.
Text values are copied verbatim from the page, never rewritten.
"""

from __future__ import annotations

import json
import re

from bs4 import BeautifulSoup
from sqlalchemy import Engine, text

from opsgraph.config import LicensePolicy
from opsgraph.logging import get_logger
from opsgraph.normalize.common import NormalizeStats
from opsgraph.normalize.cvss import cvss3_base_score

log = get_logger(__name__)

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_VECTOR = re.compile(
    r"CVSS:3\.[01]/AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z]"
)
_SCORE = re.compile(r"base\s*score\D{0,40}?(\d{1,2}\.\d)", re.IGNORECASE)
_VERSION = re.compile(r"\b\d{1,2}\.\d{1,2}(?:\.\d{1,2})?\b")

LABELS = {
    "affected": ("versions affected", "affected versions", "version affected", "affected"),
    "fixed": ("fixed in", "fixed versions", "versions fixed", "fixed"),
    "description": ("description",),
    "component": ("component",),
}
# lines that end a multi-line value (all field labels plus common neighbours on the page)
_STOP = {lab for labs in LABELS.values() for lab in labs} | {
    "cvss v3 base score", "cvss base score", "base score", "vector string", "cvss", "severity",
    "attack vector", "attack complexity", "privileges required", "user interaction", "scope",
    "confidentiality", "integrity", "availability", "credits", "references", "patch", "workaround",
}


def _content_root(soup: BeautifulSoup):
    for finder in (lambda: soup.find(id="pgContentWrap"), lambda: soup.find("main"),
                   lambda: soup.find(id="content"), lambda: soup.body):
        node = finder()
        if node is not None:
            return node
    return soup


def page_lines(html: str) -> tuple[BeautifulSoup, list[str]]:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "nav", "header", "footer"]):
        tag.decompose()
    root = _content_root(soup)
    lines = [re.sub(r"\s+", " ", ln).strip() for ln in root.get_text("\n").splitlines()]
    return soup, [ln for ln in lines if ln]


def _label_of(line: str) -> tuple[str, str] | None:
    """('versions affected', 'rest of the line') when the line starts with a known label."""
    low = line.lower()
    for lab in sorted(_STOP, key=len, reverse=True):
        if low == lab or low == lab + ":":
            return lab, ""
        if low.startswith(lab + ":"):
            return lab, line[len(lab) + 1:].strip()
    return None


def _field(lines: list[str], variants: tuple[str, ...]) -> str | None:
    for i, line in enumerate(lines):
        hit = _label_of(line)
        if not hit or hit[0] not in variants:
            continue
        parts = [hit[1]] if hit[1] else []
        for nxt in lines[i + 1:i + 13]:
            if _label_of(nxt):
                break
            parts.append(nxt)
        value = " ".join(parts).strip()
        return value or None
    return None


def parse_advisory(html: str, url: str) -> dict:
    soup, lines = page_lines(html)
    full_text = "\n".join(lines)
    m = _CVE.search(url) or _CVE.search(full_text)
    cve_id = m.group(0) if m else None

    title = None
    for h in soup.find_all(["h1", "h2", "h3"]):
        t = re.sub(r"\s+", " ", h.get_text(" ")).strip()
        if cve_id and cve_id in t:
            title = t
            break
    if title is None and soup.title and soup.title.string:
        title = soup.title.string.strip()

    affected = _field(lines, LABELS["affected"])
    fixed = _field(lines, LABELS["fixed"])
    description = _field(lines, LABELS["description"])
    component = _field(lines, LABELS["component"])
    fixed_versions = list(dict.fromkeys(_VERSION.findall(fixed))) if fixed else []

    vec = _VECTOR.search(full_text)
    vector = vec.group(0) if vec else None
    score, score_source = None, None
    for sc in _SCORE.finditer(full_text):
        # never mistake the "3.1" of "CVSS:3.1/..." for a score
        before = full_text[max(0, sc.start(1) - 6):sc.start(1)]
        after = full_text[sc.end(1):sc.end(1) + 1]
        if "CVSS:" not in before and after != "/" and 0.0 <= float(sc.group(1)) <= 10.0:
            score, score_source = float(sc.group(1)), "page"
            break
    if score is None and vector:
        score = cvss3_base_score(vector)
        score_source = "computed" if score is not None else None

    return {
        "cve_id": cve_id, "title": title, "description": description, "component": component,
        "affected_text": affected, "fixed_text": fixed, "fixed_versions": fixed_versions,
        "cvss_vector": vector, "cvss_score": score, "cvss_score_source": score_source,
        "full_text": full_text,
        "parse_flags": {
            "title": title is not None, "description": description is not None,
            "component": component is not None, "affected": affected is not None,
            "fixed": fixed is not None, "fixed_versions": bool(fixed_versions),
            "cvss_vector": vector is not None, "cvss_score": score is not None,
        },
    }


FLAG_NAMES = ("title", "description", "component", "affected", "fixed", "fixed_versions",
              "cvss_vector", "cvss_score")


def normalize_pg_advisories(engine: Engine, policy: LicensePolicy, *, force: bool = False,
                            limit: int | None = None) -> NormalizeStats:
    stats = NormalizeStats()
    with engine.begin() as conn:
        pages = conn.execute(text("""
            SELECT url, body, content_hash, license, source_url FROM raw.web_page
            WHERE source_id = 'postgresql' AND url ~ '/support/security/CVE-[0-9]{4}-[0-9]+/?$'
            ORDER BY url""")).mappings().all()
        existing = dict(conn.execute(text("SELECT cve_id, raw_hash FROM core.pg_advisory")).all())
        for page in pages:
            if limit and stats.processed >= limit:
                break
            stats.processed += 1
            try:
                with conn.begin_nested():
                    parsed = parse_advisory(page["body"], page["url"])
                    cve = parsed["cve_id"]
                    if cve is None:
                        raise ValueError("no CVE id in url or text")
                    if existing.get(cve) == page["content_hash"] and not force:
                        stats.unchanged += 1
                        continue
                    lic = page["license"]
                    conn.execute(text("DELETE FROM core.pg_advisory WHERE cve_id = :c"), {"c": cve})
                    conn.execute(text("""
                        INSERT INTO core.pg_advisory
                          (cve_id, title, description, component, affected_text, fixed_text,
                           fixed_versions, cvss_vector, cvss_score, cvss_score_source, full_text,
                           parse_flags, license, publishable, source_url, raw_hash)
                        VALUES
                          (:cve_id, :title, :description, :component, :affected_text, :fixed_text,
                           :fixed_versions, :cvss_vector, :cvss_score, :cvss_score_source,
                           :full_text, CAST(:flags AS jsonb), :license, :publishable,
                           :source_url, :raw_hash)"""),
                                 {**{k: parsed[k] for k in (
                                     "cve_id", "title", "description", "component", "affected_text",
                                     "fixed_text", "fixed_versions", "cvss_vector", "cvss_score",
                                     "cvss_score_source", "full_text")},
                                  "flags": json.dumps(parsed["parse_flags"]),
                                  "license": lic, "publishable": policy.spdx_allowed(lic),
                                  "source_url": page["source_url"],
                                  "raw_hash": page["content_hash"]})
                    stats.updated += cve in existing
                    stats.inserted += cve not in existing
            except Exception as e:
                stats.errors += 1
                stats.notes.append(f"{page['url']}: {type(e).__name__}: {e}")
                log.warning("normalize_pg_failed", url=page["url"], error=str(e))
    return stats


def parse_coverage(engine: Engine) -> dict[str, tuple[int, int]]:
    """Field -> (pages where it was found, pages total): the parser's health on real data."""
    with engine.connect() as conn:
        total = conn.execute(text("SELECT count(*) FROM core.pg_advisory")).scalar_one()
        out = {}
        for name in FLAG_NAMES:
            found = conn.execute(
                text("SELECT count(*) FROM core.pg_advisory WHERE (parse_flags ->> :f)::boolean"),
                {"f": name}).scalar_one()
            out[name] = (found, total)
    return out

