"""PostgreSQL security page (raw HTML) -> core.pg_advisory (+ core.pg_advisory_version).

Rule based, no LLM. Structure of a real page (verified on CVE-2022-1552):

    <CVE id>                                  heading
    <short title>                             heading
    <description paragraphs>                  the "Description" has no label
    Version Information                       heading, then a table:
        Affected Version | Fixed In | Fix Published     (one row per supported major version)
    CVSS <x.y>                                then label/value lines: Overall Score, Component, Vector
    Reporting Security Vulnerabilities ...    site footer text, not part of the advisory

Text is copied verbatim (whitespace normalised). A field is filled only when it is really present;
otherwise it stays NULL and `parse_flags` says so. Older layouts that use "Label: value" lines are
still understood as a fallback.
"""

from __future__ import annotations

import json
import re
from datetime import date

from bs4 import BeautifulSoup, Comment, NavigableString, Tag
from sqlalchemy import Engine, text

from opsgraph.config import LicensePolicy
from opsgraph.logging import get_logger
from opsgraph.normalize.common import NormalizeStats
from opsgraph.normalize.cvss import cvss3_base_score

log = get_logger(__name__)

# bump when the parsing rules change: stored rows are then rebuilt automatically
PARSER_VERSION = "2"

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_FULL_VECTOR = re.compile(
    r"CVSS:3\.[01]/AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z]"
)
_SHORT_VECTOR = re.compile(
    r"^AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z]$"
)
_CVSS_HEADING = re.compile(r"^CVSS (\d\.\d)$")
_SCORE = re.compile(r"^\d{1,2}(?:\.\d)?$")
_BASE_SCORE = re.compile(r"base\s*score\D{0,40}?(\d{1,2}\.\d)", re.IGNORECASE)
_VERSION = re.compile(r"\b\d{1,3}\.\d{1,3}(?:\.\d{1,3})?\b")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

BLOCK = {"p", "div", "section", "article", "main", "header", "footer", "nav", "aside", "form",
         "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "dl", "dt", "dd", "table", "thead",
         "tbody", "tfoot", "tr", "th", "td", "caption", "pre", "blockquote", "hr", "br"}
HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}

# the advisory body ends where site boilerplate starts
_END_MARKERS = ("Reporting Security Vulnerabilities",)
_SECTION_VERSION = "Version Information"

# legacy "Label: value" layout (fallback only)
_LEGACY = {
    "affected": ("versions affected", "affected versions", "version affected"),
    "fixed": ("fixed in", "fixed versions", "versions fixed"),
    "description": ("description",),
}
_LEGACY_STOP = {lab for labs in _LEGACY.values() for lab in labs} | {
    "component", "vector", "overall score", "cvss v3 base score", "base score", "credits",
    "references", "patch", "workaround"}


def block_lines(root: Tag) -> list[tuple[str, str]]:
    """(block tag, text) per block element. Inline elements (code, a, em ...) are merged into
    the surrounding text, so `<code>REINDEX</code>,` stays `REINDEX,`."""
    lines: list[tuple[str, str]] = []
    buf: list[str] = []

    def flush(tag: str) -> None:
        txt = re.sub(r"\s+", " ", "".join(buf)).strip()
        buf.clear()
        if txt:
            lines.append((tag, txt))

    def walk(node: Tag, tag: str) -> None:
        for child in node.children:
            if isinstance(child, Comment):
                continue
            if isinstance(child, NavigableString):
                buf.append(str(child))
            elif isinstance(child, Tag):
                if child.name in ("script", "style", "noscript"):
                    continue
                if child.name in BLOCK:
                    flush(tag)
                    walk(child, child.name)
                    flush(child.name)
                else:
                    walk(child, tag)

    walk(root, root.name or "div")
    flush(root.name or "div")
    return lines


def _content_root(soup: BeautifulSoup) -> Tag:
    for finder in (lambda: soup.find(id="pgContentWrap"), lambda: soup.find("main"),
                   lambda: soup.find(id="content"), lambda: soup.body):
        node = finder()
        if node is not None:
            return node
    return soup


def _cut_at_end(lines: list[tuple[str, str]]) -> list[tuple[str, str]]:
    for i, (_, t) in enumerate(lines):
        if any(t.startswith(m) for m in _END_MARKERS):
            return lines[:i]
    return lines


def _version_table(root: Tag) -> list[dict]:
    """Rows of the table whose header has 'Affected Version' and 'Fixed In'."""
    for table in root.find_all("table"):
        rows = [[re.sub(r"\s+", " ", c.get_text(" ")).strip() for c in tr.find_all(["th", "td"])]
                for tr in table.find_all("tr")]
        rows = [r for r in rows if any(r)]
        if not rows:
            continue
        header = [c.lower() for c in rows[0]]
        if not any("affected" in h for h in header) or not any("fixed" in h for h in header):
            continue
        a = next(i for i, h in enumerate(header) if "affected" in h)
        f = next(i for i, h in enumerate(header) if "fixed" in h)
        p = next((i for i, h in enumerate(header) if "publish" in h), None)
        out = []
        for ordinal, r in enumerate(rows[1:]):
            if len(r) <= max(a, f):
                continue
            fixed = r[f] if _VERSION.fullmatch(r[f]) else None
            published = r[p] if p is not None and len(r) > p and _DATE.match(r[p]) else None
            out.append({"ordinal": ordinal, "affected_major": r[a], "fixed_in": fixed,
                        "fix_published": date.fromisoformat(published) if published else None})
        if out:
            return out
    return []


def _value_after(texts: list[str], label: str, start: int = 0, window: int = 14) -> str | None:
    for i in range(start, min(len(texts), start + window)):
        if texts[i].lower() == label and i + 1 < len(texts):
            return texts[i + 1]
    return None


def _legacy_field(texts: list[str], variants: tuple[str, ...]) -> str | None:
    def label_of(line: str) -> tuple[str, str] | None:
        low = line.lower()
        for lab in sorted(_LEGACY_STOP, key=len, reverse=True):
            if low == lab or low == lab + ":":
                return lab, ""
            if low.startswith(lab + ":"):
                return lab, line[len(lab) + 1:].strip()
        return None

    for i, line in enumerate(texts):
        hit = label_of(line)
        if not hit or hit[0] not in variants:
            continue
        parts = [hit[1]] if hit[1] else []
        for nxt in texts[i + 1:i + 40]:
            if label_of(nxt):
                break
            parts.append(nxt)
        return " ".join(parts).strip() or None
    return None


def parse_advisory(html: str, url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    root = _content_root(soup)
    for tag in root(["nav", "header", "footer"]):
        tag.decompose()
    lines = _cut_at_end(block_lines(root))
    texts = [t for _, t in lines]
    full_text = "\n".join(texts)

    m = _CVE.search(url) or _CVE.search(full_text)
    cve_id = m.group(0) if m else None

    # --- title: the CVE-id heading plus the short title that follows it ---
    title = None
    sub_idx = None
    if cve_id:
        for i, (_, t) in enumerate(lines):
            if t == cve_id:
                if i + 1 < len(lines):
                    nxt_tag, nxt = lines[i + 1]
                    headline = nxt_tag in HEADINGS or (len(nxt) <= 200 and not nxt.endswith("."))
                    if headline and nxt != _SECTION_VERSION and not _CVSS_HEADING.match(nxt):
                        title, sub_idx = f"{cve_id}: {nxt}", i + 1
                if title is None:
                    title = cve_id
                sub_idx = sub_idx if sub_idx is not None else i
                break
        if title is None:
            for line_tag, t in lines:  # layouts with "CVE-xxxx: Title" in one heading
                if line_tag in HEADINGS and cve_id in t:
                    title = t
                    break
    if title is None and soup.title and soup.title.string:
        title = soup.title.string.strip()

    # --- version table ---
    version_rows = _version_table(root)
    affected_text = fixed_text = None
    fixed_versions: list[str] = []
    if version_rows:
        affected_text = ", ".join(r["affected_major"] for r in version_rows)
        fixed_versions = [r["fixed_in"] for r in version_rows if r["fixed_in"]]
        fixed_text = ", ".join(fixed_versions) or None

    # --- description: paragraphs between the title and the version / CVSS sections ---
    description = None
    if sub_idx is not None:
        body: list[str] = []
        for t in texts[sub_idx + 1:]:
            if t == _SECTION_VERSION or _CVSS_HEADING.match(t):
                break
            body.append(t)
        description = "\n".join(body).strip() or None

    # --- CVSS block ---
    cvss_version = vector = score = component = None
    score_source = None
    for i, t in enumerate(texts):
        mm = _CVSS_HEADING.match(t)
        if mm:
            cvss_version = mm.group(1)
            raw_score = _value_after(texts, "overall score", i)
            raw_vec = _value_after(texts, "vector", i)
            component = _value_after(texts, "component", i)
            if raw_score and _SCORE.match(raw_score):
                score, score_source = float(raw_score), "page"
            if raw_vec and _SHORT_VECTOR.match(raw_vec):
                vector = f"CVSS:{cvss_version}/{raw_vec}"
            break
    if vector is None:
        fv = _FULL_VECTOR.search(full_text)
        vector = fv.group(0) if fv else None
    if score is None:
        for sc in _BASE_SCORE.finditer(full_text):
            before = full_text[max(0, sc.start(1) - 6):sc.start(1)]
            if "CVSS:" not in before and full_text[sc.end(1):sc.end(1) + 1] != "/":
                score, score_source = float(sc.group(1)), "page"
                break
    computed = cvss3_base_score(vector) if vector else None
    if score is None and computed is not None:
        score, score_source = computed, "computed"
    score_matches = None if (score_source != "page" or computed is None) else score == computed

    # --- legacy "Label: value" fallback for fields the structured layout did not give ---
    if affected_text is None:
        affected_text = _legacy_field(texts, _LEGACY["affected"])
    if fixed_text is None:
        fixed_text = _legacy_field(texts, _LEGACY["fixed"])
        if fixed_text:
            fixed_versions = list(dict.fromkeys(_VERSION.findall(fixed_text)))
    if description is None:
        description = _legacy_field(texts, _LEGACY["description"])
    if component is None:
        component = _value_after(texts, "component") or _legacy_label_value(texts, "component")

    return {
        "cve_id": cve_id, "title": title, "description": description, "component": component,
        "affected_text": affected_text, "fixed_text": fixed_text, "fixed_versions": fixed_versions,
        "cvss_version": cvss_version, "cvss_vector": vector, "cvss_score": score,
        "cvss_score_source": score_source, "version_rows": version_rows, "full_text": full_text,
        "parse_flags": {
            "title": title is not None and title != cve_id,
            "description": description is not None, "component": component is not None,
            "affected": affected_text is not None, "fixed": fixed_text is not None,
            "fixed_versions": bool(fixed_versions), "version_table": bool(version_rows),
            "cvss_vector": vector is not None, "cvss_score": score is not None,
            "cvss_score_matches_vector": score_matches,
        },
    }


def _legacy_label_value(texts: list[str], label: str) -> str | None:
    for t in texts:
        if t.lower().startswith(label + ":"):
            return t[len(label) + 1:].strip() or None
    return None


FLAG_NAMES = ("title", "description", "component", "affected", "fixed", "fixed_versions",
              "version_table", "cvss_vector", "cvss_score")


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
            raw_hash = f"{page['content_hash']}:p{PARSER_VERSION}"  # new parser -> rebuild
            try:
                with conn.begin_nested():
                    parsed = parse_advisory(page["body"], page["url"])
                    cve = parsed["cve_id"]
                    if cve is None:
                        raise ValueError("no CVE id in url or text")
                    if existing.get(cve) == raw_hash and not force:
                        stats.unchanged += 1
                        continue
                    lic = page["license"]
                    conn.execute(text("DELETE FROM core.pg_advisory WHERE cve_id = :c"), {"c": cve})
                    conn.execute(text("""
                        INSERT INTO core.pg_advisory
                          (cve_id, title, description, component, affected_text, fixed_text,
                           fixed_versions, cvss_version, cvss_vector, cvss_score,
                           cvss_score_source, full_text, parse_flags, license, publishable,
                           source_url, raw_hash)
                        VALUES
                          (:cve_id, :title, :description, :component, :affected_text, :fixed_text,
                           :fixed_versions, :cvss_version, :cvss_vector, :cvss_score,
                           :cvss_score_source, :full_text, CAST(:flags AS jsonb), :license,
                           :publishable, :source_url, :raw_hash)"""),
                                 {**{k: parsed[k] for k in (
                                     "cve_id", "title", "description", "component", "affected_text",
                                     "fixed_text", "fixed_versions", "cvss_version", "cvss_vector",
                                     "cvss_score", "cvss_score_source", "full_text")},
                                  "flags": json.dumps(parsed["parse_flags"]),
                                  "license": lic, "publishable": policy.spdx_allowed(lic),
                                  "source_url": page["source_url"], "raw_hash": raw_hash})
                    for row in parsed["version_rows"]:
                        conn.execute(text("""
                            INSERT INTO core.pg_advisory_version
                              (cve_id, ordinal, affected_major, fixed_in, fix_published)
                            VALUES (:cve, :ordinal, :affected_major, :fixed_in, :fix_published)"""),
                                     {"cve": cve, **row})
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
        mismatch = conn.execute(text(
            "SELECT count(*) FROM core.pg_advisory "
            "WHERE (parse_flags ->> 'cvss_score_matches_vector') = 'false'")).scalar_one()
        out["score_mismatch (should be 0)"] = (mismatch, total)
    return out
