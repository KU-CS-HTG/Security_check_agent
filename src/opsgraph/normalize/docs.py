"""Documentation page (raw HTML) -> core.document + core.clause. Rule based, no LLM.

A clause is a heading plus the text up to the next heading, keeping the heading path
("Client Authentication > The pg_hba.conf File > Examples"). Text is the page's own text with
whitespace normalised; code/config blocks (<pre>) keep their line breaks. Overlong clauses are split
at block boundaries (never inside a code block or paragraph).

Clause identity is (document, key) where key is the heading anchor (or heading path), so rebuilding
a page keeps the id of every unchanged clause and whatever was attached to it later (extractions).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Tag
from sqlalchemy import Engine, text

from opsgraph.config import LicensePolicy
from opsgraph.logging import get_logger
from opsgraph.storage.repository import canonical_hash

log = get_logger(__name__)

# bump when parsing/splitting rules change: stored documents are then rebuilt automatically
PARSER_VERSION = "3"
MAX_CLAUSE_CHARS = 6000
# a section longer than this that contains definition-list terms is split per term (one clause
# per documented setting), so a clause maps to one checkable thing and one citable anchor
TERM_SPLIT_CHARS = 3500
MAX_TERM_PATH_CHARS = 120
SOURCE_LABEL = "postgresql-docs"

# From the PostgreSQL licence page: the notice must stay with copies of the documentation.
STANDARD_NOTICE = ("Portions Copyright © 1996-2026, The PostgreSQL Global Development Group; "
                   "Portions Copyright © 1994, The Regents of the University of California")

_NOTICE = re.compile(
    r"(?:Copyright\s*)?©\s*1996\s*[–—\-]\s*\d{4}\s+The PostgreSQL Global Development Group"
)
_VERSION_IN_URL = re.compile(r"/docs/([^/]+)/")
HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
ADMONITIONS = {"note", "tip", "warning", "caution", "important"}
SKIP_CLASSES = {"toc", "navheader", "navfooter", "navbar"}
SKIP_IDS = {"docFooter", "docComments", "pgFooter"}
SKIP_TAGS = {"script", "style", "noscript", "nav", "header", "footer", "form"}
BLOCK_CHILDREN = {"p", "ul", "ol", "dl", "pre", "table", "div", "blockquote", *HEADINGS}


@dataclass
class Block:
    kind: str                # h | term | p | pre | row
    text: str
    level: int = 0           # headings only
    anchor: str | None = None


@dataclass
class ClauseDraft:
    key: str
    ordinal: int
    heading_path: list[str]
    text: str
    anchor: str | None


@dataclass
class ParsedDoc:
    title: str | None
    copyright_notice: str
    notice_from_page: bool
    clauses: list[ClauseDraft] = field(default_factory=list)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


_SECTION_CLASS_PREFIXES = ("sect", "chapter", "section", "appendix", "preface", "refsect", "part")


def _anchor(h: Tag) -> str | None:
    """Anchor id of a heading: its own id, an <a id> inside it, or the id of the section div
    that wraps it (DocBook nests a heading in anonymous/titlepage divs inside div.sect1)."""
    own = h.get("id")
    if own:
        return str(own)
    inner = h.find("a", attrs={"id": True}) or h.find("a", attrs={"name": True})
    if inner:
        return str(inner.get("id") or inner.get("name"))
    node = h.parent
    while isinstance(node, Tag) and node.name == "div":
        cls = _classes(node)
        node_id = node.get("id")
        if not cls or "titlepage" in cls:             # wrapper divs of a DocBook title
            if node_id and node_id != "docContent":
                return str(node_id)
            node = node.parent
            continue
        if node_id and node_id != "docContent" and any(c.startswith(_SECTION_CLASS_PREFIXES)
                                                       for c in cls):
            return str(node_id)
        break
    return None


def _text(tag: Tag) -> str:
    """Text of an element as one line. Inline markup (<code>, <a>, ...) is merged without adding
    spaces, so `<code>trust</code>,` stays `trust,` and quotes can be matched against the source."""
    for br in tag.find_all("br"):
        br.replace_with("\n")
    return _norm(tag.get_text())


def _classes(tag: Tag) -> set[str]:
    return set(tag.get("class") or [])


def _has_block_child(tag: Tag) -> bool:
    return any(isinstance(c, Tag) and c.name in BLOCK_CHILDREN for c in tag.children)


def iter_blocks(root: Tag):
    def rec(node: Tag, in_admonition: bool):
        for child in node.children:
            if not isinstance(child, Tag):
                continue
            name, classes = child.name, _classes(child)
            if name in SKIP_TAGS or classes & SKIP_CLASSES or child.get("id") in SKIP_IDS:
                continue
            if name in HEADINGS:
                txt = _text(child)
                if not txt:
                    continue
                if in_admonition:      # "Note", "Warning" ... are labels, not sections
                    yield Block("p", txt)
                else:
                    yield Block("h", txt, level=int(name[1]), anchor=_anchor(child))
            elif name == "pre":
                raw = child.get_text().strip("\n")
                if raw.strip():
                    yield Block("pre", raw)
            elif name == "table":
                for tr in child.find_all("tr"):
                    cells = [_text(c) for c in tr.find_all(["th", "td"])]
                    if any(cells):
                        yield Block("row", " | ".join(cells))
            elif name == "dt":
                txt = _text(child)
                if txt:
                    yield Block("term", txt, anchor=_anchor(child))
            elif name in ("p", "caption"):
                txt = _text(child)
                if txt:
                    yield Block("p", txt)
            elif name in ("li", "dd"):
                if _has_block_child(child):
                    inner = list(rec(child, in_admonition))
                    if name == "li" and inner and inner[0].kind == "p":
                        inner[0].text = "- " + inner[0].text
                    yield from inner
                else:
                    txt = _text(child)
                    if txt:
                        yield Block("p", ("- " + txt) if name == "li" else txt)
            elif name in ("div", "section", "article", "blockquote", "ul", "ol", "dl", "tbody",
                          "thead", "main", "span"):
                adm = in_admonition or bool(classes & ADMONITIONS)
                if name in ("div", "span") and not _has_block_child(child):
                    txt = _text(child)
                    if txt and not child.find(["table", "pre"]):
                        yield Block("p", txt)
                        continue
                yield from rec(child, adm)

    yield from rec(root, False)


def _split(blocks: list[Block], max_chars: int) -> list[list[Block]]:
    parts: list[list[Block]] = []
    cur: list[Block] = []
    size = 0
    for b in blocks:
        n = len(b.text)
        if cur and size + n > max_chars:
            parts.append(cur)
            cur, size = [], 0
        cur.append(b)
        size += n
    if cur:
        parts.append(cur)
    return parts


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "term"


def _term_units(blocks: list[Block]) -> tuple[list[Block], list[list[Block]]]:
    """(blocks before the first term, [term + its following blocks, ...])"""
    lead: list[Block] = []
    units: list[list[Block]] = []
    for b in blocks:
        if b.kind == "term":
            # consecutive terms share the description that follows them (<dt>a</dt><dt>b</dt><dd>)
            if units and all(x.kind == "term" for x in units[-1]):
                units[-1].append(b)
            else:
                units.append([b])
        elif units:
            units[-1].append(b)
        else:
            lead.append(b)
    return lead, units


def _expand(path: list[str], anchor: str | None, blocks: list[Block], max_chars: int):
    """Yield (key, heading_path, anchor, blocks) for one heading's content."""
    base = anchor or "/".join(path) or "intro"
    total = sum(len(b.text) for b in blocks)
    lead, units = _term_units(blocks)
    if total > TERM_SPLIT_CHARS and len(units) >= 2:
        if lead:
            yield from _size_parts(base, path, anchor, lead, max_chars)
        for unit in units:
            term = unit[0]
            terms = " ".join(b.text for b in unit if b.kind == "term")
            tpath = [*path, terms[:MAX_TERM_PATH_CHARS]]
            tkey = term.anchor or f"{base}/{_slug(term.text)}"
            yield from _size_parts(tkey, tpath, term.anchor or anchor, unit, max_chars)
    else:
        yield from _size_parts(base, path, anchor, blocks, max_chars)


def _size_parts(key: str, path: list[str], anchor: str | None, blocks: list[Block],
                max_chars: int):
    parts = _split(blocks, max_chars)
    for i, part in enumerate(parts):
        yield (key if len(parts) == 1 else f"{key}#p{i + 1}"), path, anchor, part


def parse_doc(html: str, url: str, *, max_chars: int = MAX_CLAUSE_CHARS) -> ParsedDoc:
    soup = BeautifulSoup(html, "html.parser")
    notice_match = _NOTICE.search(soup.get_text(" "))
    notice = _norm(notice_match.group(0)) if notice_match else STANDARD_NOTICE
    for a in soup.select("a.id_link, a.permalink"):
        a.decompose()
    root = soup.find(id="docContent") or soup.find("main") or soup.find(id="pgContentWrap") \
        or soup.body or soup

    drafts: list[tuple[list[str], str | None, list[Block]]] = []
    stack: list[Block] = []
    cur: tuple[list[str], str | None, list[Block]] | None = None
    title: str | None = None
    for b in iter_blocks(root):
        # page footer lines that are not documentation text
        if b.kind != "h" and (_NOTICE.search(b.text) or b.text.startswith("Submit correction")):
            continue
        if b.kind == "h":
            title = title or b.text
            while stack and stack[-1].level >= b.level:
                stack.pop()
            stack.append(b)
            cur = ([h.text for h in stack], b.anchor, [])
            drafts.append(cur)
        else:
            if cur is None:
                cur = ([], None, [])
                drafts.append(cur)
            cur[2].append(b)

    clauses: list[ClauseDraft] = []
    used: dict[str, int] = {}
    for path, anchor, blocks in drafts:
        if not blocks:
            continue
        for key, cpath, canchor, part in _expand(path, anchor, blocks, max_chars):
            used[key] = used.get(key, 0) + 1
            if used[key] > 1:
                key = f"{key}~{used[key]}"
            clauses.append(ClauseDraft(
                key=key, ordinal=len(clauses), heading_path=cpath,
                text="\n".join(b.text for b in part), anchor=canchor))
    return ParsedDoc(title=title, copyright_notice=notice,
                     notice_from_page=notice_match is not None, clauses=clauses)


@dataclass
class DocsStats:
    documents_inserted: int = 0
    documents_updated: int = 0
    documents_unchanged: int = 0
    documents_removed: int = 0
    clauses_inserted: int = 0
    clauses_updated: int = 0
    clauses_unchanged: int = 0
    clauses_deleted: int = 0
    errors: int = 0
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def _doc_version(url: str) -> str | None:
    m = _VERSION_IN_URL.search(url)
    return m.group(1) if m else None


def normalize_docs(engine: Engine, policy: LicensePolicy, *, force: bool = False,
                   limit: int | None = None, keep_urls: set[str] | None = None) -> DocsStats:
    """keep_urls: the pages the corpus config currently lists. Documents of this source that are
    no longer listed are removed from core (their raw pages stay untouched)."""
    stats = DocsStats()
    with engine.begin() as conn:
        if keep_urls is not None:
            stale = [r.url for r in conn.execute(
                text("SELECT url FROM core.document WHERE source_id = :s"), {"s": SOURCE_LABEL})
                if r.url not in keep_urls]
            for url in stale:
                conn.execute(text("DELETE FROM core.document WHERE url = :u"), {"u": url})
                stats.documents_removed += 1
                stats.notes.append(f"removed (not in corpus config): {url}")
        pages = conn.execute(text("""
            SELECT url, body, content_hash, license, collected_at FROM raw.web_page
            WHERE source_id = :s ORDER BY url"""), {"s": SOURCE_LABEL}).mappings().all()
        if keep_urls is not None:
            pages = [p for p in pages if p["url"] in keep_urls]
        done = 0
        for page in pages:
            if limit and done >= limit:
                break
            done += 1
            raw_hash = f"{page['content_hash']}:p{PARSER_VERSION}"
            try:
                with conn.begin_nested():
                    _sync_document(conn, page, raw_hash, policy, force, stats)
            except Exception as e:
                stats.errors += 1
                stats.notes.append(f"{page['url']}: {type(e).__name__}: {e}")
                log.warning("normalize_docs_failed", url=page["url"], error=str(e))
    return stats


def _sync_document(conn, page, raw_hash: str, policy: LicensePolicy, force: bool,
                   stats: DocsStats) -> None:
    current = conn.execute(text("SELECT id, raw_hash FROM core.document WHERE url = :u"),
                           {"u": page["url"]}).first()
    if current and current.raw_hash == raw_hash and not force:
        stats.documents_unchanged += 1
        return
    parsed = parse_doc(page["body"], page["url"])
    if not parsed.clauses:
        stats.notes.append(f"{page['url']}: no clauses found (page layout?)")
    lic = page["license"]
    doc_id = conn.execute(text("""
        INSERT INTO core.document
          (url, source_id, title, version, format, license, copyright_notice, publishable,
           raw_hash, fetched_at)
        VALUES (:url, :source, :title, :version, 'html', :license, :notice, :publishable,
                :raw_hash, :fetched)
        ON CONFLICT (url) DO UPDATE SET title = EXCLUDED.title, version = EXCLUDED.version,
          license = EXCLUDED.license, copyright_notice = EXCLUDED.copyright_notice,
          publishable = EXCLUDED.publishable, raw_hash = EXCLUDED.raw_hash,
          fetched_at = EXCLUDED.fetched_at, parsed_at = now()
        RETURNING id"""), {
        "url": page["url"], "source": SOURCE_LABEL, "title": parsed.title,
        "version": _doc_version(page["url"]), "license": lic, "notice": parsed.copyright_notice,
        "publishable": policy.spdx_allowed(lic), "raw_hash": raw_hash,
        "fetched": page["collected_at"]}).scalar_one()
    stats.documents_updated += bool(current)
    stats.documents_inserted += not current

    existing = {r.key: (r.id, r.text_hash) for r in conn.execute(
        text("SELECT id, key, text_hash FROM core.clause WHERE document_id = :d"), {"d": doc_id})}
    seen = set()
    for c in parsed.clauses:
        seen.add(c.key)
        digest = canonical_hash(c.text)
        src = page["url"] + (f"#{c.anchor}" if c.anchor else "")
        params = {"d": doc_id, "key": c.key, "ord": c.ordinal, "path": c.heading_path,
                  "text": c.text, "hash": digest, "src": src}
        if c.key not in existing:
            conn.execute(text("""
                INSERT INTO core.clause (document_id, key, ordinal, heading_path, text, text_hash,
                                         source_url)
                VALUES (:d, :key, :ord, :path, :text, :hash, :src)"""), params)
            stats.clauses_inserted += 1
        elif existing[c.key][1] != digest:
            conn.execute(text("""
                UPDATE core.clause SET ordinal = :ord, heading_path = :path, text = :text,
                  text_hash = :hash, source_url = :src WHERE document_id = :d AND key = :key"""),
                         params)
            stats.clauses_updated += 1
        else:  # same text: keep the row (and its id); only position/path may have moved
            conn.execute(text("""
                UPDATE core.clause SET ordinal = :ord, heading_path = :path, source_url = :src
                WHERE document_id = :d AND key = :key"""), params)
            stats.clauses_unchanged += 1
    for key in existing.keys() - seen:
        conn.execute(text("DELETE FROM core.clause WHERE document_id = :d AND key = :k"),
                     {"d": doc_id, "k": key})
        stats.clauses_deleted += 1


def doc_report(engine: Engine) -> list[dict]:
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT d.url, d.title, count(c.id) AS clauses,
                   coalesce(sum(length(c.text)), 0) AS chars,
                   coalesce(max(length(c.text)), 0) AS longest
            FROM core.document d LEFT JOIN core.clause c ON c.document_id = d.id
            GROUP BY d.id ORDER BY d.url""")).mappings().all()
    return [dict(r) for r in rows]

