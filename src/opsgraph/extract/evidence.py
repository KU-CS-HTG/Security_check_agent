"""Verify that a quote produced by the LLM really occurs in the source clause.

This is the guard against hallucination: an extracted item is trusted only if the text it cites
is in the clause. Matching ignores differences that do not change the wording: whitespace,
invisible characters (zero-width space, soft hyphen, ...), typographic quotes and dashes. A
second, looser level ignores whitespace altogether (covers words glued together by invisible
characters in the source).
"""

from __future__ import annotations

import re
import unicodedata

MIN_QUOTE_CHARS = 20      # shorter quotes prove nothing
MAX_QUOTE_CHARS = 600
MIN_SEGMENT_CHARS = 12    # pieces of a quote that uses "..." to skip text

_QUOTES = str.maketrans({
    "“": '"', "”": '"', "„": '"', "‟": '"', "«": '"', "»": '"',
    "‘": "'", "’": "'", "‚": "'", "‛": "'", "′": "'",
    "–": "-", "—": "-", "−": "-", "‐": "-", "‑": "-",
})
_ELLIPSIS = re.compile(r"\.{3,}|…")
_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Canonical form used for comparing quotes with the clause text."""
    text = unicodedata.normalize("NFKC", text)  # NBSP -> space, ligatures, full-width forms
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")  # zero-width, soft hyphen
    return _WS.sub(" ", text.translate(_QUOTES)).strip()


def _squash(text: str) -> str:
    return _WS.sub("", text)


def _in_order(haystack: str, segments: list[str]) -> bool:
    pos = 0
    for seg in segments:
        found = haystack.find(seg, pos)
        if found < 0:
            return False
        pos = found + len(seg)
    return True


def match_quote(clause_text: str, quote: str) -> str | None:
    """'exact' (after normalisation), 'loose' (ignoring whitespace) or None when not found.

    A quote may use "..." to skip text; every remaining piece must appear, in order."""
    nq = normalize(quote)
    if len(nq) < MIN_QUOTE_CHARS or len(nq) > MAX_QUOTE_CHARS:
        return None
    nt = normalize(clause_text)
    segments = [s.strip() for s in _ELLIPSIS.split(nq) if s.strip()]
    if len(segments) > 1:
        if any(len(s) < MIN_SEGMENT_CHARS for s in segments):
            return None
        if _in_order(nt, segments):
            return "exact"
        if _in_order(_squash(nt), [_squash(s) for s in segments]):
            return "loose"
        return None
    if nq in nt:
        return "exact"
    if _squash(nq) in _squash(nt):
        return "loose"
    return None


def term_in_text(term: str, *texts: str) -> bool:
    """Is `term` (a setting or file name the LLM says the item is about) present in the source?"""
    needle = _squash(normalize(term)).lower()
    return bool(needle) and any(needle in _squash(normalize(t)).lower() for t in texts)
