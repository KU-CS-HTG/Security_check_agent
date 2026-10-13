"""CVSS v3.x base score from a vector string (FIRST CVSS v3.1 specification, section 7)."""

from __future__ import annotations

import math
import re

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_VECTOR = re.compile(r"^CVSS:3\.[01]/(?:[A-Z]{1,3}:[A-Z]/?)+$")


def roundup(x: float) -> float:
    """CVSS v3.1 Roundup: smallest number, to one decimal, that is >= x (float-safe)."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Base score, or None when the vector is not a complete, valid CVSS v3 base vector."""
    if not _VECTOR.match(vector or ""):
        return None
    m = dict(part.split(":") for part in vector.split("/")[1:])
    try:
        scope_changed = m["S"] == "C"
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = (8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]]
                          * _PR["C" if scope_changed else "U"][m["PR"]] * _W["UI"][m["UI"]])
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return roundup(min(raw, 10.0))


def severity_label(score: float | None) -> str | None:
    if score is None:
        return None
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
