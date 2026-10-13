"""Prompt for check-item extraction. Bump PROMPT_VERSION whenever the wording changes: results are
stored per (clause text, model, prompt version) and are redone when any of them changes."""

from __future__ import annotations

import json

from opsgraph.extract.schema import CATEGORIES

PROMPT_VERSION = "1"

EXAMPLE_CLAUSE = (
    "example_timeout (integer)\n"
    "Sets how long the server waits for a client to finish authentication. A connection that has "
    "not authenticated within this time is closed. The default is one minute. Setting it to zero "
    "disables the check, which lets an unauthenticated client hold a connection slot indefinitely."
)
_EXAMPLE_ANSWER = {"items": [{
    "title": "Authentication timeout is not disabled",
    "category": "authentication",
    "target": "example_timeout",
    "check_method": "",
    "recommended_value": "a non-zero value (default is one minute)",
    "remediation": "Do not set the parameter to zero.",
    "risk_level": "not_stated",
    "evidence_quote": ("Setting it to zero disables the check, which lets an unauthenticated "
                       "client hold a connection slot indefinitely."),
    "remediation_quote": "",
}]}

SYSTEM = f"""You extract security and operations check items from PostgreSQL documentation.
You receive ONE clause of the documentation. Answer with JSON only.

Rules:
1. Output an item only if the clause describes a setting, file, privilege, role or practice that a
   database administrator should verify or configure for security or reliable operation, AND the
   clause itself says what it does, what is recommended, or what the risk is.
2. Use ONLY information stated in the clause. Never add recommendations, values, risks or commands
   from your own knowledge. Leave a field as an empty string when the clause does not say.
3. evidence_quote must be copied EXACTLY, character for character, from the clause: one or two
   consecutive sentences that support the item. Never paraphrase inside a quote. If you cannot quote
   supporting text, do not output the item.
4. remediation_quote: an exact copy of the sentence that supports the remediation field; "" if there
   is no remediation.
5. risk_level: "high", "medium" or "low" only if the clause itself states or clearly describes the
   severity (for example it allows privilege escalation or data loss); otherwise "not_stated".
6. One clause may yield several items (one per setting) or none. If nothing qualifies, answer
   {{"items": []}}.
7. title: a short English phrase naming what to check (for example "Connection logging is
   enabled"). target: the setting, file or object concerned, as written in the clause.
8. category must be one of: {", ".join(CATEGORIES)}.

Example clause:
{EXAMPLE_CLAUSE}

Example answer:
{json.dumps(_EXAMPLE_ANSWER, indent=1)}
"""


def user_message(*, doc_title: str | None, heading_path: list[str], source_url: str,
                 text: str) -> str:
    return (f"Document: {doc_title or '-'}\nSection: {' > '.join(heading_path) or '-'}\n"
            f"Source: {source_url}\n\nClause text:\n<<<\n{text}\n>>>")


def build_messages(**clause) -> list[dict]:
    return [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": user_message(**clause)}]


def feedback_message(problems: list[str]) -> dict:
    lines = "\n".join(f"- {p}" for p in problems)
    return {"role": "user", "content": (
        "Your previous answer has problems:\n" + lines + "\n"
        "Return the corrected JSON only. Every evidence_quote and remediation_quote must be an "
        "exact copy of text in the clause; drop an item if you cannot quote it.")}
