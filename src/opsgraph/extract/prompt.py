"""Prompt for check-item extraction. Bump PROMPT_VERSION whenever the wording changes: results are
stored per (clause text, model, prompt version) and are redone when any of them changes."""

from __future__ import annotations

import json

from opsgraph.extract.schema import CATEGORIES

PROMPT_VERSION = "2"

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
    "risk_quote": "",
}]}

EXAMPLE_CLAUSE_2 = (
    "name_field\n"
    "Specifies which names this record matches. The value any matches all names. A name that "
    "starts with a plus sign matches every member of that group."
)

SYSTEM = f"""You extract security and operations check items from PostgreSQL documentation.
You receive ONE clause of the documentation. Answer with JSON only.

Rules:
1. Output an item only if the clause states a recommendation, requirement, warning, default or risk
   about a concrete setting, file, privilege, role or practice that a database administrator should
   verify or configure for security or reliable operation.
2. Text that only explains syntax, field formats, keywords or how a feature works, without any
   recommendation, warning, requirement or consequence, is NOT a check item: answer
   {{"items": []}}. Most clauses of a reference manual produce no item or one item.
3. Use ONLY information stated in the clause. Never add recommendations, values, risks or commands
   from your own knowledge. Leave a field as an empty string when the clause does not say.
4. title: a concrete, checkable condition that names the setting or value, for example "Connection
   logging is enabled". Never use vague words such as "correctly", "properly" or "appropriately".
5. remediation: a concrete action taken from the clause (a setting to change, a command, a value).
   It must not merely restate the title. "" if the clause gives none.
6. target: ONE identifier copied exactly as written in the clause (setting name, file name, keyword
   or role name).
7. evidence_quote must be copied EXACTLY, character for character, from the clause: one or two
   consecutive sentences that support the item. Never paraphrase inside a quote. If you cannot quote
   supporting text, do not output the item.
8. remediation_quote: an exact copy of the sentence that supports the remediation; "" if none.
9. risk_level is "high", "medium" or "low" ONLY if the clause itself states or clearly describes a
   severity or harmful consequence (for example privilege escalation, data loss, access without
   authentication); then risk_quote must be an exact copy of that sentence. Otherwise risk_level is
   "not_stated" and risk_quote is "". Never guess a risk.
10. One clause may yield several items (one per setting) or none.
11. category must be one of: {", ".join(CATEGORIES)}.

Example clause 1:
{EXAMPLE_CLAUSE}

Example answer 1:
{json.dumps(_EXAMPLE_ANSWER, indent=1)}

Example clause 2 (syntax only, no recommendation or risk):
{EXAMPLE_CLAUSE_2}

Example answer 2:
{{"items": []}}
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
