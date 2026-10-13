"""Extract check items from one clause: ask, validate, verify quotes, retry with feedback."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Protocol

from pydantic import ValidationError

from opsgraph.extract.evidence import match_quote, term_in_text
from opsgraph.extract.prompt import build_messages, feedback_message
from opsgraph.extract.schema import ExtractionResult, json_schema
from opsgraph.llm.ollama import LlmError, LlmResponse
from opsgraph.logging import get_logger

log = get_logger(__name__)


class ChatJson(Protocol):
    def chat_json(self, messages: list[dict], schema: dict) -> LlmResponse: ...


@dataclass
class CheckedItem:
    payload: dict                 # the validated item as the model gave it
    evidence_match: str | None    # exact | loose | None (not found in the clause)
    remediation_match: str | None  # None also when there is no remediation quote
    target_found: bool            # the "target" term occurs in the clause or its heading

    @property
    def verified(self) -> bool:
        needs_remediation_quote = bool(self.payload.get("remediation_quote"))
        return self.evidence_match is not None and (
            not needs_remediation_quote or self.remediation_match is not None)

    @property
    def problems(self) -> list[str]:
        out = []
        if self.evidence_match is None:
            out.append(f'item "{self.payload["title"]}": evidence_quote was not found in the '
                       f'clause text: "{self.payload["evidence_quote"][:120]}"')
        if self.payload.get("remediation_quote") and self.remediation_match is None:
            out.append(f'item "{self.payload["title"]}": remediation_quote was not found in the '
                       f'clause text: "{self.payload["remediation_quote"][:120]}"')
        return out


@dataclass
class Outcome:
    status: str                   # ok | empty | failed
    attempts: int
    items: list[CheckedItem] = field(default_factory=list)
    error: str | None = None
    raw_response: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    duration_ms: int = 0


def check_item(payload: dict, clause_text: str, heading_path: list[str]) -> CheckedItem:
    rem = payload.get("remediation_quote") or ""
    payload = dict(payload)
    claimed = payload["risk_level"]
    if claimed != "not_stated":
        risk_quote = payload.get("risk_quote") or ""
        supported = bool(risk_quote) and match_quote(clause_text, risk_quote) is not None
        payload["risk_verified"] = supported
        if not supported:  # a severity the clause does not state is the model's guess: drop it
            payload["risk_level"] = "not_stated"
            payload["risk_level_claimed"] = claimed
    return CheckedItem(
        payload=payload,
        evidence_match=match_quote(clause_text, payload["evidence_quote"]),
        remediation_match=match_quote(clause_text, rem) if rem else None,
        target_found=term_in_text(payload["target"], clause_text, " ".join(heading_path)),
    )


def extract_clause(llm: ChatJson, *, doc_title: str | None, heading_path: list[str],
                   source_url: str, text: str, max_attempts: int = 3) -> Outcome:
    schema = json_schema()
    messages = build_messages(doc_title=doc_title, heading_path=heading_path,
                              source_url=source_url, text=text)
    out = Outcome(status="failed", attempts=0)
    checked: list[CheckedItem] = []
    for attempt in range(1, max_attempts + 1):
        out.attempts = attempt
        try:
            resp = llm.chat_json(messages, schema)
        except LlmError as e:
            out.error = str(e)
            log.warning("llm_call_failed", attempt=attempt, error=str(e))
            continue  # the same prompt is tried again (timeouts, a busy runtime)
        out.raw_response = resp.content
        out.prompt_tokens += resp.prompt_tokens
        out.completion_tokens += resp.completion_tokens
        out.duration_ms += resp.duration_ms

        problems: list[str] = []
        try:
            data = json.loads(resp.content)
        except ValueError as e:
            data, problems = None, [f"the answer was not valid JSON ({e})"]
        parsed = None
        if data is not None:
            try:
                parsed = ExtractionResult.model_validate(data)
            except ValidationError as e:
                problems = [f'{".".join(str(x) for x in err["loc"])}: {err["msg"]}'
                            for err in e.errors()[:8]]
        if parsed is not None:
            checked = [check_item(i.model_dump(), text, heading_path) for i in parsed.items]
            problems = [p for c in checked for p in c.problems]
            if not problems:
                out.items, out.error = checked, None
                out.status = "ok" if checked else "empty"
                return out
            out.error = "; ".join(problems)[:500]
        else:
            out.error = "; ".join(problems)[:500]
            checked = []
        if attempt < max_attempts:
            messages = [*messages, {"role": "assistant", "content": resp.content},
                        feedback_message(problems)]
    # out of attempts: keep what the model produced, but flag unverified items as such
    if checked:
        out.items = checked
        out.status = "ok"
    return out
