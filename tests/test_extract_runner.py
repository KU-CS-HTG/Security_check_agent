import json

import pytest

from opsgraph.extract.runner import extract_clause
from opsgraph.llm.ollama import LlmError, LlmResponse

TEXT = ("log_connections (string)\n"
        "Causes aspects of each connection to the server to be logged. The default is the empty "
        "string, which disables all connection logging. Only superusers and users with the "
        "appropriate SET privilege can change this setting.")
PATH = ["19.8. Error Reporting and Logging", "19.8.3. What to Log", "log_connections (string)"]
Q = "The default is the empty string, which disables all connection logging."


def item(**over):
    base = {"title": "Connection logging is enabled", "category": "logging_audit",
            "target": "log_connections", "check_method": "", "recommended_value": "",
            "remediation": "", "risk_level": "not_stated", "evidence_quote": Q,
            "remediation_quote": "", "risk_quote": ""}
    base.update(over)
    return base


def answer(*items):
    return json.dumps({"items": list(items)})


class FakeLlm:
    """Plays back scripted answers (str) or errors (Exception) and records every prompt."""

    def __init__(self, *script):
        self.script, self.calls = list(script), []

    def chat_json(self, messages, schema):
        self.calls.append(messages)
        nxt = self.script.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return LlmResponse(content=nxt, prompt_tokens=100, completion_tokens=50, duration_ms=1000)


def run(llm, **kw):
    return extract_clause(llm, doc_title="Doc", heading_path=PATH, source_url="u", text=TEXT, **kw)


def test_valid_answer_is_accepted_on_the_first_attempt():
    llm = FakeLlm(answer(item()))
    out = run(llm)
    assert (out.status, out.attempts, len(out.items)) == ("ok", 1, 1)
    it = out.items[0]
    assert it.verified and it.evidence_match == "exact" and it.target_found
    assert (out.prompt_tokens, out.completion_tokens, out.duration_ms) == (100, 50, 1000)
    first = llm.calls[0]
    assert first[0]["role"] == "system"
    assert "ONLY information stated in the clause" in first[0]["content"]
    assert TEXT in first[1]["content"] and "19.8.3. What to Log" in first[1]["content"]


def test_empty_items_is_a_valid_answer():
    out = run(FakeLlm(answer()))
    assert (out.status, out.attempts, out.items) == ("empty", 1, [])


def test_invalid_json_is_retried_with_feedback():
    llm = FakeLlm("not json {", answer(item()))
    out = run(llm)
    assert (out.status, out.attempts) == ("ok", 2)
    feedback = llm.calls[1][-1]["content"]
    assert llm.calls[1][-2] == {"role": "assistant", "content": "not json {"}
    assert "not valid JSON" in feedback


def test_schema_violation_is_retried_and_the_problem_is_named():
    bad = answer(item(category="networking"), item(evidence_quote="too short"))
    llm = FakeLlm(bad, answer(item()))
    out = run(llm)
    assert (out.status, out.attempts) == ("ok", 2)
    feedback = llm.calls[1][-1]["content"]
    assert "category" in feedback and "evidence_quote" in feedback


def test_quote_not_in_clause_is_retried_then_corrected():
    invented = item(evidence_quote="Always enable connection logging on production servers.")
    llm = FakeLlm(answer(invented), answer(item()))
    out = run(llm)
    assert (out.status, out.attempts, out.items[0].verified) == ("ok", 2, True)
    assert "was not found in the clause text" in llm.calls[1][-1]["content"]
    assert "Always enable connection logging" in llm.calls[1][-1]["content"]


def test_unverifiable_item_after_all_attempts_is_kept_but_flagged():
    invented = item(evidence_quote="Always enable connection logging on production servers.")
    llm = FakeLlm(answer(invented, item(title="Other", evidence_quote=Q)),
                  answer(invented, item(title="Other", evidence_quote=Q)))
    out = run(llm, max_attempts=2)
    assert (out.status, out.attempts) == ("ok", 2)
    flags = {i.payload["title"]: i.verified for i in out.items}
    assert flags == {"Connection logging is enabled": False, "Other": True}
    assert out.error and "not found" in out.error


def test_remediation_quote_is_verified_too():
    ok = item(remediation="Do not disable it.", remediation_quote="Only superusers and users with "
              "the appropriate SET privilege can change this setting.")
    assert run(FakeLlm(answer(ok))).items[0].verified
    bad = item(remediation="Do not disable it.", remediation_quote="Restart the server afterwards "
               "to apply the change to all sessions.")
    out = run(FakeLlm(answer(bad)), max_attempts=1)
    assert out.items[0].evidence_match == "exact" and not out.items[0].verified


def test_target_that_is_not_in_the_clause_is_flagged():
    out = run(FakeLlm(answer(item(target="log_statement"))))
    assert out.items[0].verified and out.items[0].target_found is False


def test_everything_invalid_means_failed_with_the_last_error():
    out = run(FakeLlm("x", "y", "z"), max_attempts=3)
    assert (out.status, out.attempts, out.items) == ("failed", 3, [])
    assert out.raw_response == "z" and "not valid JSON" in out.error


def test_runtime_errors_are_retried_with_the_same_prompt():
    llm = FakeLlm(LlmError("timeout"), answer(item()))
    out = run(llm)
    assert (out.status, out.attempts) == ("ok", 2)
    assert llm.calls[0] == llm.calls[1]
    only_errors = run(FakeLlm(LlmError("a"), LlmError("b")), max_attempts=2)
    assert only_errors.status == "failed" and only_errors.error == "b"


@pytest.mark.parametrize("attempts", [1, 2])
def test_attempt_limit_is_respected(attempts):
    llm = FakeLlm(*(["bad"] * 5))
    run(llm, max_attempts=attempts)
    assert len(llm.calls) == attempts


def test_capitalised_quote_of_mid_sentence_text_is_still_a_faithful_quote():
    # real case: the model wrote "The default ..." for "..., since the default ..."
    text = ("Remote TCP/IP connections will not be possible unless the server is started with an "
            "appropriate value for listen_addresses, since the default behavior is to listen for "
            "TCP/IP connections only on the local loopback address localhost.")
    quote = ("The default behavior is to listen for TCP/IP connections only on the local loopback "
             "address localhost.")
    evidence = "Remote TCP/IP connections will not be possible unless the server is started"
    bad = item(target="listen_addresses", evidence_quote=evidence,
               remediation="Set listen_addresses.", remediation_quote=quote)
    out = extract_clause(FakeLlm(answer(bad)), doc_title=None, heading_path=["host"],
                         source_url="u", text=text, max_attempts=1)
    assert out.items[0].verified and out.items[0].remediation_match == "exact"


def test_risk_is_kept_only_with_a_verified_quote():
    sentence = ("Only superusers and users with the appropriate SET privilege can change this "
                "setting.")
    stated = item(risk_level="high", risk_quote=sentence)
    out = run(FakeLlm(answer(stated)))
    p = out.items[0].payload
    assert (p["risk_level"], p["risk_verified"]) == ("high", True) and "risk_level_claimed" not in p


def test_a_guessed_risk_is_dropped_and_recorded():
    guessed = item(risk_level="medium")                       # no quote at all
    wrong = item(risk_level="high", risk_quote="This setting can lead to complete data loss.")
    for it in (guessed, wrong):
        out = run(FakeLlm(answer(it)))
        p = out.items[0].payload
        assert (p["risk_level"], p["risk_level_claimed"], p["risk_verified"]) == (
            "not_stated", it["risk_level"], False)
        assert out.items[0].verified          # the item itself is fine, only the risk is dropped
        assert out.status == "ok" and out.attempts == 1       # no retry for an unsupported risk


def test_not_stated_risk_needs_nothing():
    p = run(FakeLlm(answer(item()))).items[0].payload
    assert p["risk_level"] == "not_stated" and "risk_verified" not in p


def test_prompt_forbids_the_failure_modes_seen_in_the_first_real_run():
    from opsgraph.extract.prompt import PROMPT_VERSION, SYSTEM

    assert PROMPT_VERSION == "2"
    for phrase in ("Never guess a risk", '"correctly"', "only explains syntax", "ONE identifier",
                   "must not merely restate the title"):
        assert phrase in SYSTEM
