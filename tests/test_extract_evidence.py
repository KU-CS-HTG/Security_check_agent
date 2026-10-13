import pytest

from opsgraph.extract.evidence import match_quote, normalize, term_in_text
from opsgraph.extract.schema import (
    CATEGORIES,
    ExtractionResult,
    json_schema,
)

CLAUSE = ("log_connections (boolean)\n"
          "Causes each attempted connection to the server to be logged, as well as successful\n"
          "completion of client authentication. Only superusers can change this parameter at\n"
          "session start, and it cannot be changed at all within a session. The default is off.")

Q1 = "Causes each attempted connection to the server to be logged"


def test_exact_quote_is_verified():
    assert match_quote(CLAUSE, Q1) == "exact"
    # sentences that are not consecutive in the clause
    assert match_quote(CLAUSE, "The default is off. Only superusers") is None


def test_whitespace_and_line_breaks_do_not_matter():
    q = "successful completion of client authentication. Only superusers can change this parameter"
    assert match_quote(CLAUSE, q) == "exact"


def test_typographic_quotes_dashes_and_invisible_characters():
    clause = ("The “facility” can be LOCAL0–LOCAL7; when logging to syslog is enabled, "
              "this parameter deter­mines the program​ name used.")
    quote = 'The "facility" can be LOCAL0-LOCAL7; when logging to syslog is enabled'
    assert match_quote(clause, quote) == "exact"
    assert match_quote(clause, "this parameter determines the program name used") == "exact"


def test_words_glued_in_the_source_match_loosely():
    clause = "this parameter determinesthe maximum size of an individual log file"
    quote = "this parameter determines the maximum size of an individual"
    assert match_quote(clause, quote) == "loose"


def test_hallucinated_or_altered_quotes_are_rejected():
    paraphrase = "Causes every connection attempt to the server to be recorded"
    assert match_quote(CLAUSE, paraphrase) is None
    invented = "Always enable log_connections in production environments"
    assert match_quote(CLAUSE, invented) is None
    one_word_changed = ("Causes each attempted connection to the server to be logged,"
                        " as well as unsuccessful completion of client authentication")
    assert match_quote(CLAUSE, one_word_changed) is None


def test_too_short_or_too_long_quotes_prove_nothing():
    assert match_quote(CLAUSE, "log_connections") is None
    assert match_quote(CLAUSE, "The default is off.") is None          # < 20 chars
    assert match_quote(CLAUSE * 5, normalize(CLAUSE) * 5) is None        # > 600 chars


def test_ellipsis_skips_text_but_pieces_must_appear_in_order():
    q = "Causes each attempted connection ... Only superusers can change this parameter"
    assert match_quote(CLAUSE, q) == "exact"
    reversed_ = "Only superusers can change this parameter ... Causes each attempted connection"
    assert match_quote(CLAUSE, reversed_) is None
    too_short_piece = "Causes each attempted connection ... tiny"
    assert match_quote(CLAUSE, too_short_piece) is None


def test_term_in_text():
    assert term_in_text("log_connections", CLAUSE)
    assert term_in_text("log_connections", "see LOG_CONNECTIONS here")  # case does not matter
    assert not term_in_text("log_statement", CLAUSE, "19.8. Error Reporting")
    assert not term_in_text("", CLAUSE)


def test_flat_schema_mirrors_the_pydantic_model():
    schema = json_schema()
    item = schema["properties"]["items"]["items"]
    assert "$ref" not in str(schema) and "anyOf" not in str(schema) and "null" not in str(schema)
    assert set(item["required"]) == set(item["properties"])
    assert item["properties"]["category"]["enum"] == list(CATEGORIES)
    ok = {"title": "Connection logging is enabled", "category": "logging_audit",
          "target": "log_connections", "check_method": "", "recommended_value": "",
          "remediation": "", "risk_level": "not_stated", "evidence_quote": Q1,
          "remediation_quote": ""}
    assert ExtractionResult.model_validate({"items": [ok]}).items[0].target == "log_connections"
    for bad in ({**ok, "category": "network"}, {**ok, "evidence_quote": "too short"},
                {**ok, "risk_level": "critical"}):
        with pytest.raises(ValueError):
            ExtractionResult.model_validate({"items": [bad]})
