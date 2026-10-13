from osv_fixtures import DEB_PG, GHSA_NGINX, rec

from opsgraph.normalize.cvss import cvss3_base_score, roundup, severity_label
from opsgraph.normalize.osv import normalize_record, pick_severity, range_intervals
from opsgraph.normalize.pg_advisory import FLAG_NAMES, parse_advisory


# ---- CVSS ---------------------------------------------------------------------------------
def test_cvss3_known_scores():
    cases = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N": 4.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
    }
    for vector, expected in cases.items():
        assert cvss3_base_score(vector) == expected, vector


def test_cvss3_rejects_incomplete_or_foreign_vectors():
    assert cvss3_base_score("") is None
    assert cvss3_base_score("CVSS:3.1/AV:N") is None
    assert cvss3_base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None  # CVSS v2
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:Z") is None


def test_roundup_and_labels():
    assert roundup(4.0) == 4.0 and roundup(4.02) == 4.1 and roundup(7.0000001) == 7.0
    assert [severity_label(s) for s in (None, 0.0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0)] == [
        None, "NONE", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]


# ---- OSV ----------------------------------------------------------------------------------
def test_range_intervals():
    ev = [{"introduced": "0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"fixed": "2.3"}]
    assert range_intervals(ev) == [{"introduced": "0", "fixed": "1.2"},
                                   {"introduced": "2.0", "fixed": "2.3"}]
    assert range_intervals([{"introduced": "0"}]) == [{"introduced": "0"}]  # open ended
    assert range_intervals([{"introduced": "1"}, {"last_affected": "1.5"}]) == [
        {"introduced": "1", "last_affected": "1.5"}]
    assert range_intervals([{"introduced": "0"}, {"limit": "*"}]) == [
        {"introduced": "0", "limit_": "*"}]
    assert range_intervals([{"fixed": "3"}]) == [{"introduced": None, "fixed": "3"}]
    assert range_intervals([]) == []


def test_severity_priority_and_no_invention():
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    v3 = {"severity": [{"type": "CVSS_V3", "score": vec}],
          "database_specific": {"severity": "LOW"}}
    s = pick_severity(v3)
    assert (s["severity_score"], s["severity_label"], s["severity_source"]) == (
        9.8, "CRITICAL", "cvss3_computed")  # computed from the vector, not the db label
    v4 = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H"
                                                  "/VA:H/SC:N/SI:N/SA:N"}]}
    assert pick_severity(v4)["severity_source"] == "cvss_vector_only"
    assert pick_severity(v4)["severity_score"] is None
    moderate = pick_severity({"database_specific": {"severity": "MODERATE"}})
    assert moderate["severity_label"] == "MEDIUM"
    none = pick_severity({"id": "X"})
    assert set(none.values()) == {None}  # nothing is guessed


def test_normalize_record_structure():
    r = rec("GHSA-aaaa-bbbb-cccc", "2024-05-01T00:00:00Z", [
        {"package": {"ecosystem": "Debian:12", "name": "nginx", "purl": "pkg:deb/debian/nginx"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.22.1-9"}]}],
         "versions": ["1.18", "1.20"]},
    ], aliases=["CVE-2024-1", "CVE-2024-1"], withdrawn="2024-06-01T00:00:00Z",
        references=[{"type": "WEB", "url": "https://example.org/a"}, {"type": "WEB"}])
    n = normalize_record(r)
    assert n["aliases"] == ["CVE-2024-1"] and n["withdrawn"].month == 6
    aff = n["affected"][0]
    assert (aff["ecosystem"], aff["ecosystem_base"], aff["package"]) == (
        "Debian:12", "Debian", "nginx")
    assert aff["versions"] == ["1.18", "1.20"]
    assert aff["ranges"] == [{"range_type": "ECOSYSTEM", "repo": None, "introduced": "0",
                              "fixed": "1.22.1-9", "last_affected": None, "limit_": None}]
    # references without a url are dropped
    assert n["references"] == [{"ref_type": "WEB", "url": "https://example.org/a"}]
    assert normalize_record(DEB_PG)["modified"].year == 2024
    # a package listed with only {"introduced": "0"} is an open-ended range, not "no range"
    open_ended = normalize_record(GHSA_NGINX)["affected"][0]["ranges"]
    assert [(x["introduced"], x["fixed"]) for x in open_ended] == [("0", None)]


# ---- PostgreSQL advisory pages (synthetic fixtures: shapes the parser is meant to handle) ----
PAGE_INLINE = """<html><head><title>PostgreSQL: CVE-2024-0985</title></head><body>
<nav>Home About Download</nav><div id="pgContentWrap">
<h1>CVE-2024-0985: Late privilege drop in REFRESH MATERIALIZED VIEW CONCURRENTLY</h1>
<p><strong>Versions Affected:</strong> 16, 15, 14, 13, 12</p>
<p><strong>Fixed In:</strong> 16.2, 15.6, 14.11, 13.14, 12.18</p>
<p><strong>Component:</strong> core server</p>
<p><strong>Description:</strong> Late privilege drop in REFRESH MATERIALIZED VIEW
CONCURRENTLY allows an object creator to execute arbitrary SQL functions as the command issuer.</p>
<p>CVSS v3 Base Score: 8.0</p>
<p>Vector string: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H</p>
</div><footer>copyright</footer></body></html>"""

PAGE_TABLE = """<html><body><div id="pgContentWrap">
<h2>CVE-2022-1552: Autovacuum, REINDEX, and others omit "security restricted operation"</h2>
<table>
<tr><th>Versions affected</th><td>14, 13, 12, 11, 10</td></tr>
<tr><th>Fixed</th><td>Fixed in 14.3, 13.7, 12.11, 11.16, 10.21</td></tr>
<tr><th>Description</th><td>Autovacuum, REINDEX, CREATE INDEX, REFRESH MATERIALIZED VIEW,
CLUSTER, and pg_amcheck made incomplete efforts to operate safely when a privileged user is
maintaining another user's objects.</td></tr>
<tr><th>CVSS v3 Base Score</th><td>8.8</td></tr>
</table></div></body></html>"""

PAGE_SPARSE = """<html><head><title>PostgreSQL: CVE-2019-0001</title></head><body>
<div id="pgContentWrap"><h1>CVE-2019-0001: Something old</h1>
<p>Some prose without any labelled fields. The score is 3.1/ in CVSS:3.1/ lists and not a score.</p>
</div></body></html>"""


def test_parse_inline_label_page():
    p = parse_advisory(PAGE_INLINE, "https://www.postgresql.org/support/security/CVE-2024-0985/")
    assert p["cve_id"] == "CVE-2024-0985"
    assert p["title"].startswith("CVE-2024-0985: Late privilege drop")
    assert p["affected_text"] == "16, 15, 14, 13, 12"
    assert p["fixed_versions"] == ["16.2", "15.6", "14.11", "13.14", "12.18"]
    assert p["component"] == "core server"
    assert p["description"].startswith("Late privilege drop in REFRESH")
    assert "Base Score" not in p["description"] and "Home About" not in p["full_text"]
    assert (p["cvss_score"], p["cvss_score_source"]) == (8.0, "page")
    assert p["cvss_vector"] == "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H"
    assert all(p["parse_flags"].values())


def test_parse_table_page():
    p = parse_advisory(PAGE_TABLE, "https://www.postgresql.org/support/security/CVE-2022-1552/")
    assert p["affected_text"] == "14, 13, 12, 11, 10"
    assert p["fixed_versions"] == ["14.3", "13.7", "12.11", "11.16", "10.21"]
    assert p["description"].startswith("Autovacuum, REINDEX")
    assert p["cvss_score"] == 8.8 and p["cvss_vector"] is None
    assert p["parse_flags"]["cvss_vector"] is False and p["parse_flags"]["component"] is False


def test_sparse_page_stays_empty_instead_of_guessing():
    p = parse_advisory(PAGE_SPARSE, "https://www.postgresql.org/support/security/CVE-2019-0001/")
    assert p["cve_id"] == "CVE-2019-0001" and p["title"].startswith("CVE-2019-0001")
    for field in ("description", "component", "affected_text", "fixed_text", "cvss_vector",
                  "cvss_score"):
        assert p[field] is None
    assert p["fixed_versions"] == []
    assert set(p["parse_flags"]) == set(FLAG_NAMES)
    assert [k for k, v in p["parse_flags"].items() if v] == ["title"]


def test_score_computed_from_vector_when_page_has_none():
    html = ("<div id='pgContentWrap'><h1>CVE-2020-1: t</h1>"
            "<p>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</p></div>")
    p = parse_advisory(html, "https://www.postgresql.org/support/security/CVE-2020-1/")
    assert (p["cvss_score"], p["cvss_score_source"]) == (9.8, "computed")
