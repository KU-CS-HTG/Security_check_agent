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


# ---- PostgreSQL advisory pages ----------------------------------------------------------------
# PAGE_REAL is rebuilt from the parser's text view of the REAL page CVE-2022-1552 (the HTML tags
# are inferred from that text, the wording, order and values are the page's). The other pages are
# synthetic shapes for the legacy "Label: value" layout and for a page with almost no structure.
PAGE_REAL = """<html><head><title>PostgreSQL: Security Information</title></head><body>
<nav>Home About Download</nav><div id="pgContentWrap">
<h1>CVE-2022-1552</h1>
<h2>Autovacuum, REINDEX, and others omit "security restricted operation" sandbox</h2>
<p><a href="/docs/current/routine-vacuuming.html">Autovacuum</a>,
<code>REINDEX</code>, <code>CREATE INDEX</code>, <code>REFRESH MATERIALIZED VIEW</code>,
<code>CLUSTER</code>, and <code>pg_amcheck</code> made incomplete efforts to operate safely when a
privileged user is maintaining another user's objects. Those commands activated relevant
protections too late or not at all. An attacker having permission to create non-temp objects in
at least one schema could execute arbitrary SQL functions under a superuser identity.</p>
<p>While promptly updating PostgreSQL is the best remediation for most users, a user unable to do
that can work around the vulnerability by disabling autovacuum, not manually running the above
commands, and not restoring from output of the <code>pg_dump</code> command. Performance may
degrade quickly under this workaround. <code>VACUUM</code> is safe, and all commands are fine
when a trusted user owns the target object.</p>
<p>The PostgreSQL project thanks Alexander Lakhin for reporting this problem.</p>
<h3>Version Information</h3>
<table><thead><tr><th>Affected Version</th><th>Fixed In</th><th>Fix Published</th></tr></thead>
<tbody>
<tr><td>14</td><td>14.3</td><td>2022-05-12</td></tr>
<tr><td>13</td><td>13.7</td><td>2022-05-12</td></tr>
<tr><td>12</td><td>12.11</td><td>2022-05-12</td></tr>
<tr><td>11</td><td>11.16</td><td>2022-05-12</td></tr>
<tr><td>10</td><td>10.21</td><td>2022-05-12</td></tr>
</tbody></table>
<p>For more information about <a href="/support/versioning/">PostgreSQL versioning</a>,
please visit the <a href="/support/versioning/">versioning page</a>.</p>
<h3>CVSS 3.0</h3>
<table>
<tr><th>Overall Score</th><td>8.8</td></tr>
<tr><th>Component</th><td>core server</td></tr>
<tr><th>Vector</th><td>AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td></tr>
</table>
<h3>Reporting Security Vulnerabilities</h3>
<p>If you wish to report a new security vulnerability in PostgreSQL, please send an email to
security@postgresql.org. For reporting non-security bugs, please see the Report a Bug page.</p>
</div><footer>copyright</footer></body></html>"""

PAGE_LEGACY = """<html><head><title>PostgreSQL: CVE-2024-0985</title></head><body>
<nav>Home About Download</nav><div id="pgContentWrap">
<h1>CVE-2024-0985: Late privilege drop in REFRESH MATERIALIZED VIEW CONCURRENTLY</h1>
<p><strong>Versions Affected:</strong> 16, 15, 14, 13, 12</p>
<p><strong>Fixed In:</strong> 16.2, 15.6, 14.11, 13.14, 12.18</p>
<p><strong>Component:</strong> core server</p>
<p><strong>Description:</strong> Late privilege drop in REFRESH MATERIALIZED VIEW
CONCURRENTLY allows an object creator to execute arbitrary SQL functions as the command issuer.</p>
<p>CVSS v3 Base Score: 8.5</p>
<p>Vector string: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H</p>
</div><footer>copyright</footer></body></html>"""

PAGE_SPARSE = """<html><head><title>PostgreSQL: CVE-2019-0001</title></head><body>
<div id="pgContentWrap"><h1>CVE-2019-0001: Something old</h1>
<p>Some prose without any labelled fields. The score is 3.1/ in CVSS:3.1/ lists and not a score.</p>
</div></body></html>"""

REAL_URL = "https://www.postgresql.org/support/security/CVE-2022-1552/"


def test_parse_real_page_structure():
    p = parse_advisory(PAGE_REAL, REAL_URL)
    assert p["cve_id"] == "CVE-2022-1552"
    assert p["title"] == ('CVE-2022-1552: Autovacuum, REINDEX, and others omit '
                          '"security restricted operation" sandbox')
    # inline <code>/<a> are merged into the sentence instead of splitting it into fragments
    assert p["description"].startswith(
        "Autovacuum, REINDEX, CREATE INDEX, REFRESH MATERIALIZED VIEW, CLUSTER, and pg_amcheck "
        "made incomplete efforts")
    assert "output of the pg_dump command" in p["description"]
    assert "thanks Alexander Lakhin" in p["description"]
    assert "Version Information" not in p["description"] and "Reporting" not in p["description"]
    assert "report a new security vulnerability" not in p["full_text"]  # site footer text cut off
    assert [(r["affected_major"], r["fixed_in"], str(r["fix_published"]))
            for r in p["version_rows"]] == [
        ("14", "14.3", "2022-05-12"), ("13", "13.7", "2022-05-12"), ("12", "12.11", "2022-05-12"),
        ("11", "11.16", "2022-05-12"), ("10", "10.21", "2022-05-12")]
    assert p["affected_text"] == "14, 13, 12, 11, 10"
    assert p["fixed_versions"] == ["14.3", "13.7", "12.11", "11.16", "10.21"]  # 10.21 is not lost
    assert (p["cvss_version"], p["cvss_score"], p["cvss_score_source"]) == ("3.0", 8.8, "page")
    assert p["cvss_vector"] == "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert p["component"] == "core server"
    assert p["parse_flags"]["cvss_score_matches_vector"] is True
    assert all(p["parse_flags"][k] for k in FLAG_NAMES)


def test_page_score_that_disagrees_with_its_vector_is_flagged():
    wrong = PAGE_REAL.replace("<td>8.8</td>", "<td>9.9</td>")
    p = parse_advisory(wrong, REAL_URL)
    assert p["cvss_score"] == 9.9 and p["parse_flags"]["cvss_score_matches_vector"] is False


def test_vector_gives_score_when_page_has_no_score():
    no_score = PAGE_REAL.replace("<tr><th>Overall Score</th><td>8.8</td></tr>", "")
    p = parse_advisory(no_score, REAL_URL)
    assert (p["cvss_score"], p["cvss_score_source"]) == (8.8, "computed")


def test_legacy_label_layout_still_parsed():
    p = parse_advisory(PAGE_LEGACY, "https://www.postgresql.org/support/security/CVE-2024-0985/")
    assert p["title"].startswith("CVE-2024-0985: Late privilege drop")
    assert p["affected_text"] == "16, 15, 14, 13, 12"
    assert p["fixed_versions"] == ["16.2", "15.6", "14.11", "13.14", "12.18"]
    assert p["component"] == "core server" and p["version_rows"] == []
    assert p["description"].startswith("Late privilege drop in REFRESH")
    assert (p["cvss_score"], p["cvss_score_source"]) == (8.5, "page")
    assert p["parse_flags"]["cvss_score_matches_vector"] is True


def test_sparse_page_stays_empty_instead_of_guessing():
    p = parse_advisory(PAGE_SPARSE, "https://www.postgresql.org/support/security/CVE-2019-0001/")
    assert p["cve_id"] == "CVE-2019-0001" and p["title"].startswith("CVE-2019-0001")
    for field in ("description", "component", "affected_text", "fixed_text", "cvss_vector",
                  "cvss_score"):
        assert p[field] is None
    assert p["fixed_versions"] == [] and p["version_rows"] == []
    assert set(FLAG_NAMES) <= set(p["parse_flags"])
    assert [k for k in FLAG_NAMES if p["parse_flags"][k]] == ["title"]
