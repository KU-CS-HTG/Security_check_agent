from docs_fixtures import CHAPTER, NO_NOTICE, SECTION

from opsgraph.normalize.docs import STANDARD_NOTICE, parse_doc

URL = "https://www.postgresql.org/docs/18/auth-pg-hba-conf.html"


def test_section_is_split_by_headings_with_paths_and_anchors():
    doc = parse_doc(SECTION, URL)
    assert doc.title == "20.1. The pg_hba.conf File"  # permalink '#' removed, <code> merged
    assert [c.key for c in doc.clauses] == ["AUTH-PG-HBA-CONF", "AUTH-PG-HBA-EXAMPLES"]
    first, second = doc.clauses
    assert first.heading_path == ["20.1. The pg_hba.conf File"]
    assert second.heading_path == ["20.1. The pg_hba.conf File", "20.1.1. Examples"]
    assert [c.ordinal for c in doc.clauses] == [0, 1]
    assert second.anchor == "AUTH-PG-HBA-EXAMPLES"


def test_empty_heading_only_sections_are_dropped():
    doc = parse_doc(SECTION, URL)
    assert all("Empty" not in " ".join(c.heading_path) for c in doc.clauses)


def test_text_is_the_pages_own_text_inline_markup_merged():
    first = parse_doc(SECTION, URL).clauses[0].text
    assert ("Client authentication is controlled by a configuration file, which traditionally "
            "is named pg_hba.conf and is stored in the database cluster's data directory.") in first
    assert "This record matches connection attempts using Unix-domain sockets." in first
    assert "- first item" in first                      # list items keep a marker
    assert "Prev" not in first and "Next" not in first   # navigation is not content


def test_code_blocks_keep_their_line_breaks():
    first = parse_doc(SECTION, URL).clauses[0].text
    assert ("local      database  user  auth-method [auth-options]\n"
            "host       database  user  address  auth-method  [auth-options]") in first
    ex = parse_doc(SECTION, URL).clauses[1].text
    assert "host all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128      scram-sha-256" in ex


def test_admonition_label_is_text_not_a_section():
    doc = parse_doc(SECTION, URL)
    first = doc.clauses[0].text
    assert "Warning\nDo not use trust unless you trust every user on the machine." in first
    assert not any(c.heading_path[-1] == "Warning" for c in doc.clauses)


def test_table_rows_become_lines():
    ex = parse_doc(SECTION, URL).clauses[1].text
    assert "Method | Meaning" in ex and "scram-sha-256 | salted challenge response" in ex
    assert "Table 20.1. Methods" in ex


def test_toc_and_chapter_intro():
    doc = parse_doc(CHAPTER, "https://www.postgresql.org/docs/18/client-authentication.html")
    assert [c.key for c in doc.clauses] == ["CLIENT-AUTHENTICATION"]
    assert doc.clauses[0].text.startswith("When a client application connects")
    assert "Table of Contents" not in doc.clauses[0].text and "20.1." not in doc.clauses[0].text


def test_copyright_notice_from_page_or_standard_fallback():
    assert parse_doc(SECTION, URL).copyright_notice == (
        "Copyright © 1996–2026 The PostgreSQL Global Development Group")
    assert parse_doc(SECTION, URL).notice_from_page is True
    bare = parse_doc(NO_NOTICE, URL)
    assert bare.copyright_notice == STANDARD_NOTICE and bare.notice_from_page is False


def test_long_clause_is_split_at_block_boundaries_with_stable_keys():
    paras = "".join(f"<p>{'word ' * 120}number {i}.</p>" for i in range(10))  # ~6000+ chars
    html = ('<div id="docContent"><div class="sect1" id="BIG"><div class="titlepage"><div><div>'
            f'<h2 class="title">1. Big</h2></div></div></div>{paras}</div></div>')
    doc = parse_doc(html, URL, max_chars=2000)
    keys = [c.key for c in doc.clauses]
    assert len(keys) > 1 and keys[0] == "BIG#p1" and keys == [f"BIG#p{i + 1}" for i in
                                                              range(len(keys))]
    assert all(len(c.text) <= 2000 + 800 for c in doc.clauses)       # never cut mid paragraph
    assert sum(c.text.count("number") for c in doc.clauses) == 10     # nothing lost
    assert len({c.key for c in doc.clauses}) == len(doc.clauses)


def test_one_huge_code_block_is_kept_whole():
    big = "line\n" * 5000
    html = ('<div id="docContent"><div class="sect1" id="C"><div class="titlepage"><div><div>'
            f'<h2 class="title">1. C</h2></div></div></div><pre>{big}</pre></div></div>')
    doc = parse_doc(html, URL, max_chars=1000)
    assert len(doc.clauses) == 1 and doc.clauses[0].text.count("line") == 5000


def test_duplicate_anchors_get_distinct_keys():
    html = ('<div id="docContent"><div class="sect1" id="D"><div class="titlepage"><div><div>'
            '<h2 class="title">1. One</h2></div></div></div><p>a</p>'
            '<div class="titlepage"><div><div><h3 class="title" id="D">1.1. Same</h3></div></div>'
            '</div><p>b</p></div></div>')
    keys = [c.key for c in parse_doc(html, URL).clauses]
    assert len(keys) == len(set(keys)) == 2
