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


def _guc_page(n_terms: int = 6, with_ids: bool = True) -> str:
    items = ""
    for i in range(n_terms):
        ident = f' id="GUC-SETTING-{i}"' if with_ids else ""
        items += (f'<dt{ident}><span class="term"><code class="varname">setting_{i}</code> '
                  f'(<code class="type">boolean</code>)'
                  f'<a href="#GUC-SETTING-{i}" class="id_link">#</a></span></dt>'
                  f'<dd><p>{"Controls behaviour number " + str(i) + ". " * 1}'
                  f'{"This sentence pads the description. " * 25}</p>'
                  f'<p>The default is <code>off</code>.</p></dd>')
    return ('<div id="docContent"><div class="sect1" id="RUNTIME-CONFIG-LOGGING-WHAT">'
            '<div class="titlepage"><div><div>'
            '<h2 class="title">19.8.3. What to Log</h2></div></div></div>'
            '<p>Intro paragraph of the section.</p>'
            f'<div class="variablelist"><dl class="variablelist">{items}</dl></div></div></div>')


def test_oversized_section_with_terms_is_split_per_setting():
    doc = parse_doc(_guc_page(), "https://www.postgresql.org/docs/18/runtime-config-logging.html")
    keys = [c.key for c in doc.clauses]
    assert keys[0] == "RUNTIME-CONFIG-LOGGING-WHAT"          # lead paragraph
    assert keys[1:] == [f"GUC-SETTING-{i}" for i in range(6)]  # one clause per setting
    lead, first = doc.clauses[0], doc.clauses[1]
    assert lead.text == "Intro paragraph of the section."
    assert first.heading_path == ["19.8.3. What to Log", "setting_0 (boolean)"]  # '#' removed
    assert first.text.startswith("setting_0 (boolean)\nControls behaviour number 0.")
    assert "The default is off." in first.text
    assert first.anchor == "GUC-SETTING-0"                  # citations point at the setting
    assert [c.ordinal for c in doc.clauses] == list(range(7))


def test_terms_without_ids_get_slug_keys():
    doc = parse_doc(_guc_page(with_ids=False), URL)
    assert [c.key for c in doc.clauses[1:]] == [
        f"RUNTIME-CONFIG-LOGGING-WHAT/setting-{i}-boolean" for i in range(6)]
    assert all(c.anchor == "RUNTIME-CONFIG-LOGGING-WHAT" for c in doc.clauses[1:])


def test_small_term_list_stays_in_one_clause():
    # SECTION's variablelist has two short terms: the section is not oversized
    first = parse_doc(SECTION, URL).clauses[0]
    assert "local" in first.text and "host" in first.text
    assert all(c.key != "local" for c in parse_doc(SECTION, URL).clauses)


def test_single_term_never_splits_a_definition_from_its_text():
    doc = parse_doc(_guc_page(), URL)
    for c in doc.clauses[1:]:
        term, _, rest = c.text.partition("\n")
        assert term.startswith("setting_") and "Controls behaviour" in rest


def test_inline_markup_does_not_add_spaces_before_punctuation():
    html = ('<div id="docContent"><div class="sect1" id="P"><div class="titlepage"><div><div>'
            '<h2 class="title">1. Using <code>trust</code>, safely</h2></div></div></div>'
            '<p>Use <code>trust</code>, or <code>md5</code>. See <a href="x">the docs</a>.<br/>'
            'Next line (<code>boolean</code>).</p></div></div>')
    doc = parse_doc(html, URL)
    assert doc.title == "1. Using trust, safely"
    # a <br> is whitespace (paragraphs are single lines), never glued text
    assert doc.clauses[0].text == "Use trust, or md5. See the docs. Next line (boolean)."


def test_consecutive_terms_share_the_following_description():
    items = ""
    for i in range(3):
        items += (f'<dt id="GUC-A{i}"><span class="term">a_{i} (boolean)</span></dt>'
                  f'<dt id="GUC-B{i}"><span class="term">b_{i} (boolean)</span></dt>'
                  f'<dd><p>{"Shared description. " * 60}</p></dd>')
    html = ('<div id="docContent"><div class="sect1" id="S"><div class="titlepage"><div><div>'
            f'<h2 class="title">1. S</h2></div></div></div><dl>{items}</dl></div></div>')
    doc = parse_doc(html, URL)
    assert [c.key for c in doc.clauses] == ["GUC-A0", "GUC-A1", "GUC-A2"]
    first = doc.clauses[0]
    assert first.text.startswith("a_0 (boolean)\nb_0 (boolean)\nShared description.")
    assert first.heading_path[-1] == "a_0 (boolean) b_0 (boolean)"
    assert all("Shared description." in c.text for c in doc.clauses)  # no term without text
