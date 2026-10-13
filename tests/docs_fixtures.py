"""Documentation pages shaped like the PostgreSQL manual's HTML (DocBook output). The structure is
reconstructed from knowledge of that layout (div.sect1/sect2, titlepage, h2/h3.title, div.toc,
navheader/navfooter, admonition divs, id_link permalinks); real pages are verified on the user's
machine with `opsgraph docs parse`."""

CHAPTER = """<html><head><title>PostgreSQL: Documentation: 18: Client Authentication</title>
</head><body><div id="docContent">
<div class="navheader"><table><tr><td>Prev</td><td>Up</td><td>Next</td></tr></table></div>
<div class="chapter" id="CLIENT-AUTHENTICATION"><div class="titlepage"><div><div>
<h2 class="title"><a id="CLIENT-AUTHENTICATION"></a>Chapter 20. Client Authentication</h2>
</div></div></div>
<p>When a client application connects to the database server, it specifies which
<span class="productname">PostgreSQL</span> database user name it wants to connect as.</p>
<div class="toc"><p><strong>Table of Contents</strong></p><dl class="toc">
<dt><span class="sect1"><a href="auth-pg-hba-conf.html">20.1. The pg_hba.conf File</a></span></dt>
</dl></div></div>
<div class="navfooter"><table><tr><td>Prev</td><td>Next</td></tr></table></div>
<div id="docFooter">Submit correction.
Copyright © 1996–2026 The PostgreSQL Global Development Group</div>
</div></body></html>"""

SECTION = """<html><body><div id="docContent">
<div class="navheader">Prev Up Next</div>
<div class="sect1" id="AUTH-PG-HBA-CONF"><div class="titlepage"><div><div>
<h2 class="title" style="clear: both">20.1. The <code class="filename">pg_hba.conf</code> File
<a href="#AUTH-PG-HBA-CONF" class="id_link">#</a></h2></div></div></div>
<p>Client authentication is controlled by a configuration file, which traditionally is named
<code class="filename">pg_hba.conf</code> and is stored in the database cluster's data
directory.</p>
<p>A record can have several formats:</p>
<pre class="synopsis">local      database  user  auth-method [auth-options]
host       database  user  address  auth-method  [auth-options]</pre>
<div class="variablelist"><dl class="variablelist">
<dt><span class="term"><code class="literal">local</code></span></dt>
<dd><p>This record matches connection attempts using Unix-domain sockets.</p></dd>
<dt><span class="term"><code class="literal">host</code></span></dt>
<dd><p>This record matches connection attempts made using TCP/IP.</p>
<ul class="itemizedlist"><li class="listitem"><p>first item</p></li></ul></dd>
</dl></div>
<div class="warning"><h3 class="title">Warning</h3>
<p>Do not use <code class="literal">trust</code> unless you trust every user on the
machine.</p></div>
<div class="sect2" id="AUTH-PG-HBA-EXAMPLES"><div class="titlepage"><div><div>
<h3 class="title">20.1.1. Examples</h3></div></div></div>
<pre class="programlisting">host all all 127.0.0.1/32 scram-sha-256
host all all ::1/128      scram-sha-256</pre>
<div class="table" id="X1"><p class="title"><strong>Table 20.1. Methods</strong></p>
<div class="table-contents"><table><thead><tr><th>Method</th><th>Meaning</th></tr></thead>
<tbody><tr><td>trust</td><td>allow unconditionally</td></tr>
<tr><td>scram-sha-256</td><td>salted challenge response</td></tr></tbody></table></div></div>
</div>
<div class="sect2" id="EMPTY-SECTION"><div class="titlepage"><div><div>
<h3 class="title">20.1.2. Empty</h3></div></div></div></div>
</div>
<div class="navfooter">Prev Next</div>
<div id="docFooter">Copyright © 1996–2026 The PostgreSQL Global Development Group</div>
</div></body></html>"""

NO_NOTICE = """<html><body><div id="docContent"><div class="sect1" id="A"><div class="titlepage">
<div><div><h2 class="title">1. A</h2></div></div></div><p>text</p></div></div></body></html>"""
