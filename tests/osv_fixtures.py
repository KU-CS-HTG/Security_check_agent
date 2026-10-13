"""Hand-written OSV records following the OSV schema (https://ossf.github.io/osv-schema/)."""

import io
import json
import zipfile


def rec(osv_id, modified, packages, **extra):
    r = {"schema_version": "1.6.0", "id": osv_id, "modified": modified,
         "published": "2024-01-01T00:00:00Z", "summary": f"summary of {osv_id}",
         "affected": packages}
    r.update(extra)
    return r


def pkg(ecosystem, name, fixed=None):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {"package": {"ecosystem": ecosystem, "name": name},
            "ranges": [{"type": "ECOSYSTEM", "events": events}]}


def git_aff(repo_url, fixed):
    return {"ranges": [{"type": "GIT", "repo": repo_url,
                        "events": [{"introduced": "0"}, {"fixed": fixed}]}]}


DEB_PG = rec("DSA-5000-1", "2024-03-01T10:00:00.123456789Z",
             [pkg("Debian:12", "postgresql-15", "15.5-0+deb12u1")], aliases=["CVE-2024-0001"])
DEB_NGINX = rec("DLA-3000-1", "2024-03-02T10:00:00Z",
                [pkg("Debian:11", "nginx", "1.18.0-6.1+deb11u3")])
DEB_OTHER = rec("DSA-5001-1", "2024-03-03T10:00:00Z", [pkg("Debian:12", "curl", "7.88.1-10")])
GIT_PG = rec("CVE-2024-1111", "2024-03-04T10:00:00Z",
             [git_aff("https://git.postgresql.org/git/postgresql.git", "abc123")])
UBUNTU_PG = rec("UBUNTU-CVE-2024-0001", "2024-03-05T10:00:00Z",
                [pkg("Ubuntu:22.04:LTS", "postgresql-14", "14.10-0ubuntu0.22.04.1")])
GHSA_NGINX = rec("GHSA-xxxx-yyyy-zzzz", "2024-03-06T10:00:00Z", [pkg("Debian:12", "nginx-extras")])


def zip_bytes(records):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for r in records:
            zf.writestr(f"{r['id']}.json", json.dumps(r))
        zf.writestr("README.txt", "not json")
    return buf.getvalue()
