from osv_fixtures import (
    DEB_NGINX,
    DEB_OTHER,
    DEB_PG,
    GHSA_NGINX,
    GIT_PG,
    UBUNTU_PG,
)

from opsgraph.licensing import UNKNOWN, is_ubuntu_record, license_for_osv_id
from opsgraph.scope import load_scope


def test_scope_matches_target_products_only():
    scope = load_scope()
    assert scope.match(DEB_PG) == ["postgresql"]
    assert scope.match(DEB_NGINX) == ["nginx"]
    assert scope.match(GIT_PG) == ["postgresql"]  # matched through the GIT repo URL
    assert scope.match(DEB_OTHER) == []
    assert scope.match({"id": "x"}) == []


def test_scope_ecosystems_follow_policy():
    assert "Ubuntu" not in load_scope().ecosystems


def test_license_by_id_prefix():
    assert license_for_osv_id("GHSA-aaaa-bbbb-cccc") == "CC-BY-4.0"
    assert license_for_osv_id("RUSTSEC-2020-0001") == "CC0-1.0"
    assert license_for_osv_id("UBUNTU-CVE-2024-0001") == "CC-BY-SA-4.0"
    # converted feeds are not licensed on the OSV data page -> UNKNOWN, never guessed
    for osv_id in ("DSA-5000-1", "DLA-3000-1", "CVE-2024-1111", "ALPINE-CVE-2024-1"):
        assert license_for_osv_id(osv_id) == UNKNOWN


def test_ubuntu_detection_by_id_and_by_package():
    assert is_ubuntu_record(UBUNTU_PG)
    sneaky = {"id": "CVE-2024-9", "affected": [{"package": {"ecosystem": "Ubuntu:20.04:LTS"}}]}
    assert is_ubuntu_record(sneaky)
    assert not is_ubuntu_record(DEB_PG) and not is_ubuntu_record(GHSA_NGINX)
