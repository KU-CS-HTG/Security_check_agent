"""License of an OSV record, derived from the upstream database its id comes from.

Source: OSV "Data sources" page (docs/sources/SOURCES.md, 2026-10-09). The page lists the license
per upstream database. Records converted by OSV from other feeds (Debian DSA/DLA, Alpine, NVD
CVEs) have no license stated there -> UNKNOWN: stored and tagged, never treated as publish-safe.
"""

from __future__ import annotations

UNKNOWN = "UNKNOWN"

# id prefix -> license, exactly as listed on the OSV data page
_PREFIX_LICENSE: dict[str, str] = {
    "GHSA-": "CC-BY-4.0",       # GitHub Advisory Database
    "PYSEC-": "CC-BY-4.0",      # PyPI Advisory Database
    "GO-": "CC-BY-4.0",         # Go Vulnerability Database
    "RUSTSEC-": "CC0-1.0",      # Rust Advisory Database
    "DRUPAL-": "MIT",           # Drupal Advisory Database
    "GSD-": "CC0-1.0",          # Global Security Database
    "OSV-": "CC-BY-4.0",        # OSS-Fuzz
    "RLSA-": "BSD", "RLBA-": "BSD", "RLEA-": "BSD",           # Rocky Linux (page says "BSD")
    "ALSA-": "MIT", "ALBA-": "MIT", "ALEA-": "MIT",           # AlmaLinux
    "HSEC-": "CC0-1.0",         # Haskell Security Advisories
    "RSEC-": "Apache-2.0",      # RConsortium Advisory Database
    "MAL-": "Apache-2.0",       # OpenSSF Malicious Packages
    "PSF-": "CC-BY-4.0",        # Python Software Foundation
    "BIT-": "Apache-2.0",       # Bitnami Vulnerability Database
    "EEF-": "CC-BY-4.0",        # Erlang Ecosystem Foundation CNA
    "UBUNTU-": "CC-BY-SA-4.0",  # Ubuntu -> blocked by policy
    "USN-": "CC-BY-SA-4.0",
    "LSN-": "CC-BY-SA-4.0",
}


def license_for_osv_id(osv_id: str) -> str:
    for prefix, lic in _PREFIX_LICENSE.items():
        if osv_id.startswith(prefix):
            return lic
    return UNKNOWN


def is_ubuntu_record(record: dict) -> bool:
    """Ubuntu data is excluded at first (ADR-0003). Detected by id prefix or any Ubuntu package."""
    if license_for_osv_id(record.get("id", "")) == "CC-BY-SA-4.0":
        return True
    for aff in record.get("affected", []):
        eco = (aff.get("package") or {}).get("ecosystem", "")
        if eco.split(":")[0] == "Ubuntu":
            return True
    return False
