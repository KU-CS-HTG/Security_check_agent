"""Scope (b): decide whether an OSV record concerns one of the target products."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from opsgraph.config import CONFIG_DIR


class ProductMatcher(BaseModel):
    name: str
    package_patterns: dict[str, list[str]] = Field(default_factory=dict)  # ecosystem -> regexes
    repo_patterns: list[str] = Field(default_factory=list)  # regexes on ranges[].repo (GIT)

    def matches(self, record: dict) -> bool:
        for aff in record.get("affected", []):
            pkg = aff.get("package") or {}
            eco = str(pkg.get("ecosystem", "")).split(":")[0]  # "Debian:12" -> "Debian"
            name = str(pkg.get("name", ""))
            patterns = self.package_patterns.get(eco, []) + self.package_patterns.get("*", [])
            if name and any(re.search(p, name) for p in patterns):
                return True
            for rng in aff.get("ranges", []):
                repo = rng.get("repo")
                if repo and any(re.search(p, repo) for p in self.repo_patterns):
                    return True
        return False


class OsvScope(BaseModel):
    ecosystems: list[str]
    products: list[ProductMatcher]

    def match(self, record: dict) -> list[str]:
        return [p.name for p in self.products if p.matches(record)]


def load_scope(path: Path | None = None) -> OsvScope:
    with (path or CONFIG_DIR / "osv_scope.yaml").open(encoding="utf-8") as f:
        return OsvScope.model_validate(yaml.safe_load(f))
