"""Configuration: secrets from .env (pydantic-settings), non-secrets from config/*.yaml."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"

DbRole = Literal["owner", "collector", "reader"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=PROJECT_ROOT / ".env", extra="ignore")

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "opsgraph"

    db_owner_user: str = "og_owner"
    db_owner_password: str = ""
    db_collector_user: str = "og_collector"
    db_collector_password: str = ""
    db_reader_user: str = "og_reader"
    db_reader_password: str = ""

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""

    http_contact: str = ""
    nvd_api_key: str = ""
    log_level: str = "INFO"

    def dsn(self, role: DbRole) -> str:
        """Connection string for one DB role. Callers pick the least privileged role they need."""
        user = getattr(self, f"db_{role}_user")
        password = getattr(self, f"db_{role}_password")
        return (
            f"postgresql://{user}:{password}@{self.postgres_host}:{self.postgres_port}"
            f"/{self.postgres_db}"
        )

    def __repr__(self) -> str:  # never leak secrets into logs
        return "Settings(<redacted>)"


class LicensePolicy(BaseModel):
    """Which licenses may enter the pipeline (decisions of 2026-10-09, see docs/sources/SOURCES.md).

    The project is NOT restricted to non-commercial use, so KOGL types with a
    commercial-use ban (2, 4) are excluded. Types 3/4 forbid derivative works: collected text may
    be stored and quoted, but LLM rewrites of it must not be published.
    """

    kogl_collectable_types: list[int] = Field(default_factory=lambda: [0, 1, 3])
    kogl_no_published_rewrite_types: list[int] = Field(default_factory=lambda: [3, 4])
    blocked_spdx: list[str] = Field(default_factory=lambda: ["CC-BY-SA-4.0"])

    def kogl_collectable(self, kogl_type: int) -> bool:
        return kogl_type in self.kogl_collectable_types

    def kogl_rewrite_publishable(self, kogl_type: int) -> bool:
        return kogl_type not in self.kogl_no_published_rewrite_types

    def spdx_allowed(self, spdx_id: str) -> bool:
        return spdx_id not in self.blocked_spdx


class ApprovedSource(BaseModel):
    id: str
    status: Literal["approved", "conditional"]
    conditions: list[str] = Field(default_factory=list)
    min_interval_seconds: float = 2.0
    allow_url_prefixes: list[str] = Field(default_factory=list)   # empty = no URL restriction
    deny_url_prefixes: list[str] = Field(default_factory=list)    # deny wins over allow
    exclude_ecosystems: list[str] = Field(default_factory=list)   # e.g. OSV ecosystems

    def url_allowed(self, url: str) -> bool:
        if any(url.startswith(p) for p in self.deny_url_prefixes):
            return False
        if not self.allow_url_prefixes:
            return True
        return any(url.startswith(p) for p in self.allow_url_prefixes)

    @model_validator(mode="after")
    def _conditional_needs_conditions(self) -> ApprovedSource:
        if self.status == "conditional" and not self.conditions:
            raise ValueError(f"source {self.id}: conditional status requires listed conditions")
        return self


class SourcesConfig(BaseModel):
    license_policy: LicensePolicy = Field(default_factory=LicensePolicy)
    sources: list[ApprovedSource] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> SourcesConfig:
        ids = [s.id for s in self.sources]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate source ids in sources.yaml")
        return self

    def get(self, source_id: str) -> ApprovedSource:
        for s in self.sources:
            if s.id == source_id:
                return s
        raise KeyError(f"source {source_id!r} is not approved (see docs/sources/SOURCES.md)")


class HttpSettings(BaseModel):
    min_interval_seconds: dict[str, float] = Field(default_factory=lambda: {"default": 2.0})
    timeout_seconds: float = 30
    max_retries: int = 4
    respect_robots_txt: bool = True
    cache_dir: str = "data/http_cache"
    cache_ttl_seconds: int = 86400


class AppConfig(BaseModel):
    http: HttpSettings = Field(default_factory=HttpSettings)


class ModelEndpoint(BaseModel):
    provider: Literal["local", "api"] = "local"
    endpoint: str | None = None
    model: str | None = None
    temperature: float | None = None


class ModelsConfig(BaseModel):
    allow_external: bool = False
    embedding: ModelEndpoint = Field(default_factory=ModelEndpoint)
    llm: ModelEndpoint = Field(default_factory=ModelEndpoint)

    @model_validator(mode="after")
    def _external_requires_opt_in(self) -> ModelsConfig:
        for name in ("embedding", "llm"):
            if getattr(self, name).provider == "api" and not self.allow_external:
                raise ValueError(
                    f"{name}.provider=api requires allow_external: true (air-gap default is local)"
                )
        return self


def _load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_sources(path: Path | None = None) -> SourcesConfig:
    return SourcesConfig.model_validate(_load_yaml(path or CONFIG_DIR / "sources.yaml"))


def load_app_config(path: Path | None = None) -> AppConfig:
    return AppConfig.model_validate(_load_yaml(path or CONFIG_DIR / "settings.yaml"))


def load_models(path: Path | None = None) -> ModelsConfig:
    return ModelsConfig.model_validate(_load_yaml(path or CONFIG_DIR / "models.yaml"))


@lru_cache
def get_settings() -> Settings:
    return Settings()
