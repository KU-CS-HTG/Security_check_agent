"""Structured output of the extraction step.

The JSON Schema handed to the model is written by hand and kept flat (no $ref, no null unions;
"" and "not_stated" mean "absent") because constrained decoding in local runtimes supports only
a subset of JSON Schema. The model's answer is validated again with pydantic.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "2"

CATEGORIES = (
    "account_management",    # roles, passwords, privileges of accounts
    "authentication",        # how clients prove identity (pg_hba.conf, methods)
    "access_control",        # object privileges, row security, schemas
    "network_connection",    # listening addresses, ports, connection limits
    "encryption",            # TLS, password hashing, encryption options
    "logging_audit",         # what is logged, log files, rotation
    "backup_recovery",       # dumps, archiving, restore
    "configuration",         # other server settings with operational effect
    "file_permission",       # file/directory ownership and modes, OS account
    "maintenance_operations",  # start/stop, vacuum, upgrades
    "other",
)
RISK_LEVELS = ("high", "medium", "low", "not_stated")

Category = Literal[
    "account_management", "authentication", "access_control", "network_connection", "encryption",
    "logging_audit", "backup_recovery", "configuration", "file_permission",
    "maintenance_operations", "other",
]
Risk = Literal["high", "medium", "low", "not_stated"]


class CheckItemDraft(BaseModel):
    title: str = Field(min_length=5, max_length=160)
    category: Category
    target: str = Field(min_length=1, max_length=120)
    check_method: str = Field(default="", max_length=400)
    recommended_value: str = Field(default="", max_length=300)
    remediation: str = Field(default="", max_length=600)
    risk_level: Risk = "not_stated"
    evidence_quote: str = Field(min_length=20, max_length=600)
    remediation_quote: str = Field(default="", max_length=600)
    risk_quote: str = Field(default="", max_length=600)

    @field_validator("*", mode="before")
    @classmethod
    def _strip(cls, v):
        return v.strip() if isinstance(v, str) else v


class ExtractionResult(BaseModel):
    items: list[CheckItemDraft] = Field(max_length=12)


def _str(max_len: int, description: str = "") -> dict:
    return {"type": "string", "maxLength": max_len, "description": description}


def json_schema() -> dict:
    """Flat JSON Schema for constrained decoding (mirrors ExtractionResult)."""
    item = {
        "type": "object",
        "properties": {
            "title": _str(160, "short name of what to check"),
            "category": {"type": "string", "enum": list(CATEGORIES)},
            "target": _str(120, "the setting, file, role or object concerned"),
            "check_method": _str(400, "how to verify it, only if the clause says so, else empty"),
            "recommended_value": _str(300, "recommended value or behaviour, else empty"),
            "remediation": _str(600, "how to fix or configure it per the clause, else empty"),
            "risk_level": {"type": "string", "enum": list(RISK_LEVELS)},
            "evidence_quote": _str(600, "exact copy of 1-2 consecutive sentences of the clause"),
            "remediation_quote": _str(600, "exact copy supporting the remediation, else empty"),
            "risk_quote": _str(600, "exact copy of the sentence stating the risk, else empty"),
        },
        "required": ["title", "category", "target", "check_method", "recommended_value",
                     "remediation", "risk_level", "evidence_quote", "remediation_quote",
                     "risk_quote"],
    }
    return {"type": "object",
            "properties": {"items": {"type": "array", "items": item, "maxItems": 12}},
            "required": ["items"]}
