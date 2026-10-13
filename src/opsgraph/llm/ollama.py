"""Local LLM client (Ollama HTTP API). No third-party SDK; only the local endpoint is called.

`chat_json` sends a JSON Schema in `format` (constrained decoding), temperature 0 and a fixed
seed, so the same clause gives the same answer. Only loopback/private addresses are accepted unless
`allow_external` is set in config/models.yaml (air-gap default).
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from opsgraph.config import ModelEndpoint, ModelsConfig
from opsgraph.logging import get_logger

log = get_logger(__name__)


class LlmError(Exception):
    pass


@dataclass
class LlmResponse:
    content: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    duration_ms: int = 0


def _is_local(host: str | None) -> bool:
    if not host:
        return False
    if host in ("localhost", "host.docker.internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


class OllamaClient:
    def __init__(self, endpoint: str, model: str, *, temperature: float = 0.0, num_ctx: int = 8192,
                 timeout: float = 300.0, allow_external: bool = False, seed: int = 0,
                 transport: httpx.BaseTransport | None = None) -> None:
        host = urlsplit(endpoint).hostname
        if not allow_external and not _is_local(host):
            raise LlmError(f"LLM endpoint {endpoint!r} is not a local address "
                           "(air-gap default; set allow_external: true to override)")
        self.endpoint = endpoint.rstrip("/")
        self.model, self.temperature, self.num_ctx, self.seed = model, temperature, num_ctx, seed
        self._http = httpx.Client(timeout=timeout, transport=transport)

    def list_models(self) -> list[str]:
        try:
            r = self._http.get(f"{self.endpoint}/api/tags")
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise LlmError(f"cannot reach Ollama at {self.endpoint}: {e}") from e
        return [m["name"] for m in r.json().get("models", [])]

    def chat_json(self, messages: list[dict], schema: dict) -> LlmResponse:
        body = {
            "model": self.model, "messages": messages, "stream": False, "format": schema,
            "options": {"temperature": self.temperature, "num_ctx": self.num_ctx,
                        "seed": self.seed},
        }
        started = time.monotonic()
        try:
            r = self._http.post(f"{self.endpoint}/api/chat", json=body)
        except httpx.HTTPError as e:
            raise LlmError(f"Ollama request failed: {type(e).__name__}: {e}") from e
        if r.status_code != 200:
            raise LlmError(f"Ollama returned HTTP {r.status_code}: {r.text[:300]}")
        data = r.json()
        content = (data.get("message") or {}).get("content")
        if content is None:
            raise LlmError(f"unexpected Ollama response: {str(data)[:300]}")
        return LlmResponse(
            content=content, prompt_tokens=int(data.get("prompt_eval_count") or 0),
            completion_tokens=int(data.get("eval_count") or 0),
            duration_ms=int((time.monotonic() - started) * 1000))

    def close(self) -> None:
        self._http.close()


def build_client(cfg: ModelsConfig, endpoint_cfg: ModelEndpoint | None = None,
                 transport: httpx.BaseTransport | None = None) -> OllamaClient:
    llm = endpoint_cfg or cfg.llm
    if llm.provider != "local":
        raise LlmError("only provider 'local' (Ollama) is implemented")
    if not llm.endpoint or not llm.model:
        raise LlmError("config/models.yaml: llm.endpoint and llm.model must be set")
    return OllamaClient(llm.endpoint, llm.model, temperature=llm.temperature or 0.0,
                        num_ctx=llm.num_ctx, timeout=llm.timeout_seconds,
                        allow_external=cfg.allow_external, transport=transport)
