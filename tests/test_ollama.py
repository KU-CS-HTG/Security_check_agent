import json

import httpx
import pytest

from opsgraph.config import ModelsConfig
from opsgraph.extract.schema import json_schema
from opsgraph.llm.ollama import LlmError, OllamaClient, build_client

URL = "http://localhost:11434"


def client(handler, **kw):
    return OllamaClient(URL, "qwen2.5:7b-instruct", transport=httpx.MockTransport(handler), **kw)


def test_chat_json_sends_schema_and_deterministic_options():
    seen = {}

    def handler(req: httpx.Request):
        seen["url"], seen["body"] = str(req.url), json.loads(req.content)
        message = {"role": "assistant", "content": '{"items": []}'}
        return httpx.Response(200, json={"message": message, "prompt_eval_count": 321,
                                         "eval_count": 12})

    res = client(handler).chat_json([{"role": "user", "content": "hi"}], json_schema())
    assert seen["url"] == f"{URL}/api/chat"
    body = seen["body"]
    assert body["model"] == "qwen2.5:7b-instruct" and body["stream"] is False
    assert body["format"] == json_schema()
    assert body["options"] == {"temperature": 0.0, "num_ctx": 8192, "seed": 0}
    assert (res.content, res.prompt_tokens, res.completion_tokens) == ('{"items": []}', 321, 12)


def test_http_errors_and_garbage_become_llm_errors():
    with pytest.raises(LlmError, match="HTTP 500"):
        client(lambda r: httpx.Response(500, text="boom")).chat_json([], {})
    with pytest.raises(LlmError, match="unexpected"):
        client(lambda r: httpx.Response(200, json={"nope": 1})).chat_json([], {})

    def refuse(req):
        raise httpx.ConnectError("refused")

    with pytest.raises(LlmError, match="request failed"):
        client(refuse).chat_json([], {})


def test_list_models():
    c = client(lambda r: httpx.Response(200, json={"models": [{"name": "qwen2.5:7b-instruct"}]}))
    assert c.list_models() == ["qwen2.5:7b-instruct"]
    with pytest.raises(LlmError, match="cannot reach"):
        client(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x"))).list_models()


@pytest.mark.parametrize("endpoint", ["http://localhost:11434", "http://127.0.0.1:11434",
                                      "http://192.168.0.5:11434", "http://[::1]:11434",
                                      "http://host.docker.internal:11434"])
def test_local_endpoints_are_accepted(endpoint):
    OllamaClient(endpoint, "m")


@pytest.mark.parametrize("endpoint", ["https://api.example.com", "http://8.8.8.8:11434",
                                      "http://llm.example.org"])
def test_non_local_endpoints_are_refused_unless_allowed(endpoint):
    with pytest.raises(LlmError, match="not a local address"):
        OllamaClient(endpoint, "m")
    OllamaClient(endpoint, "m", allow_external=True)


def test_build_client_follows_models_yaml():
    cfg = ModelsConfig.model_validate({"llm": {"endpoint": URL, "model": "qwen2.5:7b-instruct",
                                               "num_ctx": 4096, "temperature": 0.0}})
    c = build_client(cfg)
    assert c.model == "qwen2.5:7b-instruct" and c.num_ctx == 4096
    with pytest.raises(LlmError, match="must be set"):
        build_client(ModelsConfig.model_validate({"llm": {"endpoint": URL}}))
