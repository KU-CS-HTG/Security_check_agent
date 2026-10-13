import httpx
import pytest

from opsgraph.config import HttpSettings
from opsgraph.http import FetchError, HttpClient, RobotsDisallowed


class Clock:
    """Fake time: sleep() advances the clock, so throttling is testable without waiting."""

    def __init__(self):
        self.t = 1000.0
        self.sleeps: list[float] = []

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s

    def now(self):
        return self.t


def make(handler, tmp_path=None, **cfg):
    clock = Clock()
    settings = HttpSettings(
        min_interval_seconds=cfg.pop("min_interval_seconds", {"default": 2.0}),
        max_retries=cfg.pop("max_retries", 2),
        respect_robots_txt=cfg.pop("respect_robots_txt", False),
        **cfg,
    )
    client = HttpClient(
        settings,
        "me@example.com",
        cache_dir=tmp_path,
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        clock=clock.now,
        wall_clock=clock.now,
    )
    return client, clock


def test_contact_is_required():
    with pytest.raises(ValueError):
        HttpClient(HttpSettings(), "  ")


def test_user_agent_carries_contact():
    seen = {}

    def h(req):
        seen["ua"] = req.headers["user-agent"]
        return httpx.Response(200, text="ok")

    client, _ = make(h)
    client.get("https://a.example/x")
    assert "me@example.com" in seen["ua"] and seen["ua"].startswith("opsgraph/")


def test_per_host_min_interval():
    client, clock = make(lambda r: httpx.Response(200, text="ok"))
    client.get("https://a.example/1")
    client.get("https://a.example/2")
    client.get("https://b.example/1")  # other host: no wait
    assert clock.sleeps == [2.0]


def test_retry_after_is_honoured_and_then_succeeds():
    calls = {"n": 0}

    def h(req):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "7"})
        return httpx.Response(200, text="fine")

    client, clock = make(h)
    res = client.get("https://a.example/x")
    assert res.status == 200 and res.text == "fine"
    assert 7.0 in clock.sleeps


def test_gives_up_after_max_retries():
    client, _ = make(lambda r: httpx.Response(503), max_retries=2)
    with pytest.raises(FetchError):
        client.get("https://a.example/x")


def test_client_error_is_returned_not_retried():
    calls = {"n": 0}

    def h(req):
        calls["n"] += 1
        return httpx.Response(404)

    client, _ = make(h)
    assert client.get("https://a.example/x").status == 404
    assert calls["n"] == 1


def robots_handler(robots_text, status=200):
    def h(req):
        if req.url.path == "/robots.txt":
            return httpx.Response(status, text=robots_text)
        return httpx.Response(200, text="page")

    return h


def test_robots_disallow_blocks_request():
    robots = "User-agent: *\nDisallow: /docs/devel/\n"
    client, _ = make(robots_handler(robots), respect_robots_txt=True)
    assert client.get("https://a.example/docs/16/").status == 200
    with pytest.raises(RobotsDisallowed):
        client.get("https://a.example/docs/devel/x")


def test_html_instead_of_robots_means_no_rules():
    client, _ = make(robots_handler("<!doctype html><html></html>"), respect_robots_txt=True)
    assert client.get("https://a.example/anything").status == 200


def test_missing_robots_means_allowed():
    client, _ = make(robots_handler("", status=404), respect_robots_txt=True)
    assert client.get("https://a.example/anything").status == 200


def test_crawl_delay_raises_interval():
    client, clock = make(
        robots_handler("User-agent: *\nCrawl-delay: 10\n"),
        respect_robots_txt=True,
        min_interval_seconds={"default": 1.0},
    )
    client.get("https://a.example/1")
    client.get("https://a.example/2")
    assert max(clock.sleeps) >= 9.0  # waited for the Crawl-delay, not just the 1s default


def test_exempt_host_skips_robots():
    seen = []

    def h(req):
        seen.append(req.url.path)
        return httpx.Response(200, text="zip")

    client, _ = make(h, respect_robots_txt=True, robots_exempt_hosts=["a.example"])
    client.get("https://a.example/data")
    assert seen == ["/data"]


def test_cache_fresh_then_conditional_revalidation(tmp_path):
    seen = []

    def h(req):
        seen.append(req.headers.get("if-none-match"))
        if req.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, text="body-v1", headers={"etag": '"v1"'})

    client, clock = make(h, tmp_path, cache_ttl_seconds=100)
    assert client.get("https://a.example/x").text == "body-v1"
    again = client.get("https://a.example/x")  # fresh: no network
    assert again.from_cache and seen == [None]
    clock.t += 500  # stale -> conditional request, 304 -> cached body
    revalidated = client.get("https://a.example/x")
    assert revalidated.from_cache and revalidated.text == "body-v1"
    assert seen == [None, '"v1"']
    forced = client.get("https://a.example/x", ttl=0)  # ttl=0 always revalidates
    assert forced.text == "body-v1" and seen[-1] == '"v1"'


def test_download_streams_then_304(tmp_path):
    def h(req):
        if req.headers.get("if-none-match") == '"z1"':
            return httpx.Response(304)
        return httpx.Response(200, content=b"x" * 5000, headers={"etag": '"z1"'})

    client, _ = make(h, tmp_path)
    dest = tmp_path / "dl" / "all.zip"
    r1 = client.download("https://a.example/all.zip", dest)
    assert r1.changed and dest.stat().st_size == 5000
    r2 = client.download("https://a.example/all.zip", dest)
    assert not r2.changed and dest.stat().st_size == 5000


def test_download_size_limit(tmp_path):
    client, _ = make(
        lambda r: httpx.Response(200, content=b"x" * (2 * 1024 * 1024)), tmp_path, max_download_mb=1
    )
    with pytest.raises(FetchError):
        client.download("https://a.example/big", tmp_path / "big")
    assert not (tmp_path / "big").exists()
    assert not (tmp_path / "big.part").exists()  # partial file is cleaned up
