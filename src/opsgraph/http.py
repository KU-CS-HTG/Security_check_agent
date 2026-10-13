"""Polite HTTP client for the collection stage (the only stage that needs the internet).

- identifying User-Agent with a contact address (required)
- per-host minimum interval (raised to robots.txt Crawl-delay when larger)
- robots.txt enforcement (except explicitly exempted official bulk-data hosts)
- retries with exponential backoff, honouring Retry-After
- on-disk cache with ETag / Last-Modified revalidation
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.robotparser
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from opsgraph import __version__
from opsgraph.config import HttpSettings
from opsgraph.logging import get_logger

log = get_logger(__name__)

RETRY_STATUS = {429, 500, 502, 503, 504}


class RobotsDisallowed(Exception):
    pass


class FetchError(Exception):
    pass


@dataclass
class FetchResult:
    url: str
    status: int
    content: bytes
    headers: dict[str, str] = field(default_factory=dict)
    from_cache: bool = False

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.content)


@dataclass
class DownloadResult:
    path: Path
    changed: bool  # False when the server answered 304 and the file is unchanged


class HttpClient:
    def __init__(
        self,
        cfg: HttpSettings,
        contact: str,
        *,
        cache_dir: Path | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if not contact.strip():
            raise ValueError("HTTP_CONTACT must be set: every request carries a contact address")
        self.cfg = cfg
        self.user_agent = f"opsgraph/{__version__} (+contact: {contact.strip()})"
        self.cache_dir = cache_dir
        if cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)
        self._client = httpx.Client(
            transport=transport,
            follow_redirects=True,
            timeout=cfg.timeout_seconds,
            headers={"User-Agent": self.user_agent},
        )
        self._sleep, self._clock, self._wall = sleep, clock, wall_clock
        self._last_request: dict[str, float] = {}
        self._robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}

    # ---- politeness -------------------------------------------------------------------------
    def _interval(self, host: str, override: float | None) -> float:
        base = self.cfg.min_interval_seconds
        configured = base.get(host, base.get("default", 1.0))
        return max(configured, override or 0.0)

    def _throttle(self, host: str, interval: float) -> None:
        last = self._last_request.get(host)
        if last is not None:
            wait = interval - (self._clock() - last)
            if wait > 0:
                self._sleep(wait)
        self._last_request[host] = self._clock()

    def _robots_for(self, url: str) -> urllib.robotparser.RobotFileParser | None:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin in self._robots:
            return self._robots[origin]
        rp: urllib.robotparser.RobotFileParser | None = urllib.robotparser.RobotFileParser()
        try:
            res = self._request("GET", f"{origin}/robots.txt", check_robots=False)
        except FetchError:
            log.warning("robots_unreachable_assume_disallow", origin=origin)
            self._robots[origin] = rp
            rp.disallow_all = True
            return rp
        text = res.text
        if res.status in (404, 410) or text.lstrip()[:1] == "<":
            # missing, or an HTML page served in place of robots.txt: no usable rules
            log.info("robots_no_rules", origin=origin, status=res.status)
            rp = None
        else:
            rp.parse(text.splitlines())
        self._robots[origin] = rp
        return rp

    def _check_robots(self, url: str, host: str) -> float | None:
        if not self.cfg.respect_robots_txt or host in self.cfg.robots_exempt_hosts:
            return None
        rp = self._robots_for(url)
        if rp is None:
            return None
        if not rp.can_fetch(self.user_agent, url):
            raise RobotsDisallowed(f"robots.txt of {host} disallows {url}")
        delay = rp.crawl_delay(self.user_agent)
        return float(delay) if delay else None

    # ---- low level --------------------------------------------------------------------------
    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        if retry_after and retry_after.isdigit():
            return min(float(retry_after), 300.0)
        return min(2.0**attempt, 60.0)

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        min_interval: float | None = None,
        check_robots: bool = True,
    ) -> FetchResult:
        host = urlsplit(url).netloc
        crawl_delay = self._check_robots(url, host) if check_robots else None
        interval = self._interval(host, max(min_interval or 0.0, crawl_delay or 0.0))
        last_err: Exception | None = None
        for attempt in range(self.cfg.max_retries + 1):
            self._throttle(host, interval)
            try:
                r = self._client.request(method, url, headers=headers)
            except httpx.TransportError as e:
                last_err = e
                log.warning("http_transport_error", url=url, attempt=attempt, error=str(e))
                self._sleep(self._backoff(attempt, None))
                continue
            if r.status_code in RETRY_STATUS:
                last_err = FetchError(f"HTTP {r.status_code} for {url}")
                log.warning("http_retry", url=url, status=r.status_code, attempt=attempt)
                self._sleep(self._backoff(attempt, r.headers.get("retry-after")))
                continue
            return FetchResult(url, r.status_code, r.content, dict(r.headers))
        raise FetchError(
            f"giving up on {url} after {self.cfg.max_retries + 1} attempts: {last_err}"
        )

    # ---- cache ------------------------------------------------------------------------------
    def _cache_paths(self, url: str) -> tuple[Path, Path] | None:
        if not self.cache_dir:
            return None
        key = hashlib.sha256(url.encode()).hexdigest()
        return self.cache_dir / f"{key}.meta.json", self.cache_dir / f"{key}.body"

    def get(
        self,
        url: str,
        *,
        ttl: int | None = None,
        min_interval: float | None = None,
    ) -> FetchResult:
        """GET with disk cache. ttl=0 always revalidates (conditional request) but still reuses
        the cached body on 304. Non-2xx responses are returned to the caller, never cached."""
        ttl = self.cfg.cache_ttl_seconds if ttl is None else ttl
        paths = self._cache_paths(url)
        headers: dict[str, str] = {}
        meta: dict = {}
        if paths and paths[0].exists() and paths[1].exists():
            meta = json.loads(paths[0].read_text())
            age = self._wall() - meta["fetched_at"]
            if age < ttl:
                body = paths[1].read_bytes()
                return FetchResult(url, meta["status"], body, meta["headers"], True)
            if meta.get("etag"):
                headers["If-None-Match"] = meta["etag"]
            if meta.get("last_modified"):
                headers["If-Modified-Since"] = meta["last_modified"]
        res = self._request("GET", url, headers=headers, min_interval=min_interval)
        if res.status == 304 and paths and meta:
            meta["fetched_at"] = self._wall()
            paths[0].write_text(json.dumps(meta))
            return FetchResult(url, meta["status"], paths[1].read_bytes(), meta["headers"], True)
        if paths and 200 <= res.status < 300:
            hdr = {k.lower(): v for k, v in res.headers.items()}
            paths[1].write_bytes(res.content)
            paths[0].write_text(json.dumps({
                "status": res.status,
                "fetched_at": self._wall(),
                "etag": hdr.get("etag"),
                "last_modified": hdr.get("last-modified"),
                "headers": {k: hdr[k] for k in ("content-type",) if k in hdr},
            }))
        return res

    def download(
        self, url: str, dest: Path, *, min_interval: float | None = None
    ) -> DownloadResult:
        """Stream a large file to `dest`, revalidating with ETag so unchanged files are not
        fetched again. A sidecar `<dest>.meta.json` keeps the validators."""
        host = urlsplit(url).netloc
        crawl_delay = self._check_robots(url, host)
        interval = self._interval(host, max(min_interval or 0.0, crawl_delay or 0.0))
        meta_path = dest.with_name(dest.name + ".meta.json")
        headers: dict[str, str] = {}
        if dest.exists() and meta_path.exists():
            meta = json.loads(meta_path.read_text())
            if meta.get("etag"):
                headers["If-None-Match"] = meta["etag"]
        limit = self.cfg.max_download_mb * 1024 * 1024
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".part")
        last_err: Exception | None = None
        for attempt in range(self.cfg.max_retries + 1):
            self._throttle(host, interval)
            try:
                with self._client.stream("GET", url, headers=headers) as r:
                    if r.status_code == 304:
                        return DownloadResult(dest, changed=False)
                    if r.status_code in RETRY_STATUS:
                        last_err = FetchError(f"HTTP {r.status_code} for {url}")
                        self._sleep(self._backoff(attempt, r.headers.get("retry-after")))
                        continue
                    r.raise_for_status()
                    size = 0
                    with tmp.open("wb") as f:
                        for chunk in r.iter_bytes(1 << 20):
                            size += len(chunk)
                            if size > limit:
                                raise FetchError(
                                    f"{url} exceeds max_download_mb={self.cfg.max_download_mb}"
                                )
                            f.write(chunk)
                    tmp.replace(dest)
                    meta_path.write_text(json.dumps({"etag": r.headers.get("etag"), "url": url}))
                    return DownloadResult(dest, changed=True)
            except FetchError:
                tmp.unlink(missing_ok=True)
                raise
            except httpx.TransportError as e:
                last_err = e
                self._sleep(self._backoff(attempt, None))
            except httpx.HTTPStatusError as e:
                raise FetchError(f"HTTP {e.response.status_code} for {url}") from e
        raise FetchError(f"giving up on {url}: {last_err}")

    def close(self) -> None:
        self._client.close()
