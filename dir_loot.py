#!/usr/bin/env python3
"""
dir_loot.py - Automated browsable directory secret scanner.
For authorized penetration testing engagements only.

Parses Nessus output for browsable web directories, recursively mirrors
their contents, and scans downloaded files for secrets and sensitive data.

Supports input from:
  - Nessus XML (.nessus)
  - Nessus CSV export
  - Plain text file (one URL per line)

Usage:
  python3 dir_loot.py -i results.nessus -o ./loot
  python3 dir_loot.py -i urls.txt -o ./loot --threads 30 --depth 15
  python3 dir_loot.py -i results.csv -o ./loot --proxy http://127.0.0.1:8080
"""

import argparse
import csv
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse, unquote

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] 'requests' library required: pip3 install requests")
    sys.exit(1)


# ── Defaults ─────────────────────────────────────────────────────────────────

DEFAULT_THREADS = 20
DEFAULT_DEPTH = 10
DEFAULT_TIMEOUT = 15
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

NESSUS_DIR_PLUGINS = {"11032", "40984"}


# ── Secret Detection Patterns ────────────────────────────────────────────────

_PATTERNS = [
    # Cloud provider keys
    ("AWS Access Key ID",           r'AKIA[0-9A-Z]{16}',                                            "CRITICAL"),
    ("AWS Secret Access Key",       r'(?i)(?:aws.?secret.?access.?key|aws.?secret)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "CRITICAL"),
    ("Google API Key",              r'AIza[A-Za-z0-9_\-]{35}',                                      "HIGH"),
    ("Google OAuth Client ID",      r'\d+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com',          "MEDIUM"),
    ("Azure Storage Account Key",   r'(?i)(?:AccountKey|DefaultEndpointsProtocol)[=;][^\s"\'<]{20,}', "HIGH"),

    # Private keys
    ("Private Key",                 r'-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?:\sBLOCK)?-----', "CRITICAL"),

    # Platform tokens
    ("GitHub Token",                r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',                 "CRITICAL"),
    ("GitLab Token",                r'glpat-[A-Za-z0-9_\-]{20,}',                                  "CRITICAL"),
    ("Slack Token",                 r'xox[baprs]-[A-Za-z0-9\-]+',                                  "HIGH"),
    ("Slack Webhook",               r'hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', "HIGH"),
    ("Discord Webhook",            r'discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+',       "HIGH"),
    ("Stripe Key",                  r'[sr]k_(?:test|live)_[A-Za-z0-9]{20,}',                       "CRITICAL"),
    ("SendGrid Key",                r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',                "CRITICAL"),
    ("Twilio API Key",              r'SK[a-f0-9]{32}',                                              "HIGH"),
    ("Mailgun API Key",             r'key-[A-Za-z0-9]{32}',                                         "HIGH"),
    ("Square Access Token",         r'sq0[a-z]{3}-[A-Za-z0-9_\-]{22,}',                            "HIGH"),
    ("NPM Token",                   r'npm_[A-Za-z0-9]{36}',                                        "HIGH"),
    ("Dynatrace Token",             r'dt0[a-zA-Z]\d{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}',              "HIGH"),
    ("HashiCorp Vault Token",       r'(?:hvs|s)\.[A-Za-z0-9]{24,}',                                "HIGH"),
    ("Heroku API Key",              r'(?i)heroku.{0,20}[=:]\s*["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "HIGH"),

    # Connection strings
    ("Database Connection String",  r'(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|mssql|redis|amqp)://[^\s"\'<>]+', "CRITICAL"),
    ("JDBC Connection String",      r'jdbc:[a-z:]+//[^\s"\'<>]+',                                  "HIGH"),
    ("Basic Auth in URL",           r'https?://[^/\s:]+:[^@/\s]+@[^\s"\'<>]+',                    "CRITICAL"),

    # JWT
    ("JWT Token",                   r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+', "MEDIUM"),

    # Credential patterns
    ("Password Assignment",         r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^\s"\']{8,})["\']', "HIGH"),
    ("Secret/Token Assignment",     r'(?i)(?:secret|token|api_?key|auth_?key|access_?token|client_?secret|private_?key|encryption_?key|signing_?key)\s*[=:]\s*["\']([^\s"\']{8,})["\']', "HIGH"),
    ("Environment Variable Secret", r'(?i)(?:export\s+)?(?:DB_PASS(?:WORD)?|DATABASE_URL|SECRET_KEY|DJANGO_SECRET|FLASK_SECRET|SESSION_SECRET|ENCRYPTION_KEY|AUTH_TOKEN|PRIVATE_KEY)\s*=\s*["\']?([^\s"\']{8,})', "HIGH"),
    (".htpasswd Entry",             r'[A-Za-z0-9_.]+:\$(?:apr1|2[aby])\$[^\s]+',                   "CRITICAL"),
    ("Shadow File Entry",           r'[a-z_][a-z0-9_-]*:\$[156]\$[^\s:]+:[^\s:]*:',               "CRITICAL"),
]

SECRET_PATTERNS = [(name, re.compile(pattern), severity) for name, pattern, severity in _PATTERNS]


# ── Interesting File Indicators ──────────────────────────────────────────────

INTERESTING_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    ".env.backup", ".env.bak", ".env.old",
    ".htpasswd", ".htaccess", "web.config",
    "wp-config.php", "configuration.php", "config.php", "settings.php",
    "local_settings.py", "settings.py", "config.py",
    "database.yml", "secrets.yml", "credentials.yml", "master.key",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".pgpass", ".netrc", ".npmrc", ".pypirc", ".dockercfg",
    "shadow", "passwd", "htpasswd",
    "phpinfo.php", "info.php", "test.php",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".gitconfig",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "server.xml", "context.xml", "tomcat-users.xml",
    "ansible.cfg", "vault.yml",
    "terraform.tfvars", "terraform.tfstate",
    "appsettings.json", "appsettings.Development.json",
    "ConnectionStrings.config",
}

INTERESTING_EXTENSIONS = {
    ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo", ".tmp",
    ".sql", ".sqlite", ".sqlite3", ".db", ".mdb", ".accdb",
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".cer", ".crt",
    ".conf", ".cfg", ".ini", ".config", ".properties",
    ".env",
    ".log",
    ".pcap", ".cap",
    ".kdbx", ".kdb",
}

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp", ".avif",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flv", ".webm", ".ogg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".exe", ".dll", ".so", ".dylib",
    ".class", ".pyc", ".pyo",
}


# ── Input Parsing ────────────────────────────────────────────────────────────

def parse_input(filepath):
    ext = Path(filepath).suffix.lower()
    if ext == ".nessus":
        return parse_nessus_xml(filepath)
    elif ext == ".csv":
        return parse_nessus_csv(filepath)
    else:
        return parse_url_list(filepath)


def parse_nessus_xml(filepath):
    urls = set()
    tree = ET.parse(filepath)
    root = tree.getroot()

    for item in root.iter("ReportItem"):
        plugin_id = item.get("pluginID", "")
        plugin_name = item.get("pluginName", "").lower()

        is_dir_plugin = (
            plugin_id in NESSUS_DIR_PLUGINS
            or "browsable" in plugin_name
            or "directory listing" in plugin_name
        )
        if not is_dir_plugin:
            continue

        output_el = item.find("plugin_output")
        if output_el is None or not output_el.text:
            continue

        for url in _extract_urls(output_el.text):
            urls.add(_normalize_dir_url(url))

    return sorted(urls)


def parse_nessus_csv(filepath):
    urls = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        headers = {h.lower().strip(): h for h in (reader.fieldnames or [])}

        pid_col = headers.get("plugin id") or headers.get("pluginid") or headers.get("plugin_id")
        out_col = (
            headers.get("plugin output")
            or headers.get("pluginoutput")
            or headers.get("plugin_output")
            or headers.get("output")
        )

        if not pid_col or not out_col:
            print("[!] CSV columns not recognized. Trying as plain URL list.")
            f.seek(0)
            return parse_url_list(filepath)

        for row in reader:
            plugin_id = row.get(pid_col, "")
            if plugin_id not in NESSUS_DIR_PLUGINS:
                continue
            output = row.get(out_col, "")
            for url in _extract_urls(output):
                urls.add(_normalize_dir_url(url))

    return sorted(urls)


def parse_url_list(filepath):
    urls = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if re.match(r"https?://", line, re.I):
                    urls.add(_normalize_dir_url(line))
    return sorted(urls)


def _extract_urls(text):
    return re.findall(r"https?://[^\s<>\"']+", text)


def _normalize_dir_url(url):
    parsed = urlparse(url)
    path = parsed.path
    if not path.endswith("/"):
        if "." not in path.split("/")[-1]:
            path += "/"
    return parsed._replace(path=path, fragment="").geturl()


# ── HTML Link Extraction ─────────────────────────────────────────────────────

class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self.links.append(value)

    def error(self, message):
        pass


def extract_child_links(base_url, html):
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        return [], []

    parsed_base = urlparse(base_url)
    base_path = parsed_base.path
    if not base_path.endswith("/"):
        base_path += "/"

    dirs = []
    files = []

    for link in parser.links:
        if not link or link.startswith("?") or link.startswith("#"):
            continue
        if link in ("../", "/", ".", ".."):
            continue
        if link.startswith("/") and not link.startswith(base_path):
            continue

        resolved = urljoin(base_url, link)
        parsed = urlparse(resolved)

        if parsed.hostname != parsed_base.hostname:
            continue
        if parsed.port != parsed_base.port:
            continue
        if not parsed.path.startswith(base_path):
            continue
        if parsed.path == base_path:
            continue

        clean_url = parsed._replace(query="", fragment="").geturl()

        if parsed.path.endswith("/"):
            dirs.append(clean_url)
        else:
            files.append(clean_url)

    return dirs, files


# ── Thread-local Session ─────────────────────────────────────────────────────

_tls = threading.local()
_sess_cfg = {}


def _init_session_config(**kwargs):
    _sess_cfg.update(kwargs)


def _get_session():
    if not hasattr(_tls, "session"):
        s = requests.Session()
        s.verify = False
        s.headers["User-Agent"] = _sess_cfg.get("user_agent", DEFAULT_USER_AGENT)

        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503])
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=50, pool_connections=20)
        s.mount("http://", adapter)
        s.mount("https://", adapter)

        proxy = _sess_cfg.get("proxy")
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}

        cookies = _sess_cfg.get("cookies")
        if cookies:
            for k, v in cookies.items():
                s.cookies.set(k, v)

        auth = _sess_cfg.get("auth")
        if auth:
            s.auth = tuple(auth.split(":", 1))

        _tls.session = s
    return _tls.session


# ── Phase 1: Crawl ──────────────────────────────────────────────────────────

def _crawl_root(root_url, max_depth, timeout):
    session = _get_session()
    visited = set()
    found_files = []

    def _recurse(url, depth):
        if depth > max_depth or url in visited:
            return
        visited.add(url)

        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            if resp.status_code != 200:
                return
            ct = resp.headers.get("Content-Type", "")
            if "html" not in ct and "text/plain" not in ct:
                return
        except Exception:
            return

        dirs, files = extract_child_links(url, resp.text)
        found_files.extend(files)
        for d in dirs:
            _recurse(d, depth + 1)

    _recurse(root_url, 0)
    return found_files


def crawl_all(root_urls, max_depth, timeout, threads):
    all_files = []
    total = len(root_urls)
    completed = [0]
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_crawl_root, u, max_depth, timeout): u for u in root_urls}
        for future in as_completed(futures):
            with lock:
                completed[0] += 1
            try:
                files = future.result()
                with lock:
                    all_files.extend(files)
            except Exception:
                pass
            sys.stdout.write(
                f"\r  Crawled {completed[0]}/{total} directories ({len(all_files)} files found)"
            )
            sys.stdout.flush()
    print()

    seen = set()
    unique = []
    for f in all_files:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


# ── Phase 2: Download + Scan ─────────────────────────────────────────────────

def _is_text(data):
    if not data:
        return False
    if b"\x00" in data[:8192]:
        return False
    try:
        data[:8192].decode("utf-8")
        return True
    except UnicodeDecodeError:
        try:
            data[:8192].decode("latin-1")
            return True
        except Exception:
            return False


def _scan_text(text, file_url):
    findings = []
    for name, pattern, severity in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            start = max(0, match.start() - 60)
            end = min(len(text), match.end() + 60)
            context = text[start:end].strip()
            line_num = text[: match.start()].count("\n") + 1
            findings.append({
                "type": "secret",
                "pattern_name": name,
                "severity": severity,
                "url": file_url,
                "match": match.group(0)[:200],
                "context": context[:400],
                "line": line_num,
            })
    return findings


def _check_interesting(file_url):
    parsed = urlparse(file_url)
    path = unquote(parsed.path)
    filename = path.split("/")[-1].lower()
    reasons = []

    for name in INTERESTING_FILENAMES:
        if filename == name.lower() or path.lower().endswith("/" + name.lower()):
            reasons.append(f"Sensitive filename: {name}")

    for ext in INTERESTING_EXTENSIONS:
        if filename.endswith(ext.lower()):
            reasons.append(f"Sensitive extension: {ext}")
            break

    if re.search(r"\.(bak|backup|old|orig|save|copy)\b", filename, re.I):
        if not any("Backup" in r for r in reasons):
            reasons.append("Backup file")
    if filename.endswith("~"):
        reasons.append("Editor backup file")

    if "/.git/" in path or "/.svn/" in path or "/.hg/" in path:
        reasons.append("Source control artifact")

    return reasons


def _should_skip(file_url):
    path = unquote(urlparse(file_url).path).lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


def _sanitize_path(path):
    path = path.replace(":", "_").replace("?", "_").replace("*", "_")
    path = path.replace('"', "_").replace("<", "_").replace(">", "_").replace("|", "_")
    parts = path.split("/")
    parts = [p[:200] for p in parts]
    return "/".join(parts)


def _process_file(file_url, output_dir, max_size, timeout):
    findings = []

    interesting = _check_interesting(file_url)
    if interesting:
        findings.append({
            "type": "interesting_file",
            "severity": "MEDIUM",
            "url": file_url,
            "reasons": interesting,
        })

    if _should_skip(file_url):
        return findings

    session = _get_session()

    try:
        resp = session.get(file_url, timeout=timeout, stream=True)
        if resp.status_code != 200:
            return findings

        cl = resp.headers.get("Content-Length")
        if cl and int(cl) > max_size:
            if findings:
                findings[-1]["note"] = f"Too large ({int(cl)} bytes)"
            return findings

        chunks = []
        total_bytes = 0
        for chunk in resp.iter_content(chunk_size=65536):
            total_bytes += len(chunk)
            if total_bytes > max_size:
                break
            chunks.append(chunk)

        data = b"".join(chunks)

        parsed = urlparse(file_url)
        host = parsed.hostname
        if parsed.port and parsed.port not in (80, 443):
            host = f"{host}_{parsed.port}"

        rel_path = _sanitize_path(unquote(parsed.path).lstrip("/"))
        if not rel_path:
            rel_path = "index"

        save_path = os.path.join(output_dir, "downloads", host, rel_path)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(data)

        if _is_text(data):
            text = data.decode("utf-8", errors="replace")
            for sf in _scan_text(text, file_url):
                sf["local_path"] = save_path
                findings.append(sf)

    except Exception:
        pass

    return findings


def download_and_scan_all(file_urls, output_dir, max_size, timeout, threads):
    all_findings = []
    total = len(file_urls)
    completed = [0]
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(_process_file, u, output_dir, max_size, timeout): u
            for u in file_urls
        }
        for future in as_completed(futures):
            with lock:
                completed[0] += 1
            try:
                findings = future.result()
                if findings:
                    with lock:
                        all_findings.extend(findings)
            except Exception:
                pass

            if completed[0] % 50 == 0 or completed[0] == total:
                secrets = sum(1 for f in all_findings if f["type"] == "secret")
                interesting = sum(1 for f in all_findings if f["type"] == "interesting_file")
                sys.stdout.write(
                    f"\r  Files {completed[0]}/{total}"
                    f" | {secrets} secrets, {interesting} interesting files"
                )
                sys.stdout.flush()
    print()
    return all_findings


# ── TruffleHog Integration ───────────────────────────────────────────────────

def _find_trufflehog():
    return shutil.which("trufflehog")


def run_trufflehog(output_dir):
    binary = _find_trufflehog()
    if not binary:
        print("[!] trufflehog not found in PATH. Install: https://github.com/trufflesecurity/trufflehog")
        print("[!] Skipping trufflehog scan.")
        return []

    downloads_dir = os.path.join(output_dir, "downloads")
    if not os.path.isdir(downloads_dir):
        return []

    print(f"[*] Running trufflehog against {downloads_dir} ...")
    try:
        result = subprocess.run(
            [binary, "filesystem", "--json", "--no-update", downloads_dir],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        print("[!] trufflehog timed out after 10 minutes.")
        return []
    except Exception as e:
        print(f"[!] trufflehog failed: {e}")
        return []

    findings = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        detector = obj.get("DetectorName") or obj.get("detectorName") or "Unknown"
        raw = obj.get("Raw") or obj.get("raw") or ""
        verified = obj.get("Verified", obj.get("verified", False))

        source_meta = obj.get("SourceMetadata", obj.get("sourceMetadata", {}))
        data = source_meta.get("Data", source_meta.get("data", {}))
        filesystem = data.get("Filesystem", data.get("filesystem", {}))
        filepath = filesystem.get("file", "")

        file_url = _local_path_to_url(filepath, output_dir)

        severity = "CRITICAL" if verified else "HIGH"

        findings.append({
            "type": "secret",
            "pattern_name": f"trufflehog: {detector}",
            "severity": severity,
            "url": file_url,
            "match": raw[:200],
            "context": f"Verified: {verified}",
            "line": filesystem.get("line", 0),
            "local_path": filepath,
            "verified": verified,
        })

    verified_count = sum(1 for f in findings if f.get("verified"))
    print(f"[+] trufflehog found {len(findings)} results ({verified_count} verified)")
    return findings


def _local_path_to_url(filepath, output_dir):
    """Best-effort map of a downloaded file path back to its source URL."""
    downloads_prefix = os.path.join(output_dir, "downloads") + os.sep
    if filepath.startswith(downloads_prefix):
        rel = filepath[len(downloads_prefix):]
        parts = rel.split(os.sep, 1)
        if len(parts) == 2:
            host_part, path_part = parts
            host = host_part.replace("_", ":", 1) if "_" in host_part else host_part
            return f"http://{host}/{path_part}"
    return filepath


# ── Reporting ────────────────────────────────────────────────────────────────

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def generate_report(findings, output_dir, dir_count, file_count):
    findings.sort(key=lambda f: SEVERITY_RANK.get(f.get("severity", "INFO"), 99))

    json_path = os.path.join(output_dir, "findings.json")
    with open(json_path, "w") as f:
        json.dump(findings, f, indent=2, default=str)

    secrets = [fi for fi in findings if fi["type"] == "secret"]
    interesting = [fi for fi in findings if fi["type"] == "interesting_file"]
    by_severity = defaultdict(int)
    for fi in findings:
        by_severity[fi.get("severity", "INFO")] += 1

    by_host = defaultdict(list)
    for fi in findings:
        host = urlparse(fi["url"]).hostname or "unknown"
        by_host[host].append(fi)

    txt_path = os.path.join(output_dir, "findings.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 80 + "\n")
        f.write("  BROWSABLE DIRECTORY SECRET SCAN RESULTS\n")
        f.write(f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"  Directories crawled:  {dir_count}\n")
        f.write(f"  Files discovered:     {file_count}\n")
        f.write(f"  Secrets found:        {len(secrets)}\n")
        f.write(f"  Interesting files:    {len(interesting)}\n\n")

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if by_severity[sev]:
                f.write(f"    [{sev}]: {by_severity[sev]}\n")

        # Per-host summary
        f.write("\n" + "-" * 80 + "\n")
        f.write("  FINDINGS BY HOST\n")
        f.write("-" * 80 + "\n\n")
        for host in sorted(by_host):
            host_secrets = [x for x in by_host[host] if x["type"] == "secret"]
            host_interesting = [x for x in by_host[host] if x["type"] == "interesting_file"]
            f.write(f"  {host}: {len(host_secrets)} secrets, {len(host_interesting)} interesting files\n")

        # Secrets detail
        if secrets:
            f.write("\n" + "-" * 80 + "\n")
            f.write("  SECRET FINDINGS\n")
            f.write("-" * 80 + "\n\n")

            for i, finding in enumerate(secrets, 1):
                f.write(f"  [{finding['severity']}] #{i}: {finding['pattern_name']}\n")
                f.write(f"  URL:     {finding['url']}\n")
                f.write(f"  Line:    {finding.get('line', '?')}\n")
                f.write(f"  Match:   {finding['match']}\n")
                f.write(f"  Context: {finding['context']}\n")
                if "local_path" in finding:
                    f.write(f"  Saved:   {finding['local_path']}\n")
                f.write("\n")

        # Interesting files detail
        if interesting:
            f.write("\n" + "-" * 80 + "\n")
            f.write("  INTERESTING FILES\n")
            f.write("-" * 80 + "\n\n")

            for i, finding in enumerate(interesting, 1):
                f.write(f"  #{i}: {finding['url']}\n")
                for reason in finding.get("reasons", []):
                    f.write(f"       - {reason}\n")
                if "note" in finding:
                    f.write(f"       Note: {finding['note']}\n")
                f.write("\n")

        f.write("=" * 80 + "\n")
        f.write("  END OF REPORT\n")
        f.write("=" * 80 + "\n")

    return json_path, txt_path


def write_inventory(file_urls, output_dir):
    inv_path = os.path.join(output_dir, "file_inventory.csv")
    with open(inv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Host", "Path", "Filename", "Extension"])
        for url in sorted(file_urls):
            parsed = urlparse(url)
            path = unquote(parsed.path)
            filename = path.split("/")[-1] if "/" in path else path
            ext = ("." + filename.rsplit(".", 1)[1]) if "." in filename else ""
            host = parsed.hostname
            if parsed.port and parsed.port not in (80, 443):
                host = f"{host}:{parsed.port}"
            writer.writerow([url, host, path, filename, ext])
    return inv_path


# ── Main ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Scan browsable web directories for secrets and sensitive files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s -i scan.nessus -o ./loot\n"
            "  %(prog)s -i urls.txt -o ./loot --threads 30 --depth 15\n"
            "  %(prog)s -i scan.csv -o ./loot --proxy http://127.0.0.1:8080\n"
        ),
    )
    p.add_argument("-i", "--input", required=True,
                   help="Input: .nessus XML, .csv export, or text file of URLs")
    p.add_argument("-o", "--output", default="./loot",
                   help="Output directory (default: ./loot)")
    p.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                   help=f"Concurrent threads (default: {DEFAULT_THREADS})")
    p.add_argument("-d", "--depth", type=int, default=DEFAULT_DEPTH,
                   help=f"Max recursive crawl depth (default: {DEFAULT_DEPTH})")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--max-size", type=int, default=DEFAULT_MAX_FILE_SIZE,
                   help=f"Max file download size in bytes (default: {DEFAULT_MAX_FILE_SIZE})")
    p.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 for Burp")
    p.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="Custom User-Agent")
    p.add_argument("--cookie", action="append", default=[],
                   help="Cookie as name=value (repeatable)")
    p.add_argument("--auth", help="Basic auth as user:pass")
    p.add_argument("--crawl-only", action="store_true",
                   help="Crawl and inventory only; skip downloads and scanning")
    p.add_argument("--trufflehog", action="store_true",
                   help="Run trufflehog on downloaded files (requires trufflehog in PATH)")
    return p.parse_args()


def main():
    args = parse_args()

    print("""
    +-----------------------------------------+
    |  dir_loot.py                            |
    |  Browsable Directory Secret Scanner     |
    +-----------------------------------------+
    """)

    # Parse input
    print("[*] Parsing input file...")
    try:
        urls = parse_input(args.input)
    except Exception as e:
        print(f"[!] Failed to parse input: {e}")
        sys.exit(1)

    if not urls:
        print("[!] No browsable directory URLs found in input.")
        sys.exit(1)

    print(f"[+] Loaded {len(urls)} browsable directory URLs")

    # Prepare output
    os.makedirs(os.path.join(args.output, "downloads"), exist_ok=True)

    cookies = {}
    for c in args.cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k] = v

    _init_session_config(
        proxy=args.proxy,
        user_agent=args.user_agent,
        timeout=args.timeout,
        cookies=cookies or None,
        auth=args.auth,
    )

    # Phase 1: Crawl
    print(f"\n[*] Phase 1: Crawling directories (depth={args.depth}, threads={args.threads})")
    t0 = time.time()
    file_urls = crawl_all(urls, args.depth, args.timeout, args.threads)
    print(f"[+] Crawl complete: {len(file_urls)} unique files in {time.time() - t0:.1f}s")

    inv_path = write_inventory(file_urls, args.output)
    print(f"[+] File inventory: {inv_path}")

    if args.crawl_only:
        print("[*] --crawl-only set, skipping download/scan.")
        return

    if not file_urls:
        print("[*] No files discovered. Nothing to scan.")
        return

    # Phase 2: Download + Scan
    print(f"\n[*] Phase 2: Downloading and scanning (max {args.max_size // (1024*1024)}MB/file)")
    t0 = time.time()
    findings = download_and_scan_all(
        file_urls, args.output, args.max_size, args.timeout, args.threads,
    )
    print(f"[+] Download/scan complete in {time.time() - t0:.1f}s")

    # Phase 2b: TruffleHog (optional)
    if args.trufflehog:
        print(f"\n[*] Phase 2b: TruffleHog deep scan (entropy + verified credentials)")
        th_findings = run_trufflehog(args.output)
        if th_findings:
            existing_matches = {
                (f["url"], f["match"]) for f in findings if f["type"] == "secret"
            }
            deduped = 0
            for tf in th_findings:
                if (tf["url"], tf["match"]) not in existing_matches:
                    findings.append(tf)
                else:
                    deduped += 1
            if deduped:
                print(f"[+] Deduplicated {deduped} findings already caught by regex scan")

    # Phase 3: Report
    print("\n[*] Phase 3: Generating reports...")
    json_path, txt_path = generate_report(findings, args.output, len(urls), len(file_urls))
    print(f"[+] JSON: {json_path}")
    print(f"[+] Text: {txt_path}")

    # Summary
    secrets = [f for f in findings if f["type"] == "secret"]
    interesting = [f for f in findings if f["type"] == "interesting_file"]

    print(f"\n{'=' * 50}")
    print(f"  SUMMARY")
    print(f"{'=' * 50}")
    print(f"  Directories crawled:  {len(urls)}")
    print(f"  Files discovered:     {len(file_urls)}")
    print(f"  Secrets found:        {len(secrets)}")
    print(f"  Interesting files:    {len(interesting)}")

    if secrets:
        print(f"\n  Top findings:")
        for f in secrets[:15]:
            print(f"    [{f['severity']}] {f['pattern_name']}")
            print(f"           {f['url']}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Partial results may be in the output directory.")
        sys.exit(130)
