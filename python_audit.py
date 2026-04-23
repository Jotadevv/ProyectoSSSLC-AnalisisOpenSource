"""
audit_python.py
Versión final:
- Resolución determinística con pip-tools (pip-compile)
- OSV batch queries
- Cache persistente
- Connection pooling
- Paralelización por chunks
"""

import json
import os
import subprocess
import sys
import requests
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Config ─────────────────────────────────────────

MAX_WORKERS = int(os.environ.get("AUDIT_WORKERS", 8))
CHUNK_SIZE = int(os.environ.get("AUDIT_CHUNK", 50))

REQUIREMENTS_PATH = "requirements.txt"
LOCK_PATH = "requirements.lock"
CACHE_PATH = "osv_cache.json"

OSV_URL = "https://api.osv.dev/v1/querybatch"

# ── HTTP + Cache ───────────────────────────────────

_session = requests.Session()
_cache_lock = Lock()

if os.path.exists(CACHE_PATH):
    with open(CACHE_PATH, "r", encoding="utf-8") as f:
        OSV_CACHE = json.load(f)
else:
    OSV_CACHE = {}


def save_cache():
    with _cache_lock:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(OSV_CACHE, f)


def _cache_key(name, version):
    return f"{name}=={version}"


def osv_batch_query(packages):
    queries = []
    results = {}

    for name, version in packages:
        key = _cache_key(name, version)
        if key in OSV_CACHE:
            results[key] = OSV_CACHE[key]
        else:
            queries.append({
                "package": {"name": name, "ecosystem": "PyPI"},
                "version": version
            })

    if queries:
        try:
            resp = _session.post(OSV_URL, json={"queries": queries}, timeout=15)
            data = resp.json()

            for q, res in zip(queries, data.get("results", [])):
                key = _cache_key(q["package"]["name"], q["version"])
                with _cache_lock:
                    OSV_CACHE[key] = res
                results[key] = res

        except Exception as e:
            print(f"[osv] error: {e}")

    return results


# ── pip-tools (pip-compile) ─────────────────────────

def ensure_pip_tools():
    try:
        subprocess.run(
            [sys.executable, "-m", "piptools", "--version"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pip-tools"],
            check=True
        )


def generate_lockfile():
    if os.path.exists(LOCK_PATH):
        return

    print("[lock] Generando requirements.lock con pip-compile...")

    subprocess.run(
        [
            sys.executable,
            "-m",
            "piptools",
            "compile",
            REQUIREMENTS_PATH,
            "--output-file",
            LOCK_PATH,
            "--quiet"
        ],
        check=True
    )


# ── Helpers ────────────────────────────────────────

def load_lockfile():
    with open(LOCK_PATH, "r", encoding="utf-8") as f:
        lines = [
            l.strip()
            for l in f
            if l.strip() and not l.startswith("#") and "==" in l
        ]
    return lines


def extract_packages(lines):
    result = []
    for line in lines:
        name, version = line.split("==", 1)
        result.append((name.strip(), version.strip()))
    return result


def chunks(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


# ── Audit ──────────────────────────────────────────

def audit_chunk(packages, chunk_id):
    osv_results = osv_batch_query(packages)

    vulns = []

    for name, version in packages:
        key = _cache_key(name, version)
        data = osv_results.get(key, {})

        for vuln in data.get("vulns", []):
            vulns.append({
                "name": vuln.get("id"),
                "package": name,
                "version": version,
                "severity": vuln.get("severity", "unknown"),
                "fixed_in": ", ".join(vuln.get("fix_versions", [])),
                "description": vuln.get("summary", ""),
            })

    print(f"[chunk {chunk_id}] ⚡ {len(vulns)} vulns")
    return vulns


def audit_all(packages):
    all_vulns = []
    seen = set()

    pkg_chunks = list(chunks(packages, CHUNK_SIZE))

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [
            pool.submit(audit_chunk, chunk, i)
            for i, chunk in enumerate(pkg_chunks)
        ]

        for f in as_completed(futures):
            for v in f.result():
                key = f"{v['package']}:{v['version']}:{v['name']}"
                if key not in seen:
                    seen.add(key)
                    all_vulns.append(v)

    return all_vulns


# ── Main ───────────────────────────────────────────

def run():
    if not os.path.exists(REQUIREMENTS_PATH):
        print("No requirements.txt")
        return

    ensure_pip_tools()
    generate_lockfile()

    lines = load_lockfile()
    packages = extract_packages(lines)

    print(f"[info] paquetes: {len(packages)}")

    vulns = audit_all(packages)

    save_cache()

    with open("audit_results.json", "w", encoding="utf-8") as f:
        json.dump(vulns, f, indent=2)

    print(f"\n✅ {len(vulns)} vulnerabilidades encontradas")


if __name__ == "__main__":
    run()