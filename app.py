from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote_plus
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder="dist", static_url_path="")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RUNTIME_DIR = os.path.join(BASE_DIR, ".runtime")
CACHE_TTL_SECONDS = 300
INTEL_CACHE_TTL_SECONDS = 3600
COMMAND_TIMEOUT_SECONDS = 240
HTTP_TIMEOUT_SECONDS = 6
SEVERITY_KEYS = ["critical", "high", "moderate", "low", "info", "unknown"]
SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "moderate": 3,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

cache_lock = threading.Lock()
tool_lock = threading.Lock()
audit_cache: dict[str, dict[str, Any]] = {}
pip_audit_ready = False
npm_cmd_path: str | None = None
latest_python_raw: dict[str, Any] | None = None
intel_cache: dict[str, dict[str, Any]] = {}
kev_cache: dict[str, Any] = {"created_at": 0, "set": {}}

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
GHSA_PATTERN = re.compile(r"^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$", re.IGNORECASE)
PYSEC_PATTERN = re.compile(r"^PYSEC-\d{4}-\d+$", re.IGNORECASE)
CVE_SEARCH_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
GHSA_SEARCH_PATTERN = re.compile(r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", re.IGNORECASE)
PYSEC_SEARCH_PATTERN = re.compile(r"PYSEC-\d{4}-\d+", re.IGNORECASE)

VULNERABILITY_DATABASES = [
    {
        "id": "nvd",
        "name": "NVD (NIST)",
        "description": "Detalle tecnico oficial de CVE, CVSS y referencias.",
    },
    {
        "id": "mitre_cve",
        "name": "MITRE CVE",
        "description": "Registro canonico del identificador CVE.",
    },
    {
        "id": "osv",
        "name": "OSV.dev",
        "description": "Base abierta con aliases, paquetes afectados y rangos de versiones.",
    },
    {
        "id": "github_advisories",
        "name": "GitHub Advisories",
        "description": "Advisories GHSA y aliases (CVE, PYSEC, etc).",
    },
    {
        "id": "cisa_kev",
        "name": "CISA KEV",
        "description": "Catalogo de vulnerabilidades explotadas en el mundo real.",
    },
    {
        "id": "first_epss",
        "name": "FIRST EPSS",
        "description": "Score probabilistico de explotacion para CVE.",
    },
    {
        "id": "snyk",
        "name": "Snyk Vulnerability DB",
        "description": "Contexto adicional por ecosistema y remediacion.",
    },
    {
        "id": "vulners",
        "name": "Vulners",
        "description": "Motor de busqueda de inteligencia de vulnerabilidades.",
    },
]


@app.route("/")
def serve_react():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/<path:path>")
def serve_static(path: str):
    file_path = os.path.join(app.static_folder, path)
    if os.path.exists(file_path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_severity(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().lower()
    if normalized in {"none", "", "unrated"}:
        return "unknown"
    if normalized == "medium":
        return "moderate"
    if normalized in SEVERITY_KEYS:
        return normalized
    return "unknown"


def _empty_severity_bucket() -> dict[str, int]:
    return {key: 0 for key in SEVERITY_KEYS}


def _sorted_vulnerabilities(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        vulnerabilities,
        key=lambda item: (
            -SEVERITY_WEIGHT.get(_normalize_severity(item.get("severity")), 0),
            str(item.get("package", "")).lower(),
            str(item.get("name", "")).lower(),
        ),
    )


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _cache_get(cache_key: str) -> dict[str, Any] | None:
    now = time.time()
    with cache_lock:
        entry = audit_cache.get(cache_key)
        if not entry:
            return None
        if now - entry["created_at"] > CACHE_TTL_SECONDS:
            audit_cache.pop(cache_key, None)
            return None
        return entry


def _cache_set(cache_key: str, payload: dict[str, Any], raw: dict[str, Any] | None):
    with cache_lock:
        audit_cache[cache_key] = {
            "created_at": time.time(),
            "payload": payload,
            "raw": raw,
        }


def _intel_cache_get(cache_key: str) -> dict[str, Any] | None:
    now = time.time()
    with cache_lock:
        entry = intel_cache.get(cache_key)
        if not entry:
            return None
        if now - entry["created_at"] > INTEL_CACHE_TTL_SECONDS:
            intel_cache.pop(cache_key, None)
            return None
        return entry["payload"]


def _intel_cache_set(cache_key: str, payload: dict[str, Any]):
    with cache_lock:
        intel_cache[cache_key] = {
            "created_at": time.time(),
            "payload": payload,
        }


def _http_get_json(url: str, timeout_seconds: int = HTTP_TIMEOUT_SECONDS) -> dict[str, Any] | None:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "ProyectoSSSLC-AnalisisOpenSource/1.0",
        },
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            data = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(data)
            return parsed if isinstance(parsed, dict) else None
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError):
        return None


def _runtime_path(filename: str) -> str:
    os.makedirs(RUNTIME_DIR, exist_ok=True)
    return os.path.join(RUNTIME_DIR, filename)


def _write_json_file(filename: str, data: Any):
    path = _runtime_path(filename)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def _write_text_file(filename: str, content: str):
    path = _runtime_path(filename)
    with open(path, "w", encoding="utf-8") as file:
        file.write(content)


def _detect_vulnerability_id_type(vulnerability_id: str) -> str:
    normalized = vulnerability_id.strip().upper()
    if CVE_PATTERN.match(normalized):
        return "CVE"
    if GHSA_PATTERN.match(normalized):
        return "GHSA"
    if PYSEC_PATTERN.match(normalized):
        return "PYSEC"
    return "GENERIC"


def _build_vulnerability_references(vulnerability_id: str) -> tuple[str, list[dict[str, str]]]:
    normalized = vulnerability_id.strip().upper()
    query = quote_plus(normalized)
    vuln_type = _detect_vulnerability_id_type(normalized)
    nvd_url = (
        f"https://nvd.nist.gov/vuln/detail/{normalized}"
        if vuln_type == "CVE"
        else f"https://nvd.nist.gov/vuln/search/results?query={query}&search_type=all"
    )
    mitre_url = (
        f"https://www.cve.org/CVERecord?id={normalized}"
        if vuln_type == "CVE"
        else f"https://www.cve.org/SearchResults?query={query}"
    )
    osv_url = (
        f"https://osv.dev/vulnerability/{normalized}"
        if vuln_type in {"CVE", "GHSA", "PYSEC"}
        else f"https://osv.dev/list?search={query}"
    )
    github_url = (
        f"https://github.com/advisories/{normalized}"
        if vuln_type == "GHSA"
        else f"https://github.com/advisories?query={query}"
    )
    cisa_url = (
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        f"?search_api_fulltext={query}"
    )
    epss_url = (
        f"https://api.first.org/data/v1/epss?cve={normalized}"
        if vuln_type == "CVE"
        else f"https://www.first.org/epss/data_stats?search={query}"
    )

    references: list[dict[str, str]] = [
        {
            "database_id": "nvd",
            "database_name": "NVD (NIST)",
            "url": nvd_url,
        },
        {
            "database_id": "mitre_cve",
            "database_name": "MITRE CVE",
            "url": mitre_url,
        },
        {
            "database_id": "osv",
            "database_name": "OSV.dev",
            "url": osv_url,
        },
        {
            "database_id": "github_advisories",
            "database_name": "GitHub Advisories",
            "url": github_url,
        },
        {
            "database_id": "cisa_kev",
            "database_name": "CISA KEV",
            "url": cisa_url,
        },
        {
            "database_id": "first_epss",
            "database_name": "FIRST EPSS",
            "url": epss_url,
        },
        {
            "database_id": "snyk",
            "database_name": "Snyk Vulnerability DB",
            "url": f"https://security.snyk.io/vuln/?search={query}",
        },
        {
            "database_id": "vulners",
            "database_name": "Vulners",
            "url": f"https://vulners.com/search?query={query}",
        },
    ]

    return vuln_type, references


def _extract_identifiers_from_text(text: str) -> list[str]:
    found: set[str] = set()
    for pattern in (CVE_SEARCH_PATTERN, GHSA_SEARCH_PATTERN, PYSEC_SEARCH_PATTERN):
        for match in pattern.findall(text or ""):
            found.add(str(match).upper())
    return sorted(found)


def _collect_vulnerability_identifiers(vulnerability: dict[str, Any]) -> list[str]:
    candidates: set[str] = set()

    for field_name in ("id", "name", "description", "url"):
        value = vulnerability.get(field_name)
        if isinstance(value, str) and value.strip():
            for identifier in _extract_identifiers_from_text(value):
                candidates.add(identifier)

    for field_name in ("id", "name"):
        value = vulnerability.get(field_name)
        if isinstance(value, str):
            normalized = value.strip().upper()
            if normalized and _detect_vulnerability_id_type(normalized) != "GENERIC":
                candidates.add(normalized)

    if not candidates:
        fallback = vulnerability.get("id") or vulnerability.get("name") or vulnerability.get("package")
        if isinstance(fallback, str) and fallback.strip():
            candidates.add(fallback.strip())

    ordered = sorted(
        candidates,
        key=lambda item: (
            0
            if _detect_vulnerability_id_type(item) == "CVE"
            else 1 if _detect_vulnerability_id_type(item) == "GHSA" else 2,
            item,
        ),
    )
    return ordered


def _fetch_cisa_kev_index() -> dict[str, dict[str, Any]]:
    now = time.time()
    with cache_lock:
        created_at = float(kev_cache.get("created_at", 0))
        cached_set = kev_cache.get("set")
        if now - created_at <= INTEL_CACHE_TTL_SECONDS and isinstance(cached_set, dict):
            return cached_set

    parsed = _http_get_json(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )

    kev_index: dict[str, dict[str, Any]] = {}
    vulnerabilities = parsed.get("vulnerabilities", []) if isinstance(parsed, dict) else []
    if isinstance(vulnerabilities, list):
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cveID", "")).strip().upper()
            if not cve_id:
                continue
            kev_index[cve_id] = {
                "date_added": item.get("dateAdded"),
                "due_date": item.get("dueDate"),
                "required_action": item.get("requiredAction"),
                "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
            }

    with cache_lock:
        kev_cache["created_at"] = now
        kev_cache["set"] = kev_index

    return kev_index


def _chunked(items: list[str], chunk_size: int) -> list[list[str]]:
    if chunk_size <= 0:
        return [items]
    return [items[index : index + chunk_size] for index in range(0, len(items), chunk_size)]


def _fetch_epss_scores(cve_ids: list[str]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    if not cve_ids:
        return results

    unique_cves = sorted({cve.strip().upper() for cve in cve_ids if cve and cve.strip()})
    if not unique_cves:
        return results

    for chunk in _chunked(unique_cves, 80):
        joined = ",".join(chunk)
        payload = _http_get_json(f"https://api.first.org/data/v1/epss?cve={quote_plus(joined)}")
        data = payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(data, list):
            continue

        for item in data:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cve", "")).strip().upper()
            if not cve_id:
                continue
            try:
                epss_value = float(item.get("epss")) if item.get("epss") is not None else None
            except (TypeError, ValueError):
                epss_value = None
            try:
                percentile = (
                    float(item.get("percentile"))
                    if item.get("percentile") is not None
                    else None
                )
            except (TypeError, ValueError):
                percentile = None

            results[cve_id] = {
                "score": epss_value,
                "percentile": percentile,
                "date": item.get("date"),
            }

    return results


def _fetch_nvd_context(cve_id: str) -> dict[str, Any]:
    cache_key = f"nvd:{cve_id}"
    cached = _intel_cache_get(cache_key)
    if cached:
        return cached

    payload = _http_get_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote_plus(cve_id)}",
    )
    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []

    result: dict[str, Any] = {
        "available": False,
        "found": False,
        "cvss_base_score": None,
        "cvss_severity": None,
        "published": None,
        "last_modified": None,
    }

    if isinstance(vulnerabilities, list) and vulnerabilities:
        first = vulnerabilities[0] if isinstance(vulnerabilities[0], dict) else {}
        cve_block = first.get("cve", {}) if isinstance(first, dict) else {}
        metrics = cve_block.get("metrics", {}) if isinstance(cve_block, dict) else {}
        cvss_score = None
        cvss_severity = None

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key, [])
            if not isinstance(entries, list) or not entries:
                continue
            metric_item = entries[0] if isinstance(entries[0], dict) else {}
            cvss_data = metric_item.get("cvssData", {}) if isinstance(metric_item, dict) else {}
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or metric_item.get("baseSeverity")
            if isinstance(score, (int, float)):
                cvss_score = float(score)
                cvss_severity = str(severity).lower() if severity else None
                break

        result = {
            "available": True,
            "found": True,
            "cvss_base_score": cvss_score,
            "cvss_severity": cvss_severity,
            "published": cve_block.get("published"),
            "last_modified": cve_block.get("lastModified"),
        }

    _intel_cache_set(cache_key, result)
    return result


def _fetch_osv_context(vulnerability_id: str) -> dict[str, Any]:
    cache_key = f"osv:{vulnerability_id}"
    cached = _intel_cache_get(cache_key)
    if cached:
        return cached

    payload = _http_get_json(f"https://api.osv.dev/v1/vulns/{quote_plus(vulnerability_id)}")
    if not isinstance(payload, dict) or not payload:
        result = {
            "available": False,
            "found": False,
            "summary": None,
            "aliases": [],
            "affected_packages": [],
        }
        _intel_cache_set(cache_key, result)
        return result

    aliases = payload.get("aliases", []) if isinstance(payload.get("aliases"), list) else []
    affected_packages: list[str] = []
    affected = payload.get("affected", []) if isinstance(payload.get("affected"), list) else []
    for affected_item in affected:
        if not isinstance(affected_item, dict):
            continue
        package = affected_item.get("package", {})
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        ecosystem = package.get("ecosystem")
        if isinstance(name, str) and name:
            if isinstance(ecosystem, str) and ecosystem:
                affected_packages.append(f"{ecosystem}:{name}")
            else:
                affected_packages.append(name)

    result = {
        "available": True,
        "found": True,
        "summary": payload.get("summary"),
        "aliases": [str(alias).upper() for alias in aliases if isinstance(alias, str)],
        "affected_packages": affected_packages[:8],
    }
    _intel_cache_set(cache_key, result)
    return result


def _compute_intel_score(
    cisa_kev_listed: bool,
    epss_score: float | None,
    cvss_base_score: float | None,
) -> tuple[int, str]:
    score = 0

    if cisa_kev_listed:
        score += 50

    if epss_score is not None:
        if epss_score >= 0.9:
            score += 30
        elif epss_score >= 0.7:
            score += 20
        elif epss_score >= 0.3:
            score += 10
        elif epss_score >= 0.1:
            score += 5

    if cvss_base_score is not None:
        if cvss_base_score >= 9.0:
            score += 25
        elif cvss_base_score >= 7.0:
            score += 15
        elif cvss_base_score >= 4.0:
            score += 8
        elif cvss_base_score > 0:
            score += 4

    bounded = min(100, score)
    if bounded >= 80:
        return bounded, "Crítico"
    if bounded >= 60:
        return bounded, "Alto"
    if bounded >= 35:
        return bounded, "Medio"
    if bounded >= 15:
        return bounded, "Bajo"
    return bounded, "Informativo"


def _build_identifier_intel(
    identifier: str,
    epss_scores: dict[str, dict[str, Any]],
    kev_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    normalized = identifier.strip().upper()
    detected_type, references = _build_vulnerability_references(normalized)

    cisa_kev_data = kev_index.get(normalized) if detected_type == "CVE" else None
    epss_data = epss_scores.get(normalized) if detected_type == "CVE" else None
    nvd_data = _fetch_nvd_context(normalized) if detected_type == "CVE" else {
        "available": None,
        "found": None,
        "cvss_base_score": None,
        "cvss_severity": None,
        "published": None,
        "last_modified": None,
    }
    osv_data = (
        _fetch_osv_context(normalized)
        if detected_type in {"CVE", "GHSA", "PYSEC"}
        else {
            "available": None,
            "found": None,
            "summary": None,
            "aliases": [],
            "affected_packages": [],
        }
    )

    epss_score = None
    if isinstance(epss_data, dict):
        raw_score = epss_data.get("score")
        if isinstance(raw_score, (float, int)):
            epss_score = float(raw_score)

    cvss_base_score = nvd_data.get("cvss_base_score")
    if not isinstance(cvss_base_score, (int, float)):
        cvss_base_score = None

    intel_score, intel_label = _compute_intel_score(
        cisa_kev_listed=bool(cisa_kev_data),
        epss_score=epss_score,
        cvss_base_score=float(cvss_base_score) if cvss_base_score is not None else None,
    )

    return {
        "primary_id": normalized,
        "detected_type": detected_type,
        "catalog_coverage": len(references),
        "catalog_total": len(VULNERABILITY_DATABASES),
        "references": references,
        "intel_score": intel_score,
        "intel_risk_level": intel_label,
        "signals": {
            "nvd": nvd_data,
            "osv": osv_data,
            "cisa_kev": {
                "listed": bool(cisa_kev_data),
                "details": cisa_kev_data if cisa_kev_data else None,
            },
            "first_epss": {
                "score": epss_data.get("score") if isinstance(epss_data, dict) else None,
                "percentile": epss_data.get("percentile") if isinstance(epss_data, dict) else None,
                "date": epss_data.get("date") if isinstance(epss_data, dict) else None,
            },
        },
    }


def _build_intelligence_summary(vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    total_vulnerabilities = len(vulnerabilities)
    catalog_total = len(VULNERABILITY_DATABASES)
    enriched = 0
    full_catalog = 0
    detected_types = {"CVE": 0, "GHSA": 0, "PYSEC": 0, "GENERIC": 0}
    kev_count = 0
    epss_scores: list[tuple[str, float]] = []
    top_intel: tuple[str, int] = ("", -1)

    for vulnerability in vulnerabilities:
        intel = vulnerability.get("intel")
        if not isinstance(intel, dict):
            continue
        enriched += 1

        detected_type = str(intel.get("detected_type", "GENERIC")).upper()
        detected_types[detected_type if detected_type in detected_types else "GENERIC"] += 1

        if int(intel.get("catalog_coverage", 0)) >= catalog_total:
            full_catalog += 1

        signals = intel.get("signals", {}) if isinstance(intel.get("signals"), dict) else {}
        cisa = signals.get("cisa_kev", {}) if isinstance(signals.get("cisa_kev"), dict) else {}
        if bool(cisa.get("listed")):
            kev_count += 1

        epss = signals.get("first_epss", {}) if isinstance(signals.get("first_epss"), dict) else {}
        score = epss.get("score")
        primary_id = str(intel.get("primary_id", ""))
        if isinstance(score, (int, float)):
            epss_scores.append((primary_id, float(score)))

        intel_score = intel.get("intel_score")
        if isinstance(intel_score, int) and intel_score > top_intel[1]:
            top_intel = (primary_id, intel_score)

    average_epss = round(sum(score for _, score in epss_scores) / len(epss_scores), 4) if epss_scores else None
    max_epss_item = max(epss_scores, key=lambda item: item[1]) if epss_scores else None

    return {
        "catalog_sources_total": catalog_total,
        "vulnerabilities_enriched": enriched,
        "full_catalog_matches": full_catalog,
        "coverage_percent": round((enriched / total_vulnerabilities) * 100, 2) if total_vulnerabilities else 0,
        "detected_ids": {
            "cve": detected_types["CVE"],
            "ghsa": detected_types["GHSA"],
            "pysec": detected_types["PYSEC"],
            "generic": detected_types["GENERIC"],
        },
        "known_exploited_count": kev_count,
        "average_epss": average_epss,
        "highest_epss": (
            {"id": max_epss_item[0], "score": max_epss_item[1]}
            if max_epss_item
            else None
        ),
        "top_intel_score": (
            {"id": top_intel[0], "score": top_intel[1]}
            if top_intel[1] >= 0
            else None
        ),
    }


def _enrich_vulnerabilities_with_intelligence(vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    if not vulnerabilities:
        return _build_intelligence_summary(vulnerabilities)

    plan: list[tuple[dict[str, Any], str, list[str]]] = []
    unique_identifiers: set[str] = set()

    for vulnerability in vulnerabilities:
        identifiers = _collect_vulnerability_identifiers(vulnerability)
        primary_identifier = identifiers[0] if identifiers else ""
        if not primary_identifier:
            continue
        plan.append((vulnerability, primary_identifier, identifiers))
        unique_identifiers.add(primary_identifier)

    cve_ids = [
        identifier.upper()
        for identifier in unique_identifiers
        if _detect_vulnerability_id_type(identifier) == "CVE"
    ]
    kev_index = _fetch_cisa_kev_index()
    epss_scores = _fetch_epss_scores(cve_ids)

    intel_by_identifier: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(_build_identifier_intel, identifier, epss_scores, kev_index): identifier
            for identifier in unique_identifiers
        }
        for future in as_completed(futures):
            identifier = futures[future]
            try:
                intel_by_identifier[identifier] = future.result()
            except Exception:
                detected_type, references = _build_vulnerability_references(identifier)
                intel_by_identifier[identifier] = {
                    "primary_id": identifier.upper(),
                    "detected_type": detected_type,
                    "catalog_coverage": len(references),
                    "catalog_total": len(VULNERABILITY_DATABASES),
                    "references": references,
                    "intel_score": 0,
                    "intel_risk_level": "Informativo",
                    "signals": {
                        "nvd": None,
                        "osv": None,
                        "cisa_kev": {"listed": False, "details": None},
                        "first_epss": {"score": None, "percentile": None, "date": None},
                    },
                }

    for vulnerability, primary_identifier, identifiers in plan:
        intel = dict(intel_by_identifier.get(primary_identifier, {}))
        intel["aliases"] = [identifier.upper() for identifier in identifiers]
        vulnerability["intel"] = intel

        if not vulnerability.get("url"):
            references = intel.get("references", [])
            if isinstance(references, list) and references:
                first_ref = references[0] if isinstance(references[0], dict) else {}
                default_url = first_ref.get("url")
                if isinstance(default_url, str):
                    vulnerability["url"] = default_url

    return _build_intelligence_summary(vulnerabilities)


def _parse_json_payload(raw_text: str) -> dict[str, Any]:
    text = (raw_text or "").strip()
    if not text:
        return {}

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {"data": parsed}
    except json.JSONDecodeError:
        first = text.find("{")
        last = text.rfind("}")
        if first != -1 and last != -1 and last > first:
            parsed = json.loads(text[first : last + 1])
            return parsed if isinstance(parsed, dict) else {"data": parsed}
        raise


def _ensure_pip_audit():
    global pip_audit_ready

    with tool_lock:
        if pip_audit_ready:
            return

        check = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

        if check.returncode != 0:
            install = subprocess.run(
                [sys.executable, "-m", "pip", "install", "pip-audit", "--disable-pip-version-check"],
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            if install.returncode != 0:
                raise RuntimeError(install.stderr.strip() or "No se pudo instalar pip-audit")

        pip_audit_ready = True


def _resolve_npm_cmd() -> str:
    global npm_cmd_path

    with tool_lock:
        if npm_cmd_path:
            return npm_cmd_path

        npm_cmd = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm_cmd:
            raise RuntimeError("No se encontró npm en el sistema. Instala Node.js para auditar package.json.")

        npm_cmd_path = npm_cmd
        return npm_cmd


def _build_summary(vulnerabilities: list[dict[str, Any]], dependencies_scanned: int) -> dict[str, Any]:
    by_severity = _empty_severity_bucket()
    fix_available = 0

    for vuln in vulnerabilities:
        severity = _normalize_severity(vuln.get("severity"))
        by_severity[severity] += 1
        if vuln.get("fix_available"):
            fix_available += 1

    # Calculate global risk score
    total = len(vulnerabilities)
    if total == 0:
        global_risk_level = "Sin riesgo"
        global_risk_score = 0
    else:
        score = (
            by_severity["critical"] * 5 +
            by_severity["high"] * 4 +
            by_severity["moderate"] * 3 +
            by_severity["low"] * 2 +
            by_severity["info"] * 1 +
            by_severity["unknown"] * 0
        ) / total
        global_risk_score = round(score, 2)
        if score < 1.5:
            global_risk_level = "Bajo"
        elif score < 2.5:
            global_risk_level = "Medio"
        elif score < 3.5:
            global_risk_level = "Alto"
        else:
            global_risk_level = "Crítico"

    return {
        "total_vulnerabilities": total,
        "dependencies_scanned": dependencies_scanned,
        "fix_available": fix_available,
        "by_severity": by_severity,
        "global_risk_level": global_risk_level,
        "global_risk_score": global_risk_score,
    }


def _generate_recommendations(vulnerabilities: list[dict[str, Any]], ecosystem: str) -> list[dict[str, Any]]:
    recommendations = []
    severity_priority = {"critical": 4, "high": 3, "moderate": 2, "low": 1, "info": 0, "unknown": 0}
    
    # Group by package
    package_groups = {}
    for vuln in vulnerabilities:
        pkg = vuln.get("package", "unknown")
        if pkg not in package_groups:
            package_groups[pkg] = []
        package_groups[pkg].append(vuln)
    
    # Sort packages by highest severity
    sorted_packages = sorted(package_groups.keys(), 
                           key=lambda p: max(severity_priority.get(_normalize_severity(v.get("severity")), 0) 
                                           for v in package_groups[p]), 
                           reverse=True)
    
    order = 1
    for pkg in sorted_packages:
        vulns = package_groups[pkg]
        highest_severity = max(vulns, key=lambda v: severity_priority.get(_normalize_severity(v.get("severity")), 0))
        severity = _normalize_severity(highest_severity.get("severity"))
        priority = severity_priority.get(severity, 0)
        
        # Find suggested version
        suggested_version = None
        if highest_severity.get("fixed_in"):
            fixed_in = str(highest_severity["fixed_in"])
            if fixed_in and fixed_in.lower() != "no disponible":
                # Extract version from "version" or "version1, version2"
                versions = [v.strip() for v in fixed_in.split(",")]
                suggested_version = versions[0] if versions else None
        
        # Generate update command
        if ecosystem == "python":
            if suggested_version:
                command = f"pip install --upgrade {pkg}=={suggested_version}"
            else:
                command = f"pip install --upgrade {pkg}"
        elif ecosystem == "npm":
            if suggested_version:
                command = f"npm update {pkg}@{suggested_version}"
            else:
                command = f"npm update {pkg}"
        else:
            command = f"Actualizar {pkg} a la versión más reciente"
        
        recommendations.append({
            "package": pkg,
            "severity": severity,
            "priority": priority,
            "suggested_version": suggested_version,
            "update_command": command,
            "remediation_order": order,
            "vulnerability_count": len(vulns)
        })
        order += 1
    
    return recommendations


def _parse_python_audit(raw_output: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    vulnerabilities: list[dict[str, Any]] = []
    dependencies = raw_output.get("dependencies", []) if isinstance(raw_output, dict) else []

    for dependency in dependencies:
        package_name = dependency.get("name", "unknown")
        package_version = dependency.get("version", "unknown")

        for vulnerability in dependency.get("vulns", []):
            vuln_id = vulnerability.get("id") or package_name
            fix_versions = vulnerability.get("fix_versions", [])
            if isinstance(fix_versions, list):
                fixed_in = ", ".join(fix_versions) if fix_versions else "No disponible"
                fix_available = len(fix_versions) > 0
            else:
                fixed_in = str(fix_versions or "No disponible")
                fix_available = bool(fix_versions)

            url = ""
            if isinstance(vuln_id, str) and vuln_id.startswith("CVE-"):
                url = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"

            # Calculate severity if not provided
            vuln_severity = vulnerability.get("severity")
            if not vuln_severity or vuln_severity == "unknown":
                # Simple heuristic: recent CVEs tend to be more severe
                if isinstance(vuln_id, str) and vuln_id.startswith("CVE-"):
                    try:
                        year = int(vuln_id.split("-")[1])
                        if year >= 2024:
                            vuln_severity = "high"  # Recent CVEs are often high severity
                        else:
                            vuln_severity = "moderate"
                    except:
                        vuln_severity = "moderate"
                else:
                    vuln_severity = "moderate"

            vulnerabilities.append(
                {
                    "id": vuln_id,
                    "name": vuln_id,
                    "package": package_name,
                    "version": package_version,
                    "severity": _normalize_severity(vuln_severity),
                    "fixed_in": fixed_in,
                    "fix_available": fix_available,
                    "description": (vulnerability.get("description") or "").strip(),
                    "url": url,
                }
            )

    return _sorted_vulnerabilities(vulnerabilities), len(dependencies)


def _parse_npm_audit(raw_output: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    vulnerabilities: list[dict[str, Any]] = []
    dedupe_keys: set[str] = set()

    vulnerabilities_block = raw_output.get("vulnerabilities", {}) if isinstance(raw_output, dict) else {}

    for package_name, package_data in vulnerabilities_block.items():
        package_severity = _normalize_severity(package_data.get("severity"))
        package_version = package_data.get("range") or package_data.get("version") or "unknown"

        fix_info = package_data.get("fixAvailable")
        if isinstance(fix_info, dict):
            fixed_in = str(fix_info.get("version") or "Disponible")
            fix_available = True
        elif fix_info is True:
            fixed_in = "Disponible"
            fix_available = True
        else:
            fixed_in = "No disponible"
            fix_available = False

        via = package_data.get("via", [])
        if not isinstance(via, list):
            via = [via]

        found_detail = False
        for via_item in via:
            if not isinstance(via_item, dict):
                continue

            found_detail = True
            vuln_name = via_item.get("title") or via_item.get("name") or f"Vulnerabilidad en {package_name}"
            vuln_id = via_item.get("source") or via_item.get("name") or vuln_name
            severity = _normalize_severity(via_item.get("severity") or package_severity)
            description = (via_item.get("overview") or via_item.get("title") or "").strip()
            url = via_item.get("url") or ""
            dedupe_key = f"{package_name}:{vuln_id}:{url}"

            if dedupe_key in dedupe_keys:
                continue
            dedupe_keys.add(dedupe_key)

            vulnerabilities.append(
                {
                    "id": str(vuln_id),
                    "name": str(vuln_name),
                    "package": package_name,
                    "version": str(package_version),
                    "severity": severity,
                    "fixed_in": fixed_in,
                    "fix_available": fix_available,
                    "description": description,
                    "url": url,
                }
            )

        if not found_detail:
            fallback_name = f"Vulnerabilidad en {package_name}"
            dedupe_key = f"{package_name}:{fallback_name}:{fixed_in}"
            if dedupe_key not in dedupe_keys:
                dedupe_keys.add(dedupe_key)
                vulnerabilities.append(
                    {
                        "id": fallback_name,
                        "name": fallback_name,
                        "package": package_name,
                        "version": str(package_version),
                        "severity": package_severity,
                        "fixed_in": fixed_in,
                        "fix_available": fix_available,
                        "description": "",
                        "url": "",
                    }
                )

    metadata = raw_output.get("metadata", {}) if isinstance(raw_output, dict) else {}
    dependency_meta = metadata.get("dependencies", {}) if isinstance(metadata, dict) else {}
    dependencies_scanned = dependency_meta.get("total") if isinstance(dependency_meta, dict) else None
    if not isinstance(dependencies_scanned, int):
        dependencies_scanned = len(vulnerabilities_block)

    return _sorted_vulnerabilities(vulnerabilities), dependencies_scanned


def _requirements_are_exact_pins(requirements_text: str) -> bool:
    has_packages = False

    for raw_line in requirements_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-", "--")):
            return False

        requirement = line.split(" #", 1)[0].strip()
        if "==" not in requirement:
            return False
        has_packages = True

    return has_packages


def _parse_pip_audit_stdout(stdout: str) -> dict[str, Any] | None:
    if not (stdout or "").strip():
        return None

    try:
        parsed = _parse_json_payload(stdout)
    except json.JSONDecodeError:
        return None

    dependencies = parsed.get("dependencies") if isinstance(parsed, dict) else None
    if not isinstance(dependencies, list):
        return None

    return parsed


def _run_python_audit(requirements_text: str) -> tuple[dict[str, Any], dict[str, Any]]:
    _ensure_pip_audit()

    with tempfile.TemporaryDirectory(prefix="audit_py_") as tmp_dir:
        requirements_path = os.path.join(tmp_dir, "requirements.txt")
        with open(requirements_path, "w", encoding="utf-8") as req_file:
            req_file.write(requirements_text)

        base_cmd = [
            sys.executable,
            "-m",
            "pip_audit",
            "--format",
            "json",
            "--requirement",
            requirements_path,
        ]
        no_deps_cmd = [*base_cmd, "--no-deps", "--disable-pip"]
        exact_pins = _requirements_are_exact_pins(requirements_text)
        used_no_deps_mode = False

        started = time.perf_counter()
        result: subprocess.CompletedProcess[str] | None = None
        raw: dict[str, Any] | None = None
        errors: list[str] = []

        # For fully pinned requirements, prefer the fast path and avoid expensive resolution/build.
        if exact_pins:
            command_plan = [
                ("modo rapido (--no-deps --disable-pip)", no_deps_cmd, True),
                ("modo completo (resolviendo con pip)", base_cmd, False),
            ]
        else:
            command_plan = [
                ("modo completo (resolviendo con pip)", base_cmd, False),
                ("modo rapido (--no-deps --disable-pip)", no_deps_cmd, True),
            ]

        for label, cmd, is_no_deps in command_plan:
            try:
                current_result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=COMMAND_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                errors.append(f"{label} excedio el timeout de {COMMAND_TIMEOUT_SECONDS}s")
                continue

            current_raw = _parse_pip_audit_stdout(current_result.stdout)
            run_is_usable = current_result.returncode in (0, 1) and current_raw is not None
            if run_is_usable:
                result = current_result
                raw = current_raw
                used_no_deps_mode = is_no_deps
                break

            error_detail = current_result.stderr.strip() or f"{label} no devolvio JSON valido"
            errors.append(f"{label}: {error_detail}")

        duration_ms = int((time.perf_counter() - started) * 1000)

    if result is None or raw is None:
        details = "\n".join(errors) if errors else "Error ejecutando pip-audit"
        raise RuntimeError(details)

    vulnerabilities, dependencies_scanned = _parse_python_audit(raw)
    intelligence_summary = _enrich_vulnerabilities_with_intelligence(vulnerabilities)
    summary = _build_summary(vulnerabilities, dependencies_scanned)
    summary["intelligence"] = intelligence_summary
    recommendations = _generate_recommendations(vulnerabilities, "python")

    payload = {
        "ecosystem": "python",
        "scanned_at": _utc_now_iso(),
        "duration_ms": duration_ms,
        "summary": summary,
        "intelligence_summary": intelligence_summary,
        "vulnerabilities": vulnerabilities,
        "recommendations": recommendations,
        "audit_mode": (
            "pinned-no-deps"
            if used_no_deps_mode and exact_pins
            else "no-deps-fallback" if used_no_deps_mode else "resolved-with-pip"
        ),
    }

    return payload, raw


def _run_npm_audit(package_json_text: str) -> tuple[dict[str, Any], dict[str, Any]]:
    npm_cmd = _resolve_npm_cmd()

    with tempfile.TemporaryDirectory(prefix="audit_npm_") as tmp_dir:
        package_json_path = os.path.join(tmp_dir, "package.json")
        with open(package_json_path, "w", encoding="utf-8") as package_file:
            package_file.write(package_json_text)

        lock_result = subprocess.run(
            [npm_cmd, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
            capture_output=True,
            text=True,
            check=False,
            cwd=tmp_dir,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
        if lock_result.returncode != 0:
            raise RuntimeError(lock_result.stderr.strip() or "No se pudo generar package-lock.json")

        started = time.perf_counter()
        audit_result = subprocess.run(
            [npm_cmd, "audit", "--json"],
            capture_output=True,
            text=True,
            check=False,
            cwd=tmp_dir,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
        duration_ms = int((time.perf_counter() - started) * 1000)

    raw_text = audit_result.stdout.strip() or audit_result.stderr.strip()
    raw = _parse_json_payload(raw_text)

    vulnerabilities, dependencies_scanned = _parse_npm_audit(raw)
    intelligence_summary = _enrich_vulnerabilities_with_intelligence(vulnerabilities)
    summary = _build_summary(vulnerabilities, dependencies_scanned)
    summary["intelligence"] = intelligence_summary
    recommendations = _generate_recommendations(vulnerabilities, "npm")

    payload = {
        "ecosystem": "npm",
        "scanned_at": _utc_now_iso(),
        "duration_ms": duration_ms,
        "summary": summary,
        "intelligence_summary": intelligence_summary,
        "vulnerabilities": vulnerabilities,
        "recommendations": recommendations,
    }

    return payload, raw


def _validate_uploaded_text_file(field_name: str) -> tuple[str, bytes]:
    uploaded = request.files.get(field_name)
    if not uploaded:
        raise ValueError("No se recibió el archivo en el campo 'file'.")

    content_bytes = uploaded.read()
    if not content_bytes:
        raise ValueError("El archivo recibido está vacío.")

    try:
        content_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_text = content_bytes.decode("latin-1")

    return content_text, content_bytes


@app.route("/audit/python", methods=["POST"])
def audit_python():
    global latest_python_raw

    try:
        requirements_text, raw_bytes = _validate_uploaded_text_file("file")
        cache_key = f"python:{_sha256_bytes(raw_bytes)}"
        cached = _cache_get(cache_key)

        if cached:
            latest_python_raw = cached.get("raw")
            cached_payload = dict(cached["payload"])
            cached_payload["cached"] = True
            return jsonify(cached_payload)

        payload, raw = _run_python_audit(requirements_text)
        payload["cached"] = False

        latest_python_raw = raw
        _cache_set(cache_key, payload, raw)

        _write_text_file("last_uploaded_requirements.txt", requirements_text)
        _write_json_file("python_output.json", raw)
        _write_json_file("audit_results.json", payload["vulnerabilities"])

        return jsonify(payload)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception as error:
        return jsonify({"error": f"Error ejecutando auditoría Python: {error}"}), 500


@app.route("/audit/npm", methods=["POST"])
def audit_npm():
    try:
        package_json_text, raw_bytes = _validate_uploaded_text_file("file")
        package_json_data = json.loads(package_json_text)
        cache_key = f"npm:{_sha256_bytes(raw_bytes)}"
        cached = _cache_get(cache_key)

        if cached:
            cached_payload = dict(cached["payload"])
            cached_payload["cached"] = True
            return jsonify(cached_payload)

        payload, raw = _run_npm_audit(package_json_text)
        payload["cached"] = False

        _cache_set(cache_key, payload, raw)

        _write_json_file("last_uploaded_package.json", package_json_data)
        _write_text_file("npm_output.txt", json.dumps(raw, ensure_ascii=False, indent=2))
        _write_json_file("npm_audit_results.json", payload["vulnerabilities"])

        return jsonify(payload)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except json.JSONDecodeError:
        return jsonify({"error": "El archivo package.json no tiene un JSON válido."}), 400
    except Exception as error:
        return jsonify({"error": f"Error ejecutando auditoría npm: {error}"}), 500


@app.route("/audit/python_output", methods=["GET"])
def get_python_output():
    if latest_python_raw is not None:
        return jsonify(latest_python_raw)

    output_path = _runtime_path("python_output.json")
    legacy_output_path = os.path.join(BASE_DIR, "python_output.json")
    if not os.path.exists(output_path) and not os.path.exists(legacy_output_path):
        return jsonify({"error": "No hay resultados crudos disponibles todavía."}), 404

    try:
        source_path = output_path if os.path.exists(output_path) else legacy_output_path
        with open(source_path, "r", encoding="utf-8") as output_file:
            return jsonify(json.load(output_file))
    except json.JSONDecodeError as error:
        return jsonify({"error": f"Error al parsear python_output.json: {error}"}), 500


@app.route("/api/vulnerability-databases", methods=["GET"])
def get_vulnerability_databases():
    return jsonify(
        {
            "total": len(VULNERABILITY_DATABASES),
            "databases": VULNERABILITY_DATABASES,
        }
    )


@app.route("/api/vulnerability/<path:vulnerability_id>/references", methods=["GET"])
def get_vulnerability_references(vulnerability_id: str):
    normalized = vulnerability_id.strip()
    if not normalized:
        return jsonify({"error": "Debes enviar un ID de vulnerabilidad."}), 400

    vuln_type, references = _build_vulnerability_references(normalized)
    return jsonify(
        {
            "query": normalized.upper(),
            "detected_type": vuln_type,
            "total_sources": len(references),
            "references": references,
        }
    )


@app.route("/api/vulnerability/references", methods=["POST"])
def get_vulnerability_references_batch():
    payload = request.get_json(silent=True) or {}
    ids = payload.get("ids", [])

    if not isinstance(ids, list) or not ids:
        return jsonify({"error": "Debes enviar un arreglo 'ids' con al menos un valor."}), 400

    result: dict[str, dict[str, object]] = {}
    for raw_id in ids:
        if not isinstance(raw_id, str):
            continue

        normalized = raw_id.strip()
        if not normalized:
            continue

        vuln_type, references = _build_vulnerability_references(normalized)
        result[normalized.upper()] = {
            "detected_type": vuln_type,
            "total_sources": len(references),
            "references": references,
        }

    if not result:
        return jsonify({"error": "No se recibieron IDs validos."}), 400

    return jsonify({"count": len(result), "items": result})


if __name__ == "__main__":
    app.run(debug=True, port=8000)
