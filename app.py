from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder="dist", static_url_path="")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RUNTIME_DIR = os.path.join(BASE_DIR, ".runtime")
CACHE_TTL_SECONDS = 300
COMMAND_TIMEOUT_SECONDS = 240
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

    return {
        "total_vulnerabilities": len(vulnerabilities),
        "dependencies_scanned": dependencies_scanned,
        "fix_available": fix_available,
        "by_severity": by_severity,
    }


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

            vulnerabilities.append(
                {
                    "id": vuln_id,
                    "name": vuln_id,
                    "package": package_name,
                    "version": package_version,
                    "severity": _normalize_severity(vulnerability.get("severity")),
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
        used_fallback_mode = False

        started = time.perf_counter()
        result = subprocess.run(base_cmd, capture_output=True, text=True, check=False, timeout=COMMAND_TIMEOUT_SECONDS)
        raw = _parse_pip_audit_stdout(result.stdout)
        run_is_usable = result.returncode in (0, 1) and raw is not None

        if not run_is_usable and _requirements_are_exact_pins(requirements_text):
            # Fallback for legacy pinned dependencies that fail while pip tries to build/resolve.
            fallback_cmd = [*base_cmd, "--no-deps", "--disable-pip"]
            fallback_result = subprocess.run(
                fallback_cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
            fallback_raw = _parse_pip_audit_stdout(fallback_result.stdout)
            fallback_is_usable = fallback_result.returncode in (0, 1) and fallback_raw is not None

            if fallback_is_usable:
                result = fallback_result
                raw = fallback_raw
                used_fallback_mode = True
            else:
                primary_error = result.stderr.strip() or "Error ejecutando pip-audit"
                fallback_error = fallback_result.stderr.strip() or "Error en fallback de pip-audit"
                raise RuntimeError(f"{primary_error}\nFallback (--no-deps --disable-pip): {fallback_error}")

        duration_ms = int((time.perf_counter() - started) * 1000)

    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "Error ejecutando pip-audit")
    if raw is None:
        raise RuntimeError(result.stderr.strip() or "No se pudo interpretar la salida JSON de pip-audit")

    vulnerabilities, dependencies_scanned = _parse_python_audit(raw)
    summary = _build_summary(vulnerabilities, dependencies_scanned)

    payload = {
        "ecosystem": "python",
        "scanned_at": _utc_now_iso(),
        "duration_ms": duration_ms,
        "summary": summary,
        "vulnerabilities": vulnerabilities,
        "audit_mode": "pinned-no-deps" if used_fallback_mode else "resolved-with-pip",
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
    summary = _build_summary(vulnerabilities, dependencies_scanned)

    payload = {
        "ecosystem": "npm",
        "scanned_at": _utc_now_iso(),
        "duration_ms": duration_ms,
        "summary": summary,
        "vulnerabilities": vulnerabilities,
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


if __name__ == "__main__":
    app.run(debug=True, port=8000)
