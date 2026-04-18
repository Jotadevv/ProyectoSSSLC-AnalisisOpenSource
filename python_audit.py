import subprocess
import json
import os
import sys

def requirements_are_exact_pins(requirements_text: str) -> bool:
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

def run_python_audit():
    print("1. Verificando pip-audit")
    try:
        subprocess.run([sys.executable, "-m", "pip_audit", "--version"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("pip-audit no está instalado. Instalando...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "pip-audit"], check=True)
        except subprocess.CalledProcessError:
            print("Error instalando pip-audit")
            return False

    print("2. Verificando requirements.txt")
    if not os.path.exists("requirements.txt"):
        print("Error: No se encontró requirements.txt en el directorio actual")
        return False

    print("3. Leyendo requirements.txt")
    try:
        with open("requirements.txt", "r", encoding="utf-8") as req_file:
            requirements_text = req_file.read()
    except Exception as e:
        print(f"Error leyendo requirements.txt: {e}")
        return False

    print("4. Ejecutando pip-audit")
    try:
        # Crear archivo temporal para requirements
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            temp_file.write(requirements_text)
            temp_path = temp_file.name

        try:
            result = subprocess.run([
                sys.executable, "-m", "pip_audit",
                "--format", "json",
                "--requirement", temp_path
            ], capture_output=True, text=True, check=True)

            audit_data = json.loads(result.stdout)
            with open("python_output.json", "w", encoding="utf-8") as f:
                json.dump(audit_data, f, indent=2, ensure_ascii=False)
            print("Resultado guardado en python_output.json")
        finally:
            os.unlink(temp_path)

    except subprocess.CalledProcessError as e:
        print(f"Error ejecutando pip-audit: {e}")
        if e.stderr:
            print(f"Stderr: {e.stderr}")
        return False
    except json.JSONDecodeError as e:
        print(f"Error parseando JSON: {e}")
        return False

    print("5. Procesando vulnerabilidades")
    vulnerabilities = []
    if "dependencies" in audit_data:
        for dependency in audit_data["dependencies"]:
            pkg_name = dependency.get("name", "unknown")
            pkg_version = dependency.get("version", "unknown")

            for vuln in dependency.get("vulns", []):
                vuln_entry = {
                    "id": vuln.get("id", pkg_name),
                    "package": pkg_name,
                    "version": pkg_version,
                    "severity": vuln.get("severity", "unknown"),
                    "description": vuln.get("description", "").strip(),
                    "fix_available": len(vuln.get("fix_versions", [])) > 0
                }
                if vuln.get("fix_versions"):
                    vuln_entry["fixed_in"] = ", ".join(vuln["fix_versions"])
                vulnerabilities.append(vuln_entry)

    with open("audit_results.json", "w", encoding="utf-8") as json_file:
        json.dump(vulnerabilities, json_file, indent=2, ensure_ascii=False)

    print(f"Procesadas {len(vulnerabilities)} vulnerabilidades")
    print("Resultado guardado en audit_results.json")
    return True

def consolidate_reports():
    print("6. Consolidando reportes")

    # Leer resultados de Python
    python_vulns = []
    if os.path.exists("audit_results.json"):
        try:
            with open("audit_results.json", "r") as f:
                python_vulns = json.load(f)
        except json.JSONDecodeError:
            print("Error leyendo audit_results.json")

    # Leer resultados de npm (si existen)
    npm_vulns = []
    if os.path.exists("npm_audit_results.json"):
        try:
            with open("npm_audit_results.json", "r") as f:
                npm_vulns = json.load(f)
        except json.JSONDecodeError:
            print("Error leyendo npm_audit_results.json")

    consolidated = {
        "python_vulnerabilities": python_vulns,
        "npm_vulnerabilities": npm_vulns,
        "total_python": len(python_vulns),
        "total_npm": len(npm_vulns),
        "total_vulnerabilities": len(python_vulns) + len(npm_vulns)
    }

    with open("consolidated_report.json", "w") as f:
        json.dump(consolidated, f, indent=2, ensure_ascii=False)

    print(f"Reporte consolidado guardado en consolidated_report.json")
    print(f"Total vulnerabilidades: {consolidated['total_vulnerabilities']}")

if __name__ == "__main__":
    if run_python_audit():
        consolidate_reports()
        print("Auditoría Python completada exitosamente")
    else:
        print("Error en la auditoría Python")
        sys.exit(1)import subprocess
import json
import os
import sys

def requirements_are_exact_pins(requirements_text: str) -> bool:
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


def has_valid_pip_audit_json(stdout: str) -> bool:
    text = (stdout or "").strip()
    if not text:
        return False

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return False

    return isinstance(payload, dict) and isinstance(payload.get("dependencies"), list)


def run_audit():
    print("--- 1. Verificando pip-audit ---")
    try:
        subprocess.run([sys.executable, "-m", "pip_audit", "--version"], 
                      check=True, capture_output=True)
        print("pip-audit ya está instalado")
    except subprocess.CalledProcessError:
        print("pip-audit no está instalado, instalando...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pip-audit"], check=True)

    print("--- 2. Ejecutando auditoría y generando archivo JSON ---")
    requirements_path = "requirements.txt"
    if not os.path.exists(requirements_path):
        print("Error: No se encontró requirements.txt")
        return False

    with open(requirements_path, "r", encoding="utf-8") as req_file:
        requirements_text = req_file.read()

    base_cmd = [sys.executable, "-m", "pip_audit", "--format", "json", "--requirement", requirements_path]
    result = subprocess.run(base_cmd, capture_output=True, text=True)
    run_is_usable = result.returncode in (0, 1) and has_valid_pip_audit_json(result.stdout)

    if not run_is_usable and requirements_are_exact_pins(requirements_text):
        print("Fallo resolviendo dependencias; reintentando en modo pinned (--no-deps --disable-pip)")
        fallback_cmd = [*base_cmd, "--no-deps", "--disable-pip"]
        fallback_result = subprocess.run(fallback_cmd, capture_output=True, text=True)
        fallback_is_usable = fallback_result.returncode in (0, 1) and has_valid_pip_audit_json(
            fallback_result.stdout
        )
        if fallback_is_usable:
            result = fallback_result
        else:
            print("Error en fallback:", fallback_result.stderr)

    with open("python_output.json", "w", encoding="utf-8") as f:
        f.write(result.stdout)

    if result.returncode not in (0, 1):
        print("Error al ejecutar pip-audit:", result.stderr)
        return False
    if not has_valid_pip_audit_json(result.stdout):
        print("Error: pip-audit no devolvió JSON válido.", result.stderr)
        return False

    return True

def parse_to_json(file_path):
    print("--- 3. Parseando resultados a JSON ---")
    results = []
    
    if not os.path.exists(file_path):
        print("Error: No se encontró el archivo de salida.")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        try:
            audit_data = json.load(f)
        except json.JSONDecodeError as e:
            print("Error al parsear JSON de pip-audit:", e)
            return

    if isinstance(audit_data, dict):
        if "dependencies" in audit_data:
            for dependency in audit_data.get("dependencies", []):
                pkg_name = dependency.get("name", "unknown")
                pkg_version = dependency.get("version", "unknown")
                for vuln in dependency.get("vulns", []):
                    entry = {
                        "name": vuln.get("id") or pkg_name,
                        "package": pkg_name,
                        "version": pkg_version,
                        "severity": vuln.get("severity", "unknown"),
                        "fixed_in": ", ".join(vuln.get("fix_versions", [])) if isinstance(vuln.get("fix_versions"), list) else vuln.get("fix_versions", "No disponible"),
                        "description": vuln.get("description", ""),
                    }
                    results.append(entry)
        elif "vulnerabilities" in audit_data:
            audit_data = audit_data["vulnerabilities"]
            for item in audit_data or []:
                entry = {
                    "name": item.get("id") or item.get("package") or "unknown",
                    "package": item.get("package", "unknown"),
                    "version": item.get("version", "unknown"),
                    "severity": item.get("severity", "unknown"),
                    "fixed_in": ", ".join(item.get("fix_versions", [])) if isinstance(item.get("fix_versions"), list) else item.get("fix_versions", "No disponible"),
                    "description": item.get("description", ""),
                }
                results.append(entry)
        else:
            for item in audit_data or []:
                if isinstance(item, str):
                    entry = {
                        "name": item,
                        "package": item,
                        "version": "unknown",
                        "severity": "unknown",
                        "fixed_in": "No disponible",
                        "description": "",
                    }
                else:
                    entry = {
                        "name": item.get("id") or item.get("package") or "unknown",
                        "package": item.get("package", "unknown"),
                        "version": item.get("version", "unknown"),
                        "severity": item.get("severity", "unknown"),
                        "fixed_in": ", ".join(item.get("fix_versions", [])) if isinstance(item.get("fix_versions"), list) else item.get("fix_versions", "No disponible"),
                        "description": item.get("description", ""),
                    }
                results.append(entry)
    else:
        for item in audit_data or []:
            if isinstance(item, str):
                entry = {
                    "name": item,
                    "package": item,
                    "version": "unknown",
                    "severity": "unknown",
                    "fixed_in": "No disponible",
                    "description": "",
                }
            else:
                entry = {
                    "name": item.get("id") or item.get("package") or "unknown",
                    "package": item.get("package", "unknown"),
                    "version": item.get("version", "unknown"),
                    "severity": item.get("severity", "unknown"),
                    "fixed_in": ", ".join(item.get("fix_versions", [])) if isinstance(item.get("fix_versions"), list) else item.get("fix_versions", "No disponible"),
                    "description": item.get("description", ""),
                }
            results.append(entry)

    with open("audit_results.json", "w", encoding="utf-8") as json_file:
        json.dump(results, json_file, indent=4)
    
    print(f"Se han procesado {len(results)} vulnerabilidades en 'audit_results.json'.")

if __name__ == "__main__":
    if run_audit():
        parse_to_json("python_output.json")
    else:
        print("Error en la ejecución de la auditoría de Python")
