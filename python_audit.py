import subprocess
import json
import os
import sys

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

    result = subprocess.run(
        [sys.executable, "-m", "pip_audit", "--format", "json", "--requirement", requirements_path],
        capture_output=True,
        text=True,
    )

    with open("python_output.json", "w", encoding="utf-8") as f:
        f.write(result.stdout)

    if result.returncode not in (0, 1):
        print("Error al ejecutar pip-audit:", result.stderr)
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