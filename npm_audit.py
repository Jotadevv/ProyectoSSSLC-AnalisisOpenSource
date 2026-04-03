import subprocess
import json
import os
import sys

def run_npm_audit():
    print("1. Verificando npm")
    try:
        subprocess.run(["npm", "--version"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("Error: npm no está instalado")
        return False
    
    print("2. Verificando package.json")
    if not os.path.exists("package.json"):
        print("Error: No se encontró package.json en el directorio actual")
        return False
    
    print("3. Instalando dependencias (si es necesario)")
    if os.path.exists("node_modules"):
        print("node_modules ya existe, saltando instalación")
    else:
        subprocess.run(["npm", "install"], check=True)
    
    print("4. Ejecutando npm audit y generando archivo")
    try:
        with open("npm_output.txt", "w") as f:
            subprocess.run(["npm", "audit", "--json"], stdout=f, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError as e:
        print(f"npm audit completado con código {e.returncode} (normal si hay vulnerabilidades)")
        return True

def parse_npm_audit_to_json(file_path):
    print("5. Parseando resultados de npm audit a JSON")
    
    if not os.path.exists(file_path):
        print(f"Error: No se encontró el archivo {file_path}")
        return
    
    try:
        with open(file_path, "r") as f:
            content = f.read()
        
        if not content.strip():
            print("El archivo de auditoría está vacío")
            return
        
        audit_data = json.loads(content)
        results = []
        
        # Procesar vulnerabilidades del npm audit
        if "vulnerabilities" in audit_data:
            for pkg_name, pkg_data in audit_data["vulnerabilities"].items():
                if "via" in pkg_data and pkg_data["via"]:
                    for via_item in pkg_data["via"]:
                        if isinstance(via_item, dict):
                            vulnerability = {
                                "package": pkg_name,
                                "version": pkg_data.get("version", "unknown"),
                                "severity": pkg_data.get("severity", "unknown"),
                                "title": via_item.get("title", "N/A"),
                                "cve": via_item.get("cve", []),
                                "cvss_score": via_item.get("cvss", {}).get("score", "N/A"),
                                "url": via_item.get("url", "N/A"),
                                "fixed_in": pkg_data.get("fixAvailable", False)
                            }
                            if vulnerability["fixed_in"] and isinstance(vulnerability["fixed_in"], dict):
                                vulnerability["fixed_in"] = vulnerability["fixed_in"].get("version", "unknown")
                            results.append(vulnerability)
                        elif isinstance(via_item, str):
                            vulnerability = {
                                "package": pkg_name,
                                "version": pkg_data.get("version", "unknown"),
                                "severity": pkg_data.get("severity", "unknown"),
                                "advisory": via_item,
                                "fixed_in": pkg_data.get("fixAvailable", False)
                            }
                            if vulnerability["fixed_in"] and isinstance(vulnerability["fixed_in"], dict):
                                vulnerability["fixed_in"] = vulnerability["fixed_in"].get("version", "unknown")
                            results.append(vulnerability)
        
        # Guardar resultados procesados
        with open("npm_audit_results.json", "w") as json_file:
            json.dump(results, json_file, indent=4)
        
        print(f"Se han procesado {len(results)} vulnerabilidades en 'npm_audit_results.json'")
        
        # Mostrar resumen por severidad
        severity_count = {}
        for vuln in results:
            severity = vuln.get("severity", "unknown")
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        print("\n--- Resumen de vulnerabilidades por severidad ---")
        for severity, count in severity_count.items():
            print(f"{severity}: {count}")
            
    except json.JSONDecodeError as e:
        print(f"Error al parsear JSON: {e}")
        print("Contenido del archivo:")
        with open(file_path, "r") as f:
            print(f.read()[:500])
    except Exception as e:
        print(f"Error inesperado: {e}")

def generate_summary_report():
    """Genera un reporte consolidado de vulnerabilidades"""
    print("\n--- 6. Generando reporte consolidado ---")
    
    all_vulnerabilities = []
    
    # Cargar vulnerabilidades de Python si existen
    if os.path.exists("audit_results.json"):
        with open("audit_results.json", "r") as f:
            python_vulns = json.load(f)
            for vuln in python_vulns:
                vuln["ecosystem"] = "Python"
                all_vulnerabilities.append(vuln)
    
    # Cargar vulnerabilidades de npm si existen
    if os.path.exists("npm_audit_results.json"):
        with open("npm_audit_results.json", "r") as f:
            npm_vulns = json.load(f)
            for vuln in npm_vulns:
                vuln["ecosystem"] = "Node.js"
                all_vulnerabilities.append(vuln)
    
    # Generar reporte consolidado
    report = {
        "total_vulnerabilities": len(all_vulnerabilities),
        "vulnerabilities": all_vulnerabilities,
        "summary": {
            "Python": len([v for v in all_vulnerabilities if v.get("ecosystem") == "Python"]),
            "Node.js": len([v for v in all_vulnerabilities if v.get("ecosystem") == "Node.js"])
        }
    }
    
    with open("consolidated_report.json", "w") as f:
        json.dump(report, f, indent=4)
    
    print(f"Reporte consolidado generado: {report['total_vulnerabilities']} vulnerabilidades totales")
    print(f"  - Python: {report['summary']['Python']}")
    print(f"  - Node.js: {report['summary']['Node.js']}")

if __name__ == "__main__":
    if run_npm_audit():
        parse_npm_audit_to_json("npm_output.txt")
        generate_summary_report()
    else:
        print("Error en la ejecución de npm audit")
