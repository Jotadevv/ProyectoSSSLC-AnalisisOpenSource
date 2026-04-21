import subprocess
import json
import os
import sys

def run_npm_audit():
    print("1. Verificando npm")
    npm_cmd = r"C:\Program Files\nodejs\npm.cmd"
    try:
        subprocess.run([npm_cmd, "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: npm no está instalado o no se encuentra en la ruta esperada")
        print("Verifica que Node.js esté instalado correctamente")
        return False

    print("2. Verificando package.json")
    if not os.path.exists("package.json"):
        print("Error: No se encontró package.json en el directorio actual")
        return False

    print("3. Ejecutando npm audit")
    try:
        result = subprocess.run([npm_cmd, "audit", "--json"], capture_output=True, text=True, check=True)
        audit_data = json.loads(result.stdout)
        with open("npm_output.txt", "w", encoding="utf-8") as f:
            json.dump(audit_data, f, indent=2, ensure_ascii=False)
        print("Resultado guardado en npm_output.txt")
    except subprocess.CalledProcessError as e:
        print(f"Error ejecutando npm audit: {e}")
        return False
    except json.JSONDecodeError as e:
        print(f"Error parseando JSON: {e}")
        return False

    print("4. Procesando vulnerabilidades")
    vulnerabilities = []
    if "vulnerabilities" in audit_data:
        for pkg_name, pkg_data in audit_data["vulnerabilities"].items():
            vuln = {
                "package": pkg_name,
                "severity": pkg_data.get("severity", "unknown"),
                "title": pkg_data.get("title", f"Vulnerabilidad en {pkg_name}"),
                "version": pkg_data.get("range", "unknown"),
                "fix_available": "fixAvailable" in pkg_data
            }
            if "fixAvailable" in pkg_data:
                vuln["fixed_in"] = pkg_data["fixAvailable"].get("version", "Disponible")
            vulnerabilities.append(vuln)

    with open("npm_audit_results.json", "w", encoding="utf-8") as json_file:
        json.dump(vulnerabilities, json_file, indent=2, ensure_ascii=False)

    print(f"Procesadas {len(vulnerabilities)} vulnerabilidades")
    print("Resultado guardado en npm_audit_results.json")
    return True

def consolidate_reports():
    print("5. Consolidando reportes")

    # Leer resultados de npm
    npm_vulns = []
    if os.path.exists("npm_audit_results.json"):
        try:
            with open("npm_audit_results.json", "r") as f:
                npm_vulns = json.load(f)
        except json.JSONDecodeError:
            print("Error leyendo npm_audit_results.json")

    # Leer resultados de Python (si existen)
    python_vulns = []
    if os.path.exists("audit_results.json"):
        try:
            with open("audit_results.json", "r") as f:
                python_vulns = json.load(f)
        except json.JSONDecodeError:
            print("Error leyendo audit_results.json")

    consolidated = {
        "npm_vulnerabilities": npm_vulns,
        "python_vulnerabilities": python_vulns,
        "total_npm": len(npm_vulns),
        "total_python": len(python_vulns),
        "total_vulnerabilities": len(npm_vulns) + len(python_vulns)
    }

    with open("consolidated_report.json", "w") as f:
        json.dump(consolidated, f, indent=2, ensure_ascii=False)

    print(f"Reporte consolidado guardado en consolidated_report.json")
    print(f"Total vulnerabilidades: {consolidated['total_vulnerabilities']}")

if __name__ == "__main__":
    if run_npm_audit():
        consolidate_reports()
        print("Auditoría completada exitosamente")
    else:
        print("Error en la auditoría")
        sys.exit(1)
import subprocess
import json
import os
import sys

def run_npm_audit():
    print("1. Verificando npm")
    npm_cmd = r"C:\Program Files\nodejs\npm.cmd"
    try:
        subprocess.run([npm_cmd, "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: npm no está instalado o no se encuentra en la ruta esperada")
        print("Verifica que Node.js esté instalado correctamente")
        return False
    
    print("2. Verificando package.json")
    if not os.path.exists("package.json"):
        print("Error: No se encontró package.json en el directorio actual")
        return False
    
    print("3. Instalando dependencias (si es necesario)")
    if os.path.exists("node_modules"):
        print("node_modules ya existe, saltando instalación")
    else:
        try:
            subprocess.run([npm_cmd, "install"], check=True)
            print("Dependencias instaladas correctamente")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error instalando dependencias: {e}")
            return False
    
    print("4. Ejecutando npm audit y generando archivo")
    try:
        with open("npm_output.txt", "w", encoding="utf-8") as f:
            result = subprocess.run([npm_cmd, "audit", "--json"], 
                                  stdout=f, stderr=subprocess.STDOUT, 
                                  text=True)
        # npm audit puede retornar código de error incluso si funciona
        print(f"npm audit completado con código {result.returncode}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error ejecutando npm audit: {e}")
        return False

def parse_npm_audit_to_json(file_path):
    print("5. Parseando resultados de npm audit a JSON")
    
    if not os.path.exists(file_path):
        print(f"Error: No se encontró el archivo {file_path}")
        return
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        if not content.strip():
            print("El archivo de auditoría está vacío")
            return
        
        audit_data = json.loads(content)
        results = []
        
        # Procesar vulnerabilidades del npm audit
        if "vulnerabilities" in audit_data:
            for pkg_name, pkg_data in audit_data["vulnerabilities"].items():
                severity = pkg_data.get("severity", "unknown")
                version = pkg_data.get("version", "unknown")
                
                # Determinar si hay fix disponible
                fix_available = pkg_data.get("fixAvailable", False)
                if isinstance(fix_available, dict):
                    fixed_version = fix_available.get("version", "Disponible")
                elif fix_available is True:
                    fixed_version = "Disponible"
                else:
                    fixed_version = "No disponible"
                
                # Procesar la información de 'via'
                via_info = pkg_data.get("via", [])
                if not isinstance(via_info, list):
                    via_info = [via_info]
                
                for via_item in via_info:
                    if isinstance(via_item, dict):
                        # Es un objeto con información detallada
                        vuln_name = via_item.get("title", via_item.get("name", pkg_name))
                        vuln_url = via_item.get("url", "")
                        vuln_severity = via_item.get("severity", severity)
                        
                        vulnerability = {
                            "name": vuln_name,
                            "package": pkg_name,
                            "version": version,
                            "severity": vuln_severity,
                            "fixed_in": fixed_version,
                            "url": vuln_url
                        }
                    elif isinstance(via_item, str):
                        # Es solo un string con el nombre de la dependencia
                        vulnerability = {
                            "name": via_item,
                            "package": pkg_name,
                            "version": version,
                            "severity": severity,
                            "fixed_in": fixed_version
                        }
                    else:
                        continue
                    
                    results.append(vulnerability)
        
        # Guardar resultados procesados
        with open("npm_audit_results.json", "w", encoding="utf-8") as json_file:
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
        with open(file_path, "r", encoding="utf-8") as f:
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
