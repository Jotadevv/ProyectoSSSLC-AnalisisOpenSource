import subprocess
import json
import os
import sys

def run_audit():
    print("--- 1. Instalando pip-audit ---")
    subprocess.run([sys.executable, "-m", "pip", "install", "pip-audit"], check=True)

    print("--- 2. Ejecutando auditoría y generando archivo ---")
    # Redirigimos la salida estándar al archivo txt
    with open("python_output.txt", "w") as f:
        subprocess.run([sys.executable, "-m", "pip_audit"], stdout=f, stderr=subprocess.STDOUT)

def parse_to_json(file_path):
    print("--- 3. Parseando resultados a JSON ---")
    results = []
    
    if not os.path.exists(file_path):
        print("Error: No se encontró el archivo de salida.")
        return

    with open(file_path, "r") as f:
        lines = f.readlines()

    # Bandera para saber cuándo empezar a procesar
    encontrado_inicio = False

    for line in lines:
        line = line.strip()
        
        # Saltamos todo hasta encontrar la línea que empieza con guiones
        if not encontrado_inicio:
            if line.startswith("---"):
                encontrado_inicio = True
            continue # Saltamos la línea actual (sea el encabezado o los guiones)

        # Si llegamos aquí, estamos en las líneas de datos 
        parts = line.split()
        
        # Validamos que la línea tenga el contenido mínimo esperado
        if len(parts) >= 3:
            entry = {
                "name": parts[0],
                "version": parts[1],
                "id": parts[2],
                "fix_versions": parts[3] if len(parts) > 3 else "N/A"
            }
            results.append(entry)

    # Guardar el resultado final
    with open("audit_results.json", "w") as json_file:
        json.dump(results, json_file, indent=4)
    
    print(f"Se han procesado {len(results)} vulnerabilidades en 'audit_results.json'.")

if __name__ == "__main__":
    run_audit()
    parse_to_json("python_output.txt")