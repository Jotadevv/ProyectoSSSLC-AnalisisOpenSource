import subprocess
import json

result = subprocess.run(["pip", "freeze"], capture_output=True, text=True)

deps = []
for line in result.stdout.splitlines():
    if "==" in line:
        name, version = line.split("==")
        deps.append({
            "name": name,
            "version": version
        })

with open("dependencias.json", "w") as f:
    json.dump(deps, f, indent=2)

print("Archivo dependencias.json generado")
