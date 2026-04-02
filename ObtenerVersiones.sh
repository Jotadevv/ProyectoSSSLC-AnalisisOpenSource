pip freeze | python -c "
import sys, json
deps = []
for line in sys.stdin:
    if '==' in line:
        name, version = line.strip().split('==')
        deps.append({'name': name, 'version': version})
print(json.dumps(deps, indent=2))
" > dependencias.json
