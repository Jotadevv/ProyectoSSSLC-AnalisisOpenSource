from flask import Flask, send_from_directory
import os
import json
import subprocess
import sys
from flask import request

app = Flask(__name__, static_folder="dist", static_url_path="")


# 👉 Servir React
@app.route("/")
def serve_react():
    return send_from_directory(app.static_folder, "index.html")


# 👉 IMPORTANTE: para rutas internas de React (SPA)
@app.route("/<path:path>")
def serve_static(path):
    file_path = os.path.join(app.static_folder, path)

    if os.path.exists(file_path):
        return send_from_directory(app.static_folder, path)

    # fallback a React
    return send_from_directory(app.static_folder, "index.html")


# =====================
# 🔍 APIs (igual que antes)
# =====================

@app.route("/audit/python", methods=["POST"])
def audit_python():
    file = request.files["file"]
    file.save("requirements.txt")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    python_audit_script = os.path.join(script_dir, "python_audit.py")

    result = subprocess.run([sys.executable, python_audit_script], check=False)
    if result.returncode not in (0, 1):
        print("Error ejecutando python_audit.py:", result.returncode)

    if not os.path.exists("audit_results.json"):
        return {"error": "No se generó audit_results.json"}, 500

    with open("audit_results.json") as f:
        return json.load(f)


@app.route("/audit/npm", methods=["POST"])
def audit_npm():
    file = request.files["file"]
    file.save("package.json")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    npm_audit_script = os.path.join(script_dir, "npm_audit.py")

    result = subprocess.run([sys.executable, npm_audit_script], check=False)
    if result.returncode != 0:
        print("Error ejecutando npm_audit.py:", result.returncode)

    if not os.path.exists("npm_audit_results.json"):
        return {"error": "No se generó npm_audit_results.json"}, 500

    with open("npm_audit_results.json") as f:
        return json.load(f)


@app.route("/audit/python_output", methods=["GET"])
def get_python_output():
    if not os.path.exists("python_output.json"):
        return {"error": "No se encontró python_output.json"}, 404

    try:
        with open("python_output.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError as e:
        return {"error": f"Error al parsear JSON: {str(e)}"}, 500


if __name__ == "__main__":
    app.run(debug=True, port=8000)