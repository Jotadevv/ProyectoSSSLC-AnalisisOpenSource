from pathlib import Path

from flask import Flask, jsonify, send_from_directory

app = Flask(__name__, static_folder="dist", static_url_path="")


@app.route("/", methods=["GET"])
def frontend_root():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/<path:path>", methods=["GET"])
def frontend_files(path):
    if path.startswith("api/"):
        return jsonify({"error": "Not Found"}), 404

    static_file = Path(app.static_folder) / path
    if static_file.exists() and static_file.is_file():
        return send_from_directory(app.static_folder, path)

    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    app.run(debug=True)
