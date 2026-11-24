"""
Servidor Web Flask de VulnMiner
Proporciona una interfaz gráfica moderna para ejecutar escaneos de seguridad,
visualizar la metodología SEMMA, explorar datasets y analizar hallazgos OWASP.
"""

import os
import sys
import json
import pandas as pd
from flask import Flask, render_template, request, jsonify, send_from_directory

# Asegurar importaciones
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, BASE_DIR)

from src.scanner.discovery import discover_project_structure
from src.scanner.extractor import extract_code_candidates
from src.scanner.classifier import VulnerabilityClassifierEngine
from src.scanner.reporter import generate_json_report, generate_html_report

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static")
)

# Inicializar motor de inferencia una sola vez para alto rendimiento
classifier_engine = None

def get_classifier():
    global classifier_engine
    if classifier_engine is None:
        classifier_engine = VulnerabilityClassifierEngine()
    return classifier_engine

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/select-folder", methods=["POST", "GET"])
def select_folder():
    """
    Abre el cuadro de diálogo nativo de Windows / SO para que el usuario seleccione una carpeta.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askdirectory(
            title="Seleccionar Carpeta del Proyecto de Microservicios",
            initialdir=BASE_DIR
        )
        root.destroy()

        if selected:
            # Normalizar barra inclinada para visualización amigable
            clean_path = os.path.normpath(selected)
            return jsonify({"status": "selected", "path": clean_path})
        else:
            return jsonify({"status": "cancelled", "path": None})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/open-folder", methods=["POST"])
def open_folder():
    """
    Abre la carpeta en el Explorador de archivos del sistema operativo (Windows Explorer).
    """
    data = request.get_json() or {}
    folder_path = data.get("path", "").strip()

    if not folder_path:
        folder_path = BASE_DIR

    # Si es ruta relativa, resolver respecto a BASE_DIR
    if not os.path.isabs(folder_path):
        folder_path = os.path.abspath(os.path.join(BASE_DIR, folder_path))

    if not os.path.exists(folder_path):
        return jsonify({"error": f"La carpeta '{folder_path}' no existe."}), 404

    try:
        if sys.platform == "win32":
            os.startfile(folder_path)
        else:
            import subprocess
            subprocess.Popen(["xdg-open", folder_path])
        return jsonify({"status": "opened", "path": folder_path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/list-local-folders", methods=["GET"])
def list_local_folders():
    """
    Lista las subcarpetas del proyecto para selección rápida.
    """
    folders = []
    try:
        for entry in os.scandir(BASE_DIR):
            if entry.is_dir() and not entry.name.startswith((".", "__", "venv")):
                folders.append(entry.name)
        folders.sort()
    except Exception:
        pass
    return jsonify({"folders": folders})

@app.route("/api/semma-metrics", methods=["GET"])
def get_semma_metrics():
    metadata_path = os.path.join(BASE_DIR, "models", "model_metadata.json")
    eval_path = os.path.join(BASE_DIR, "reports", "eval_metrics.json")
    dataset_path = os.path.join(BASE_DIR, "data", "processed", "dataset_vulnerabilidades.csv")

    meta = {}
    eval_metrics = {}
    stats = {}

    if os.path.exists(metadata_path):
        with open(metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

    if os.path.exists(eval_path):
        with open(eval_path, "r", encoding="utf-8") as f:
            eval_metrics = json.load(f)

    if os.path.exists(dataset_path):
        df = pd.read_csv(dataset_path)
        stats = {
            "total_records": len(df),
            "vulnerable_records": int((df["is_vulnerable"] == 1).sum()),
            "safe_records": int((df["is_vulnerable"] == 0).sum()),
            "languages": df["language"].value_counts().to_dict(),
            "categories": df["category"].value_counts().to_dict(),
            "owasp_top10": df[df["owasp_top10"] != "NONE"]["owasp_top10"].value_counts().to_dict(),
            "owasp_api": df[df["owasp_api"] != "NONE"]["owasp_api"].value_counts().to_dict()
        }

    return jsonify({
        "metadata": meta,
        "eval_metrics": eval_metrics,
        "dataset_stats": stats
    })

@app.route("/api/scan", methods=["POST"])
def run_scan():
    data = request.get_json() or {}
    target_path = data.get("path", "test_microservices")
    standards = data.get("standards", "owasp2025,api2023")

    full_target_path = os.path.abspath(os.path.join(BASE_DIR, target_path))
    if not os.path.exists(full_target_path):
        return jsonify({"error": f"La ruta '{target_path}' no existe en el sistema."}), 400

    try:
        # 1. Descubrimiento
        structure = discover_project_structure(full_target_path)
        files = structure["analyzable_files"]

        # 2. Extracción
        all_candidates = []
        for f_info in files:
            cands = extract_code_candidates(f_info)
            all_candidates.extend(cands)

        # 3. Clasificación
        engine = get_classifier()
        findings = engine.predict_candidates(all_candidates)

        # 4. Guardar reportes en reportes/
        output_dir = os.path.join(BASE_DIR, "reportes")
        os.makedirs(output_dir, exist_ok=True)
        json_path = os.path.join(output_dir, "analisis.json")
        html_path = os.path.join(output_dir, "analisis.html")

        scan_result = {
            "project_name": structure["project_name"],
            "root_path": structure["root_path"],
            "microservices_count": structure["total_services"],
            "microservices": structure["microservices"],
            "files_analyzed_count": structure["total_files"],
            "findings_count": len(findings),
            "findings": findings,
            "reports_generated": ["reportes/analisis.json", "reportes/analisis.html"]
        }

        generate_json_report(scan_result, json_path)
        generate_html_report(scan_result, html_path)

        return jsonify(scan_result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/dataset", methods=["GET"])
def get_dataset():
    dataset_path = os.path.join(BASE_DIR, "data", "processed", "dataset_vulnerabilidades.csv")
    if not os.path.exists(dataset_path):
        return jsonify({"records": []})

    df = pd.read_csv(dataset_path)

    # Filtros opcionales
    lang = request.args.get("language")
    cat = request.args.get("category")
    vuln = request.args.get("is_vulnerable")

    if lang:
        df = df[df["language"] == lang]
    if cat:
        df = df[df["category"] == cat]
    if vuln is not None and vuln != "":
        df = df[df["is_vulnerable"] == int(vuln)]

    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))

    total = len(df)
    sliced = df.iloc[offset:offset+limit]

    return jsonify({
        "total": total,
        "offset": offset,
        "limit": limit,
        "records": sliced.to_dict(orient="records")
    })

@app.route("/api/mappings", methods=["GET"])
def get_mappings():
    mapping_path = os.path.join(BASE_DIR, "data", "processed", "cwe_owasp_mapping.json")
    if os.path.exists(mapping_path):
        with open(mapping_path, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    return jsonify({"mappings": []})

@app.route("/api/dictionary", methods=["GET"])
def get_dictionary():
    dict_path = os.path.join(BASE_DIR, "data", "processed", "data_dictionary.json")
    if os.path.exists(dict_path):
        with open(dict_path, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    return jsonify({})

@app.route("/figures/<path:filename>")
def serve_figure(filename):
    figures_dir = os.path.join(BASE_DIR, "reports", "figures")
    return send_from_directory(figures_dir, filename)

@app.route("/reports/<path:filename>")
def serve_report(filename):
    report_dir = os.path.join(BASE_DIR, "reportes")
    return send_from_directory(report_dir, filename)

def start_server(host="127.0.0.1", port=5000, debug=False):
    print(f"\n=======================================================")
    print(f"🚀 VulnMiner Web Interface iniciada en:")
    print(f"👉 http://{host}:{port}/")
    print(f"=======================================================\n")
    app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    start_server(debug=True)
