"""
CLI Principal de VulnMiner
Herramienta de análisis estático y minería de datos para clasificación de vulnerabilidades
en arquitecturas de microservicios.
"""

import os
import sys
import argparse
from typing import List

# Asegurar importación de módulos internos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.scanner.discovery import discover_project_structure
from src.scanner.extractor import extract_code_candidates
from src.scanner.classifier import VulnerabilityClassifierEngine
from src.scanner.reporter import render_console_summary, generate_json_report, generate_html_report

def run_scan(target_path: str, standards: str, formats: str, output_dir: str):
    target_path = os.path.abspath(target_path)
    output_dir = os.path.abspath(output_dir)

    # 1. Descubrimiento del proyecto
    structure = discover_project_structure(target_path)
    files = structure["analyzable_files"]

    # 2. Extracción de candidatos
    all_candidates = []
    for f_info in files:
        cands = extract_code_candidates(f_info)
        all_candidates.extend(cands)

    # 3. Clasificación con modelo de minería de datos
    classifier = VulnerabilityClassifierEngine()
    findings = classifier.predict_candidates(all_candidates)

    # Filtrar según estándares si se especifican
    enabled_standards = [s.strip().lower() for s in standards.split(",")]
    # Por defecto owasp2025 y api2023 están activos

    # 4. Reportes
    formats_list = [fmt.strip().lower() for fmt in formats.split(",")]
    reports_generated = []

    scan_result = {
        "project_name": structure["project_name"],
        "root_path": structure["root_path"],
        "microservices_count": structure["total_services"],
        "microservices": list(structure["microservices"].keys()),
        "files_analyzed_count": structure["total_files"],
        "findings_count": len(findings),
        "findings": findings,
        "reports_generated": []
    }

    if "json" in formats_list:
        json_path = os.path.join(output_dir, "analisis.json")
        scan_result["reports_generated"].append(os.path.relpath(json_path, os.getcwd()).replace("\\", "/"))
        generate_json_report(scan_result, json_path)

    if "html" in formats_list:
        html_path = os.path.join(output_dir, "analisis.html")
        scan_result["reports_generated"].append(os.path.relpath(html_path, os.getcwd()).replace("\\", "/"))
        generate_html_report(scan_result, html_path)

    # 5. Salida en consola
    render_console_summary(scan_result)

def main():
    parser = argparse.ArgumentParser(
        prog="vulnminer",
        description="VulnMiner CLI: Auditoría inteligente de vulnerabilidades en microservicios mediante Minería de Datos."
    )
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Comando scan
    scan_parser = subparsers.add_parser("scan", help="Analiza un directorio de microservicios")
    scan_parser.add_argument("path", nargs="?", default=".", help="Ruta del proyecto a analizar (por defecto .)")
    scan_parser.add_argument("--standards", default="owasp2025,api2023", help="Estándares a evaluar (ej: owasp2025,api2023)")
    scan_parser.add_argument("--format", default="json,html", help="Formatos de reporte: json,html")
    scan_parser.add_argument("--output", default="./reportes", help="Directorio de salida de reportes")

    # Comando ui (interfaz web interactiva)
    ui_parser = subparsers.add_parser("ui", help="Inicia la interfaz gráfica web en el navegador")
    ui_parser.add_argument("--host", default="127.0.0.1", help="Host para la aplicación web")
    ui_parser.add_argument("--port", type=int, default=5000, help="Puerto de escucha (por defecto 5000)")
    ui_parser.add_argument("--no-browser", action="store_true", help="No abrir automáticamente el navegador")

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args.path, args.standards, args.format, args.output)
    elif args.command == "ui":
        import webbrowser
        from src.web.app import start_server

        url = f"http://{args.host}:{args.port}/"
        if not args.no_browser:
            try:
                webbrowser.open(url)
            except Exception:
                pass
        start_server(host=args.host, port=args.port)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
