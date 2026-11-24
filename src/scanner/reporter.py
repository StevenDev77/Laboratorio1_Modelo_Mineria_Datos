"""
Módulo de Reportes de Seguridad (Consola, JSON y HTML)
Genera las salidas requeridas con evidencias, clasificaciones OWASP y recomendaciones.
"""

import os
import json
from typing import Dict, List, Any

def render_console_summary(scan_result: Dict[str, Any]):
    """
    Imprime en consola con el formato solicitado en la sección 8.3.1 de la guía.
    """
    findings = scan_result["findings"]
    print("========================================")
    print("VULNMINER - SECURITY SCAN")
    print("========================================")
    print(f"Proyecto: {scan_result['project_name']}")
    print(f"Microservicios identificados: {scan_result['microservices_count']}")
    print(f"Archivos analizados: {scan_result['files_analyzed_count']}")
    print(f"Hallazgos potenciales: {len(findings)}")

    for idx, f in enumerate(findings, 1):
        print("----------------------------------------")
        print(f"HALLAZGO {idx:03d}")
        print(f"Servicio: {f['service']}")
        print(f"Archivo: {f['file']}")
        print(f"Linea: {f['line']}")
        print(f"OWASP Top 10: {f['owasp_top10']}")
        print(f"OWASP API: {f['owasp_api']}")
        print("Problema potencial:")
        print(f"{f['problem']}")
        print(f"Confianza del modelo: {f['confidence']:.2f}")
        print(f"Severidad estimada: {f['severity']}")
        print(f"Estado: {f['status']}")

    print("----------------------------------------")
    print("REPORTES GENERADOS")
    for r in scan_result.get("reports_generated", []):
        print(r)
    print("========================================")

def generate_json_report(scan_result: Dict[str, Any], output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scan_result, f, indent=2, ensure_ascii=False)

def generate_html_report(scan_result: Dict[str, Any], output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    findings = scan_result["findings"]
    p_name = scan_result["project_name"]
    n_services = scan_result["microservices_count"]
    n_files = scan_result["files_analyzed_count"]
    n_vulns = len(findings)

    # Conteo por severidad
    sev_counts = {"Crítica": 0, "Alta": 0, "Media": 0, "Baja": 0}
    for f in findings:
        s = f.get("severity", "Media")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    findings_rows = ""
    for idx, f in enumerate(findings, 1):
        sev_badge_color = {
            "Crítica": "#d63031",
            "Alta": "#e17055",
            "Media": "#fdcb6e; color: #2d3436;",
            "Baja": "#00b894"
        }.get(f['severity'], "#0984e3")

        escaped_evidence = f['evidence'].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        findings_rows += f"""
        <div class="finding-card">
            <div class="finding-header">
                <div>
                    <span class="finding-id">HALLAZGO #{idx:03d}</span>
                    <span class="badge" style="background-color: {sev_badge_color}">{f['severity']}</span>
                    <span class="badge badge-owasp">{f['owasp_top10']}</span>
                    <span class="badge badge-api">{f['owasp_api']}</span>
                    <span class="badge badge-cwe">{f['cwe']}</span>
                </div>
                <div class="confidence">Confianza Modelo: <strong>{f['confidence']*100:.1f}%</strong></div>
            </div>
            <div class="finding-body">
                <p><strong>Microservicio:</strong> <code>{f['service']}</code> | <strong>Archivo:</strong> <code>{f['file']}</code> (Línea: {f['line']})</p>
                <p><strong>Descripción:</strong> {f['problem']}</p>
                <p><strong>Recomendación:</strong> {f['recommendation']}</p>
                <details>
                    <summary>Ver Evidencia Técnica (Fragmento de Código)</summary>
                    <pre><code>{escaped_evidence}</code></pre>
                </details>
            </div>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Vulnerabilidades - {p_name}</title>
    <style>
        :root {{
            --primary: #2d3436;
            --secondary: #0984e3;
            --bg: #f8f9fa;
            --card-bg: #ffffff;
            --text: #2d3436;
            --border: #dfe6e9;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px 20px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3799, #0c2461);
            color: white;
            padding: 35px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        .header h1 {{ margin: 0 0 10px 0; font-size: 28px; }}
        .header p {{ margin: 0; opacity: 0.9; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: var(--card-bg);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border);
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }}
        .metric-value {{
            font-size: 32px;
            font-weight: bold;
            color: var(--secondary);
            margin-bottom: 5px;
        }}
        .metric-label {{ font-size: 14px; color: #636e72; text-transform: uppercase; }}
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }}
        .finding-header {{
            background: #f1f2f6;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
        }}
        .finding-id {{ font-weight: bold; font-size: 16px; margin-right: 10px; }}
        .finding-body {{ padding: 20px; }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            color: white;
            margin-right: 6px;
        }}
        .badge-owasp {{ background-color: #6c5ce7; }}
        .badge-api {{ background-color: #00cec9; color: #2d3436; }}
        .badge-cwe {{ background-color: #b2bec3; color: #2d3436; }}
        code {{ background: #f1f2f6; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
        pre {{
            background: #2d3436;
            color: #dfe6e9;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 13px;
        }}
        summary {{ cursor: pointer; color: var(--secondary); font-weight: bold; margin-top: 10px; }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            color: #74b9ff;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>VulnMiner: Reporte de Auditoría y Seguridad de Microservicios</h1>
            <p><strong>Proyecto Analizado:</strong> {p_name} | <strong>Estándares:</strong> OWASP Top 10:2025 & OWASP API Security Top 10:2023</p>
            <p><strong>Motor de Minería de Datos:</strong> Clasificador Supervisado SEMMA (Sin LLMs)</p>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{n_services}</div>
                <div class="metric-label">Microservicios</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{n_files}</div>
                <div class="metric-label">Archivos Analizados</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #d63031;">{n_vulns}</div>
                <div class="metric-label">Hallazgos Potenciales</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #e17055;">{sev_counts['Crítica'] + sev_counts['Alta']}</div>
                <div class="metric-label">Críticos / Altos</div>
            </div>
        </div>

        <h2>Detalle de Hallazgos Clasificados</h2>
        {findings_rows if findings_rows else '<p>No se identificaron patrones de vulnerabilidad con la confianza requerida.</p>'}

        <div class="footer">
            <p>Generado automáticamente por VulnMiner CLI | Universidad de las Fuerzas Armadas ESPE</p>
        </div>
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
