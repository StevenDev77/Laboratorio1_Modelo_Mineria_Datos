"""
Módulo de Extracción de Fragmentos de Código y Bloques de Configuración
Segmenta los archivos en bloques contextuales con números de línea para análisis del modelo.
"""

import os
import re
from typing import List, Dict, Any

def extract_code_candidates(file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Lee un archivo fuente o configuración y extrae bloques candidatos con contexto de línea.
    """
    candidates = []
    file_path = file_info["absolute_path"]

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        return candidates

    if not lines:
        return candidates

    total_lines = len(lines)

    # 1. Ventana deslizante para capturar construcciones multilínea (1 a 5 líneas)
    window_size = 4
    step = 2

    for i in range(0, total_lines, step):
        chunk_lines = lines[i:i + window_size]
        chunk_text = "".join(chunk_lines).strip()

        # Filtrar fragmentos vacíos o puramente comentarios triviales
        if not chunk_text or len(chunk_text) < 15:
            continue

        start_line = i + 1

        candidates.append({
            "service": file_info["service"],
            "file": file_info["relative_path"],
            "start_line": start_line,
            "snippet": chunk_text
        })

    # 2. Análisis por patrones clave directos para no perder declaraciones puntuales
    for idx, line in enumerate(lines):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("//") or line_clean.startswith("#"):
            continue

        # Si contiene palabras clave de interés en seguridad
        if re.search(r'(execute|query|password|secret|key|system|exec|md5|sha1|cors|debug|openStream|axios|fetch|pass|jwt)', line_clean, re.IGNORECASE):
            # Tomar línea con 1 anterior y 1 posterior como contexto
            ctx_start = max(0, idx - 1)
            ctx_end = min(total_lines, idx + 2)
            context_snippet = "".join(lines[ctx_start:ctx_end]).strip()

            candidates.append({
                "service": file_info["service"],
                "file": file_info["relative_path"],
                "start_line": idx + 1,
                "snippet": context_snippet
            })

    return candidates
