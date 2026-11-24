"""
Módulo de Clasificación e Inferencia con Modelos de Minería de Datos
Utiliza el pipeline y modelo serializados de SEMMA para clasificar patrones y asociar estándares OWASP.
"""

import os
import json
import joblib
import numpy as np
from typing import List, Dict, Any

from src.semma.modify import CodeSecurityFeatureExtractor

# Mapeo descriptivo amigable para el reporte
CATEGORY_DESCRIPTIONS = {
    "SQL_INJECTION": "Inyección SQL mediante concatenación directa de parámetros en consulta",
    "COMMAND_INJECTION": "Inyección de comandos del sistema operativo sin sanitización",
    "BOLA_IDOR": "Autorización insuficiente a nivel de objeto (BOLA/IDOR)",
    "MISSING_FUNCTION_AUTH": "Falta de control de acceso a nivel de función o endpoint privilegiado",
    "BROKEN_AUTHENTICATION": "Mecanismo defectuoso de autenticación o verificación de token JWT insegura",
    "WEAK_CRYPTO_HASH": "Uso de algoritmo criptográfico débil u obsoleto (MD5/SHA1/DES)",
    "HARDCODED_SECRET": "Credenciales, secretos JWT o llaves privadas embebidas en código/configuración",
    "SECURITY_MISCONFIG": "Configuración de seguridad incorrecta o modo depuración activo",
    "SSRF": "Falsificación de solicitudes del lado del servidor (SSRF) con URL no neutralizada",
    "RATE_LIMIT_ABSENCE": "Ausencia de límite de consumo de recursos o rate limiting en endpoint",
    "MASS_ASSIGNMENT": "Modificación no controlada de propiedades del objeto (Mass Assignment)",
    "EXCEPTIONAL_HANDLING": "Manejo inadecuado de excepciones o silenciamiento de fallas críticas"
}

class VulnerabilityClassifierEngine:
    def __init__(self, model_dir: str = None, data_dir: str = None):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
        if model_dir is None:
            model_dir = os.path.join(base_dir, "models")
        if data_dir is None:
            data_dir = os.path.join(base_dir, "data", "processed")

        self.model_dir = model_dir
        self.pipeline_path = os.path.join(model_dir, "feature_pipeline.joblib")
        self.encoder_path = os.path.join(model_dir, "label_encoder.joblib")
        self.model_path = os.path.join(model_dir, "vulnerability_classifier.joblib")
        self.mapping_path = os.path.join(data_dir, "cwe_owasp_mapping.json")

        self._load_artifacts()

    def _load_artifacts(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Modelo no encontrado en {self.model_path}. Ejecute el pipeline SEMMA primero.")

        self.pipeline = joblib.load(self.pipeline_path)
        self.label_encoder = joblib.load(self.encoder_path)
        self.model = joblib.load(self.model_path)

        with open(self.mapping_path, "r", encoding="utf-8") as f:
            mapping_data = json.load(f)
            self.mappings = {m["cwe"]: m for m in mapping_data["mappings"]}

        # Mapeo por categoría técnica
        self.cat_to_cwe = {
            "SQL_INJECTION": "CWE-89",
            "COMMAND_INJECTION": "CWE-78",
            "BOLA_IDOR": "CWE-639",
            "MISSING_FUNCTION_AUTH": "CWE-862",
            "BROKEN_AUTHENTICATION": "CWE-287",
            "WEAK_CRYPTO_HASH": "CWE-327",
            "HARDCODED_SECRET": "CWE-798",
            "SECURITY_MISCONFIG": "CWE-16",
            "SSRF": "CWE-918",
            "RATE_LIMIT_ABSENCE": "CWE-770",
            "MASS_ASSIGNMENT": "CWE-915",
            "EXCEPTIONAL_HANDLING": "CWE-703"
        }

    def predict_candidates(self, candidates: List[Dict[str, Any]], confidence_threshold: float = 0.55) -> List[Dict[str, Any]]:
        if not candidates:
            return []

        snippets = [c["snippet"] for c in candidates]
        X = self.pipeline.transform(snippets)

        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)

        findings = []
        finding_counter = 1
        seen_locations = set()

        for idx, (pred_idx, probas) in enumerate(zip(predictions, probabilities)):
            predicted_class = self.label_encoder.inverse_transform([pred_idx])[0]
            confidence = float(np.max(probas))

            # Ignorar si el modelo lo clasifica como SAFE_CODE o la confianza es baja
            if predicted_class == "SAFE_CODE" or confidence < confidence_threshold:
                continue

            cand = candidates[idx]
            loc_key = (cand["file"], cand["start_line"], predicted_class)
            if loc_key in seen_locations:
                continue
            seen_locations.add(loc_key)

            cwe_id = self.cat_to_cwe.get(predicted_class, "CWE-000")
            cwe_info = self.mappings.get(cwe_id, {})

            owasp_top10 = cwe_info.get("owasp_top10_2025", "N/A")
            owasp_api = cwe_info.get("owasp_api_2023", "N/A")
            severity = cwe_info.get("severity", "Media")
            recommendation = cwe_info.get("recommendation", "Revisar y corregir conforme a guías OWASP.")
            problem_desc = CATEGORY_DESCRIPTIONS.get(predicted_class, cwe_info.get("description", "Vulnerabilidad potencial detectada"))

            finding = {
                "id": f"HALLAZGO_{finding_counter:03d}",
                "service": cand["service"],
                "file": cand["file"],
                "line": cand["start_line"],
                "category": predicted_class,
                "cwe": cwe_id,
                "owasp_top10": owasp_top10,
                "owasp_api": owasp_api,
                "problem": problem_desc,
                "confidence": round(confidence, 2),
                "severity": severity,
                "status": "Requiere verificación",
                "evidence": cand["snippet"],
                "recommendation": recommendation
            }
            findings.append(finding)
            finding_counter += 1

        return findings
