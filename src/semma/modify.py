"""
Fase 3 de SEMMA: Modify (Preparación y transformación de datos)
Extrae características estadísticas, sintácticas y TF-IDF a partir de fragmentos de código fuente.
Define y exporta el pipeline reproducible de preprocesamiento.
"""

import re
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import joblib

class CodeSecurityFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extractor de características sintácticas y patrones de seguridad estáticos
    sobre código fuente y configuraciones de microservicios.
    """
    def __init__(self):
        pass

    def fit(self, X, y=None):
        return self

    def _extract_single(self, text):
        if not isinstance(text, str):
            text = str(text) if text is not None else ""
        
        lower_text = text.lower()
        lines = text.splitlines()

        # 1. Indicadores SQL
        has_sql_kw = int(bool(re.search(r'\b(select|insert|update|delete|drop|where|from|join)\b', lower_text)))
        has_sql_concat = int(bool(re.search(r'(\bexecute\s*\(|\bquery\s*\(|\bexecuteQuery\s*\().*(\+|f["\']|\.format|\%s|\$\{)', text)))

        # 2. Indicadores de Comandos del SO
        has_cmd_kw = int(bool(re.search(r'\b(os\.system|subprocess|child_process|execSync|runtime\.getruntime|processbuilder)\b', lower_text)))

        # 3. Indicadores de Secretos / Credenciales
        has_hardcoded_secrets = int(bool(re.search(r'(password|secret|jwt_secret|api_key|private_key)\s*[:=]\s*["\'][a-zA-Z0-9_\-\.\!@\#\$\%\^\&\*\=]{8,}["\']', text, re.IGNORECASE)))

        # 4. Indicadores de Criptografía Débil
        has_weak_crypto = int(bool(re.search(r'\b(md5|sha1|des|ecb|rc4)\b', lower_text)))

        # 5. Indicadores de Autorización / Guards
        has_auth_guards = int(bool(re.search(r'\b(preauthorize|rolesallowed|require_roles|useguards|authguard|ownershipguard|hasrole|depends)\b', lower_text)))

        # 6. Indicadores de Limitación de Recursos (Rate Limit)
        has_rate_limit = int(bool(re.search(r'\b(limiter|ratelimit|throttle|windowms|slowapi)\b', lower_text)))

        # 7. Indicadores de Excepciones Inseguras / Fuga de Errores
        has_empty_catch = int(bool(re.search(r'(except\s+Exception:\s*pass|\/\*\s*ignore\s*\*\/|\/\/ empty catch|catch\s*\([^\)]*\)\s*\{\s*\})', text)))
        has_stacktrace_leak = int(bool(re.search(r'\b(traceback\.format_exc|include-stacktrace:\s*always)\b', lower_text)))

        # 8. Indicadores SSRF
        has_ssrf = int(bool(re.search(r'\b(requests\.get|urllib\.request|openstream|axios\.get|fetch)\s*\(\s*(url|target_url|endpoint|req\.body)', text)))

        # 9. Indicadores Asignación Masiva
        has_mass_assign = int(bool(re.search(r'\b(setattr|copyproperties|findbyidandupdate|req\.body)\b', lower_text)))

        # 10. Indicadores Mala Configuración
        has_misconfig = int(bool(re.search(r'(debug\s*=\s*true|origin\s*:\s*[\'"]\*[\'"]|csrf\(\)\.disable|endpoints.*include.*\*|user root)', lower_text)))

        # Métricas de complejidad superficial
        char_len = len(text)
        line_cnt = len(lines)
        num_parenthesis = text.count('(') + text.count(')')
        num_braces = text.count('{') + text.count('}')

        return [
            has_sql_kw,
            has_sql_concat,
            has_cmd_kw,
            has_hardcoded_secrets,
            has_weak_crypto,
            has_auth_guards,
            has_rate_limit,
            has_empty_catch,
            has_stacktrace_leak,
            has_ssrf,
            has_mass_assign,
            has_misconfig,
            char_len,
            line_cnt,
            num_parenthesis,
            num_braces
        ]

    def transform(self, X):
        features = [self._extract_single(item) for item in X]
        return np.array(features, dtype=float)

def build_preprocessing_pipeline():
    """
    Construye la combinación del vectorizador TF-IDF y el extractor de características sintácticas.
    """
    pipeline = FeatureUnion(
        transformer_list=[
            ('tfidf', TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=2500,
                token_pattern=r'(?u)\b\w+\b|[=<>!]+|[{}();,]',
                lowercase=True
            )),
            ('domain_features', Pipeline([
                ('extractor', CodeSecurityFeatureExtractor()),
                ('scaler', StandardScaler())
            ]))
        ]
    )
    return pipeline

def run_modify_phase():
    train_path = "data/processed/train.csv"
    val_path = "data/processed/val.csv"
    test_path = "data/processed/test.csv"

    print("=== FASE 3: MODIFY (PREPARACIÓN Y TRANSFORMACIÓN) ===")
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    X_train = train_df['code_snippet']
    y_train = train_df['category']

    pipeline = build_preprocessing_pipeline()
    print("Ajustando pipeline de transformación sobre el conjunto de entrenamiento...")
    X_train_trans = pipeline.fit_transform(X_train)
    print(f"Dimensiones de la matriz de características de entrenamiento: {X_train_trans.shape}")

    # Guardar pipeline
    pipeline_file = "models/feature_pipeline.joblib"
    joblib.dump(pipeline, pipeline_file)
    print(f"[OK] Pipeline de extracción y preprocesamiento guardado en '{pipeline_file}'")

if __name__ == "__main__":
    run_modify_phase()
