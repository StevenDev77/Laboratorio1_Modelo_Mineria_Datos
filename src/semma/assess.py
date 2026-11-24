"""
Fase 5 de SEMMA: Assess (Evaluación del modelo sobre el conjunto de prueba independiente)
Calcula métricas globales y por clase (Precision, Recall, F1-Score),
genera matriz de confusión y análisis cuantitativo de falsos positivos / falsos negativos.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.semma.modify import CodeSecurityFeatureExtractor
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support

FIGURES_DIR = "reports/figures"
os.makedirs(FIGURES_DIR, exist_ok=True)
os.makedirs("reports", exist_ok=True)

def run_assess_phase():
    print("=== FASE 5: ASSESS (EVALUACIÓN DEL MODELO EN TEST INDEPENDIENTE) ===")
    test_df = pd.read_csv("data/processed/test.csv")

    pipeline = joblib.load("models/feature_pipeline.joblib")
    le = joblib.load("models/label_encoder.joblib")
    model = joblib.load("models/vulnerability_classifier.joblib")
    with open("models/model_metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)

    X_test_raw = test_df['code_snippet']
    y_test_raw = test_df['category']

    X_test = pipeline.transform(X_test_raw)
    y_test = le.transform(y_test_raw)

    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)

    # 1. Métricas por clase y globales
    report_dict = classification_report(y_test, y_pred, target_names=le.classes_, output_dict=True, zero_division=0)
    report_str = classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0)

    print("\n--- INFORME DE CLASIFICACIÓN (CONJUNTO DE PRUEBA) ---")
    print(report_str)

    # 2. Matriz de confusión
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(12, 10))
    sns.heatmap(
        cm,
        annot=True,
        fmt='d',
        cmap='Blues',
        xticklabels=le.classes_,
        yticklabels=le.classes_
    )
    plt.title(f'Matriz de Confusión en Conjunto de Prueba ({meta["champion_model"]})', fontsize=13, fontweight='bold')
    plt.xlabel('Predicción del Modelo', fontweight='bold')
    plt.ylabel('Etiqueta Real', fontweight='bold')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    cm_path = os.path.join(FIGURES_DIR, "confusion_matrix.png")
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"[OK] Matriz de confusión guardada en: {cm_path}")

    # 3. Análisis de Falsos Positivos y Falsos Negativos a nivel binario (Vulnerable vs Seguro)
    # y = 1 (Vulnerable) vs y = 0 (Seguro: SAFE_CODE)
    safe_idx = list(le.classes_).index("SAFE_CODE")
    binary_real = np.array([0 if y == safe_idx else 1 for y in y_test])
    binary_pred = np.array([0 if p == safe_idx else 1 for p in y_pred])

    tp = int(np.sum((binary_real == 1) & (binary_pred == 1)))
    tn = int(np.sum((binary_real == 0) & (binary_pred == 0)))
    fp = int(np.sum((binary_real == 0) & (binary_pred == 1)))
    fn = int(np.sum((binary_real == 1) & (binary_pred == 0)))

    binary_precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    binary_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    binary_f1 = 2 * (binary_precision * binary_recall) / (binary_precision + binary_recall) if (binary_precision + binary_recall) > 0 else 0

    print("\n--- ANÁLISIS BINARIO (DETECCIÓN DE VULNERABILIDADES) ---")
    print(f"Verdaderos Positivos (TP): {tp}")
    print(f"Verdaderos Negativos (TN): {tn}")
    print(f"Falsos Positivos     (FP): {fp} (Código seguro marcado erróneamente como vulnerable)")
    print(f"Falsos Negativos     (FN): {fn} (Vulnerabilidad no detectada)")
    print(f"Precisión Binaria:         {binary_precision:.4f}")
    print(f"Sensibilidad (Recall):     {binary_recall:.4f}")
    print(f"F1-Score Binario:          {binary_f1:.4f}")

    eval_summary = {
        "model_evaluated": meta["champion_model"],
        "test_sample_size": len(test_df),
        "macro_avg_f1": report_dict["macro avg"]["f1-score"],
        "weighted_avg_f1": report_dict["weighted avg"]["f1-score"],
        "accuracy": report_dict["accuracy"],
        "binary_metrics": {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "precision": round(binary_precision, 4),
            "recall": round(binary_recall, 4),
            "f1_score": round(binary_f1, 4)
        },
        "per_class_metrics": {
            cls: {
                "precision": report_dict[cls]["precision"],
                "recall": report_dict[cls]["recall"],
                "f1_score": report_dict[cls]["f1-score"],
                "support": report_dict[cls]["support"]
            }
            for cls in le.classes_
        }
    }

    eval_json_path = "reports/eval_metrics.json"
    with open(eval_json_path, "w", encoding="utf-8") as f:
        json.dump(eval_summary, f, indent=2, ensure_ascii=False)
    print(f"[OK] Resumen de evaluación exportado en '{eval_json_path}'")

if __name__ == "__main__":
    run_assess_phase()
