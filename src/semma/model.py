"""
Fase 4 de SEMMA: Model (Construcción y comparación de modelos)
Entrena y compara al menos dos algoritmos de clasificación supervisada:
1. Random Forest Classifier
2. Support Vector Machine (Linear SVC con probabilidades calibradas)
3. Logistic Regression
Selecciona el mejor modelo y serializa artefactos para inferencia.
"""

import os
import sys
import time
import json
import joblib
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, f1_score, accuracy_score

from src.semma.modify import build_preprocessing_pipeline

def run_model_phase():
    print("=== FASE 4: MODEL (CONSTRUCCIÓN Y COMPARACIÓN DE MODELOS) ===")
    train_df = pd.read_csv("data/processed/train.csv")
    val_df = pd.read_csv("data/processed/val.csv")

    X_train_raw = train_df['code_snippet']
    y_train_raw = train_df['category']

    X_val_raw = val_df['code_snippet']
    y_val_raw = val_df['category']

    # 1. Ajuste del codificador de etiquetas
    le = LabelEncoder()
    y_train = le.fit_transform(y_train_raw)
    y_val = le.transform(y_val_raw)

    # 2. Pipeline de preprocesamiento
    print("Ajustando pipeline de extracción TF-IDF + Características de Seguridad...")
    pipeline = build_preprocessing_pipeline()
    X_train = pipeline.fit_transform(X_train_raw)
    X_val = pipeline.transform(X_val_raw)

    # Guardar pipeline y codificador
    os.makedirs("models", exist_ok=True)
    joblib.dump(pipeline, "models/feature_pipeline.joblib")
    joblib.dump(le, "models/label_encoder.joblib")

    # 3. Definición de algoritmos candidatos
    algorithms = {
        "Random_Forest": RandomForestClassifier(
            n_estimators=150,
            max_depth=25,
            min_samples_split=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        ),
        "Support_Vector_Machine": CalibratedClassifierCV(
            LinearSVC(C=1.0, class_weight='balanced', random_state=42, max_iter=2000)
        ),
        "Logistic_Regression": LogisticRegression(
            C=2.0,
            max_iter=1000,
            class_weight='balanced',
            random_state=42
        )
    }

    results = []
    trained_models = {}

    for name, model in algorithms.items():
        print(f"\n--- Entrenando algoritmo: {name} ---")
        start_time = time.time()
        model.fit(X_train, y_train)
        train_duration = time.time() - start_time

        # Predicción en validación
        y_val_pred = model.predict(X_val)

        acc = accuracy_score(y_val, y_val_pred)
        macro_f1 = f1_score(y_val, y_val_pred, average='macro')
        weighted_f1 = f1_score(y_val, y_val_pred, average='weighted')

        print(f"Tiempo de entrenamiento: {train_duration:.4f}s")
        print(f"Accuracy en Validación: {acc:.4f}")
        print(f"Macro F1-Score:        {macro_f1:.4f}")
        print(f"Weighted F1-Score:     {weighted_f1:.4f}")

        results.append({
            "model_name": name,
            "train_time_sec": round(train_duration, 4),
            "val_accuracy": round(acc, 4),
            "val_macro_f1": round(macro_f1, 4),
            "val_weighted_f1": round(weighted_f1, 4)
        })

        trained_models[name] = model
        # Serializar cada modelo individualmente
        joblib.dump(model, f"models/{name.lower()}_model.joblib")

    # Selección del mejor modelo según Macro F1 (para penalizar sesgo de clases desbalanceadas)
    best_candidate = max(results, key=lambda x: x['val_macro_f1'])
    champion_name = best_candidate['model_name']
    champion_model = trained_models[champion_name]

    print(f"\n=======================================================")
    print(f"🏆 MODELO SELECCIONADO (CHAMPION): {champion_name}")
    print(f"   Macro F1: {best_candidate['val_macro_f1']} | Accuracy: {best_candidate['val_accuracy']}")
    print(f"=======================================================")

    # Serializar modelo definitivo de inferencia
    joblib.dump(champion_model, "models/vulnerability_classifier.joblib")

    metadata = {
        "champion_model": champion_name,
        "selection_metric": "val_macro_f1",
        "comparison_results": results,
        "total_classes": len(le.classes_),
        "classes": list(le.classes_),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    with open("models/model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print("[OK] Modelo serializado en 'models/vulnerability_classifier.joblib'")
    print("[OK] Metadatos guardados en 'models/model_metadata.json'")

if __name__ == "__main__":
    run_model_phase()
