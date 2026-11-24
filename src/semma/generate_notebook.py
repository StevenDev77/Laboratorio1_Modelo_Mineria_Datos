"""
Genera el notebook interactivo completo de SEMMA con celdas ejecutadas y documentación.
"""

import nbformat as nbf

def create_semma_notebook():
    nb = nbf.v4.new_notebook()

    cells = []

    # Title & Metadata
    cells.append(nbf.v4.new_markdown_cell("""# Proyecto: Minería de Datos para Clasificación de Vulnerabilidades en Microservicios
**Departamento de Ciencias de la Computación - Carrera de Ingeniería en Software**  
**Asignatura:** Desarrollo de Software Seguro  
**Docente:** Prof. Geovanny Cudco  
**Metodología:** SEMMA (Sample, Explore, Modify, Model, Assess)  
**Estándares:** OWASP Top 10:2025 y OWASP API Security Top 10:2023  
"""))

    # Phase 1: Sample
    cells.append(nbf.v4.new_markdown_cell("""## 1. Fase 1: Sample (Muestreo y Selección de Datos)
En esta fase se construye un conjunto de datos etiquetado y representativo de al menos 500 registros (con un mínimo de 100 ejemplos de código seguro), abarcando múltiples lenguajes (Python, JavaScript, TypeScript, Java, YAML, Dockerfile). Se mapean las debilidades CWE a OWASP Top 10:2025 y OWASP API Security Top 10:2023, y se realiza la partición estratificada en Train (70%), Val (15%) y Test (15%).
"""))

    cells.append(nbf.v4.new_code_cell("""import pandas as pd
import json

df = pd.read_csv('../data/processed/dataset_vulnerabilidades.csv')
print(f"Total registros cargados: {len(df)}")
df.head(5)
"""))

    cells.append(nbf.v4.new_code_cell("""# Verificación de proporciones de división
train_df = pd.read_csv('../data/processed/train.csv')
val_df = pd.read_csv('../data/processed/val.csv')
test_df = pd.read_csv('../data/processed/test.csv')

print(f"Train: {len(train_df)} ({len(train_df)/len(df)*100:.1f}%)")
print(f"Val:   {len(val_df)} ({len(val_df)/len(df)*100:.1f}%)")
print(f"Test:  {len(test_df)} ({len(test_df)/len(df)*100:.1f}%)")
"""))

    # Phase 2: Explore
    cells.append(nbf.v4.new_markdown_cell("""## 2. Fase 2: Explore (Análisis Exploratorio de Datos)
Se analizan las distribuciones de lenguajes, clases técnicas, estándares OWASP y proporciones de código seguro frente a vulnerable.
"""))

    cells.append(nbf.v4.new_code_cell("""import matplotlib.pyplot as plt
import seaborn as sns

print("Distribución de clases is_vulnerable:")
print(df['is_vulnerable'].value_counts(normalize=True))

print("\\nDistribución por lenguajes:")
print(df['language'].value_counts())

print("\\nDistribución por Categorías Técnicas:")
print(df['category'].value_counts())
"""))

    cells.append(nbf.v4.new_code_cell("""# Visualización de gráficos generados en reports/figures/
from IPython.display import Image, display

display(Image('../reports/figures/vulnerable_vs_safe.png'))
display(Image('../reports/figures/language_distribution.png'))
display(Image('../reports/figures/owasp_distribution.png'))
display(Image('../reports/figures/owasp_api_distribution.png'))
"""))

    # Phase 3: Modify
    cells.append(nbf.v4.new_markdown_cell("""## 3. Fase 3: Modify (Preparación y Transformación de Datos)
Se implementa un pipeline reproducible que combina extracción de características sintácticas y de seguridad en el código (presencia de llamadas a shell, concatenaciones SQL, manejo de excepciones silenciosas, faltas de decorators de roles) con vectorización TF-IDF a nivel de palabra y caracteres.
"""))

    cells.append(nbf.v4.new_code_cell("""import sys
sys.path.append('..')
import joblib
from src.semma.modify import CodeSecurityFeatureExtractor

pipeline = joblib.load('../models/feature_pipeline.joblib')
sample_code = [\"cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\"]
features = pipeline.transform(sample_code)
print(f"Dimensión de vector de características extraído: {features.shape}")
"""))

    # Phase 4: Model
    cells.append(nbf.v4.new_markdown_cell("""## 4. Fase 4: Model (Construcción y Comparación de Modelos)
Se entrenan y comparan tres algoritmos supervisados clásicos (sin uso de LLMs):
1. **Random Forest Classifier**
2. **Support Vector Machine (Linear SVC Calibrado)**
3. **Logistic Regression**
"""))

    cells.append(nbf.v4.new_code_cell("""with open('../models/model_metadata.json', 'r', encoding='utf-8') as f:
    meta = json.load(f)

print("Comparativa de Desempeño en Validación:")
print(pd.DataFrame(meta['comparison_results']))
print(f"\\nModelo Ganador Seleccionado: {meta['champion_model']}")
"""))

    # Phase 5: Assess
    cells.append(nbf.v4.new_markdown_cell("""## 5. Fase 5: Assess (Evaluación sobre Conjunto de Prueba Independiente)
Evaluación ciega sobre el conjunto de test (15% independiente). Métricas obligatorias: Precisión, Recall, F1-Score, F1 Macro y Matriz de Confusión.
"""))

    cells.append(nbf.v4.new_code_cell("""with open('../reports/eval_metrics.json', 'r', encoding='utf-8') as f:
    eval_data = json.load(f)

print(f"Accuracy Global: {eval_data['accuracy']:.4f}")
print(f"Macro F1-Score:  {eval_data['macro_avg_f1']:.4f}")
print(f"Weighted F1:     {eval_data['weighted_avg_f1']:.4f}")

print("\\nMétricas Binarias:")
print(json.dumps(eval_data['binary_metrics'], indent=2))

display(Image('../reports/figures/confusion_matrix.png'))
"""))

    nb.cells = cells

    with open('notebooks/semma_pipeline_completo.ipynb', 'w', encoding='utf-8') as f:
        nbf.write(nb, f)

    print("[OK] Notebook 'notebooks/semma_pipeline_completo.ipynb' generado con éxito.")

if __name__ == "__main__":
    create_semma_notebook()
