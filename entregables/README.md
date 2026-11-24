# ESTRUCTURA OFICIAL DE ENTREGABLES DEL PROYECTO (SEMMA)

**Universidad de las Fuerzas Armadas ESPE**  
**Departamento de Ciencias de la Computación**  
**Carrera de Ingeniería en Software**  
**Desarrollo de Software Seguro**  
**Docente:** Prof. Geovanny Cudco  
**Estándares:** OWASP Top 10:2025 y OWASP API Security Top 10:2023  

---

## 📁 Organización por Fases de la Metodología SEMMA

Esta carpeta contiene todos los entregables explícitamente requeridos en el documento `Modelo_mineria_datos.md` desglosados en subcarpetas por fase:

```text
entregables/
├── README.md                                 # Índice general de entregables
│
├── fase_1_sample/                            # FASE 1: SAMPLE (MUESTREO Y SELECCIÓN)
│   ├── dataset_vulnerabilidades.csv          # Dataset etiquetado (529 registros)
│   ├── train.csv, val.csv, test.csv          # Partición estratificada 70% / 15% / 15%
│   ├── data_dictionary.json                  # Diccionario de datos
│   ├── cwe_owasp_mapping.json                # Correspondencias CWE - OWASP
│   ├── descripcion_fuentes_y_muestreo.md     # Fuentes, justificación de muestreo y mapeo
│   └── sample.py                             # Script reproducible de muestreo
│
├── fase_2_explore/                           # FASE 2: EXPLORE (ANÁLISIS EXPLORATORIO)
│   ├── 02_explore_notebook.ipynb             # Notebook de análisis exploratorio
│   ├── tablas_estadisticas_descriptivas.md   # Tablas estadísticas y frecuencias
│   ├── conclusiones_calidad_representatividad.md # Interpretación de calidad y balance
│   ├── graficos_interpretados/               # Gráficos exportados en alta resolución
│   │   ├── owasp_distribution.png            # Distribución OWASP Top 10:2025
│   │   ├── owasp_api_distribution.png        # Distribución OWASP API:2023
│   │   ├── language_distribution.png         # Distribución por lenguaje
│   │   ├── vulnerable_vs_safe.png            # Distribución seguro vs vulnerable
│   │   ├── class_imbalance.png               # Desbalance entre clases
│   │   └── code_length_boxplot.png           # Longitudes de fragmentos de código
│   └── explore.py                            # Script generador de estadísticas y gráficos
│
├── fase_3_modify/                            # FASE 3: MODIFY (PREPARACIÓN Y TRANSFORMACIÓN)
│   ├── feature_pipeline.joblib               # Pipeline reproducible serializado
│   ├── matriz_caracteristicas_info.md        # Documentación de la matriz (370 x 2516)
│   ├── justificacion_transformaciones.md     # Justificación técnica TF-IDF + Rasgos sintácticos
│   └── modify.py                             # Script de extracción y preprocesamiento
│
├── fase_4_model/                             # FASE 4: MODEL (CONSTRUCCIÓN Y COMPARACIÓN)
│   ├── vulnerability_classifier.joblib       # Modelo campeón serializado (SVM Calibrado)
│   ├── random_forest_model.joblib            # Modelo Random Forest serializado
│   ├── logistic_regression_model.joblib      # Modelo Regresión Logística serializado
│   ├── label_encoder.joblib                  # Codificador de etiquetas
│   ├── model_metadata.json                   # Metadatos del entrenamiento
│   ├── descripcion_algoritmos_hiperparametros.md # Algoritmos e hiperparámetros
│   ├── comparacion_experimental.md           # Tabla comparativa de desempeño
│   └── model.py                              # Script de entrenamiento y selección
│
└── fase_5_assess/                            # FASE 5: ASSESS (EVALUACIÓN DEL MODELO)
    ├── eval_metrics.json                     # Resultados cuantitativos en conjunto de prueba
    ├── informe_evaluacion_y_analisis_errores.md # Métricas, análisis de FP/FN y generalización
    ├── graficos_evaluacion/                  # Visualizaciones de evaluación
    │   └── confusion_matrix.png              # Matriz de confusión en test ciego
    └── assess.py                             # Script de evaluación y cálculo de métricas
```

---

## 🏆 Cumplimiento de la Rúbrica de Evaluación (20 Puntos)

| Criterio de Evaluación | Puntaje | Carpeta de Entregable |
|---|---|---|
| **Sample:** calidad, etiquetado y trazabilidad del conjunto de datos | 2 pts | `entregables/fase_1_sample/` |
| **Explore:** análisis exploratorio, estadísticas y visualizaciones | 2 pts | `entregables/fase_2_explore/` |
| **Modify:** preprocesamiento, transformación y extracción de características | 2 pts | `entregables/fase_3_modify/` |
| **Model:** entrenamiento, comparación y selección de modelos | 4 pts | `entregables/fase_4_model/` |
| **Assess:** evaluación, métricas y análisis de resultados | 3 pts | `entregables/fase_5_assess/` |
| **CLI & Web UI:** integración, clasificación OWASP, funcionamiento y reportes | 5 pts | `vulnminer.py`, `src/scanner/`, `src/web/`, `reportes/` |
| **Documentación técnica y demostración funcional** | 2 pts | `INFORME_TECNICO.md`, `README.md`, `test_microservices/` |
| **Total** | **20 pts** | |
