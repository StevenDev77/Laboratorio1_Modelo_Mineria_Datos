# VulnMiner: Minería de Datos para Clasificación de Vulnerabilidades en Microservicios

**Universidad de las Fuerzas Armadas ESPE**  
**Departamento de Ciencias de la Computación**  
**Carrera de Ingeniería en Software**  
**Asignatura:** Desarrollo de Software Seguro  
**Docente:** Prof. Geovanny Cudco  
**Metodología:** SEMMA (*Sample, Explore, Modify, Model, Assess*)  
**Estándares de Seguridad:** OWASP Top 10:2025 y OWASP API Security Top 10:2023  
**Restricción Técnica:** Modelos de Machine Learning Supervisado Clásicos (**NO SE UTILIZAN LLMs**)

---

## 📋 Descripción del Proyecto
VulnMiner es una solución integral y ejecutable por línea de comandos (CLI) que aplica técnicas de minería de datos y aprendizaje automático supervisado para el análisis estático de seguridad en arquitecturas de microservicios.

La herramienta descubre automáticamente los servicios del proyecto analizado, procesa código fuente en múltiples lenguajes (**Python, TypeScript, JavaScript, Java**) y archivos de infraestructura/configuración (**YAML, Dockerfile**), clasifica debilidades conforme a los estándares **OWASP Top 10:2025** y **OWASP API Security Top 10:2023**, y genera reportes interactivos en **JSON** y **HTML**.

---

## 📁 Estructura del Repositorio

```text
Seguro2P/
├── Modelo_mineria_datos.md          # Especificación oficial del laboratorio
├── INFORME_TECNICO.md               # Informe académico y técnico completo
├── README.md                        # Esta guía de uso e instalación
├── vulnminer.py                     # Punto de entrada ejecutable CLI
├── vulnminer.bat                    # Script para ejecución directa en Windows
├── data/
│   ├── raw/                         # Referencias de origen (SARD, OWASP Benchmark)
│   └── processed/
│       ├── dataset_vulnerabilidades.csv  # Dataset etiquetado (529 registros)
│       ├── train.csv, val.csv, test.csv  # Partición estratificada 70/15/15
│       ├── data_dictionary.json     # Diccionario de datos
│       └── cwe_owasp_mapping.json   # Correspondencias CWE <-> OWASP 2025/2023
├── notebooks/
│   └── semma_pipeline_completo.ipynb # Notebook interactivo de las 5 fases SEMMA
├── models/
│   ├── vulnerability_classifier.joblib # Modelo campeón serializado (SVM Calibrado)
│   ├── random_forest_model.joblib      # Modelo alternativo comparado
│   ├── logistic_regression_model.joblib# Modelo lineal comparado
│   ├── feature_pipeline.joblib         # Pipeline TF-IDF + Rasgos de Seguridad
│   ├── label_encoder.joblib            # Codificador de clases técnicas
│   └── model_metadata.json             # Métricas y metadatos del entrenamiento
├── reports/
│   ├── eval_metrics.json               # Métricas de evaluación en conjunto de prueba
│   └── figures/                        # Visualizaciones del análisis exploratorio y evaluación
│       ├── vulnerable_vs_safe.png
│       ├── language_distribution.png
│       ├── owasp_distribution.png
│       ├── owasp_api_distribution.png
│       ├── class_imbalance.png
│       ├── code_length_boxplot.png
│       └── confusion_matrix.png
├── src/
│   ├── semma/                          # Scripts de cada fase SEMMA
│   │   ├── sample.py
│   │   ├── explore.py
│   │   ├── modify.py
│   │   ├── model.py
│   │   └── assess.py
│   └── scanner/                        # Motor de auditoría e inferencia
│       ├── discovery.py                # Descubridor automático de microservicios
│       ├── extractor.py                # Extractor sintáctico de candidatos
│       ├── classifier.py               # Motor de inferencia ML
│       └── reporter.py                 # Generador de reportes Consola, JSON y HTML
└── test_microservices/                 # Proyecto de prueba para validación y evaluación
    ├── docker-compose.yml
    ├── api-gateway/                    # Microservicio Express / Node
    ├── user-service/                   # Microservicio NestJS / TypeScript
    ├── product-service/                # Microservicio Spring Boot / Java
    └── order-service/                  # Microservicio FastAPI / Python
```

---

## 🚀 Requisitos e Instalación

### Requisitos del Sistema
- Python 3.10 o superior (compatible y probado en Python 3.14).
- Paquetes requeridos: `scikit-learn`, `pandas`, `numpy`, `matplotlib`, `seaborn`, `joblib`.

### Instalación de Dependencias
```bash
pip install scikit-learn pandas numpy matplotlib seaborn joblib
```

---

## 🔬 Reproducción del Pipeline SEMMA

Para regenerar los datos, gráficos, entrenamiento y evaluación desde cero:

```bash
# Fase 1: Sample (Muestreo y partición 70/15/15)
python src/semma/sample.py

# Fase 2: Explore (Análisis exploratorio y gráficos estadísticos)
python src/semma/explore.py

# Fase 3: Modify (Extracción de características y pipeline TF-IDF)
python src/semma/modify.py

# Fase 4: Model (Entrenamiento y comparación de algoritmos)
python src/semma/model.py

# Fase 5: Assess (Evaluación sobre conjunto de prueba independiente)
python src/semma/assess.py
```

O ejecute todo en una sola línea:
```bash
python src/semma/sample.py && python src/semma/explore.py && python src/semma/modify.py && python src/semma/model.py && python src/semma/assess.py
```

---

## 💻 Uso de la Herramienta (CLI & Interfaz Web)

### 1. Interfaz Gráfica Web Interactiva (Dashboard)
Para iniciar la interfaz gráfica web en su navegador:
```bash
python vulnminer.py ui
```
O especificando puerto:
```bash
python vulnminer.py ui --port 5000
```
La interfaz web proporciona:
- **Tablero de Auditoría en Vivo:** Selección de ruta, ejecución interactiva del escáner, visualización de microservicios descubiertos y filtros avanzados de hallazgos por severidad, servicio y CWE.
- **Visualizador SEMMA:** Tablas comparativas de algoritmos (Random Forest, SVM, Regresión Logística) y galería de figuras estadísticas.
- **Explorador de Dataset y Mapeos:** Tabla con búsqueda de las 529 muestras y matriz de relaciones CWE <-> OWASP 2025/2023.

---

### 2. Ejecución mediante Línea de Comandos (CLI)

### Sintaxis General
```bash
python vulnminer.py scan <RUTA_PROYECTO> --standards <STANDARDS> --format <FORMATS> --output <DIRECTORIO_REPORTES>
```

### Ejemplo de Escaneo sobre el Proyecto de Microservicios de Prueba
```bash
python vulnminer.py scan test_microservices --standards owasp2025,api2023 --format json,html --output ./reportes
```

### Ejecución directa desde el directorio del proyecto a analizar:
```bash
cd test_microservices
python ../vulnminer.py scan . --standards owasp2025,api2023 --format json,html --output ./reportes
```

En sistemas Windows también está disponible `vulnminer.bat`:
```cmd
vulnminer.bat scan test_microservices --output ./reportes
```

---

## 📊 Reportes Generados
Al finalizar el análisis, VulnMiner genera:
1. **Salida resumida en consola:** Con el microservicio, archivo, número de línea, categoría OWASP Top 10, OWASP API, nivel de confianza y severidad.
2. **`reportes/analisis.json`:** Estructura de datos completa orientada a integración CI/CD.
3. **`reportes/analisis.html`:** Tablero interactivo con métricas ejecutivas, desglose por microservicio y código de evidencia técnica.
