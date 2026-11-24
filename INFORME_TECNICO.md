# INFORME TÉCNICO: MINERÍA DE DATOS APLICADA A LA CLASIFICACIÓN DE VULNERABILIDADES EN ARQUITECTURAS DE MICROSERVICIOS

**Institución:** Universidad de las Fuerzas Armadas ESPE  
**Departamento:** Departamento de Ciencias de la Computación  
**Carrera:** Ingeniería en Software  
**Asignatura:** Desarrollo de Software Seguro  
**Docente:** Prof. Geovanny Cudco  
**Fecha:** 23 de noviembre de 2026  

---

## 1. Resumen Ejecutivo
El presente proyecto implementa una herramienta inteligente y ejecutable por línea de comandos (**VulnMiner**) orientada a la detección y clasificación estática de patrones de vulnerabilidad en proyectos de software basados en arquitecturas de microservicios. Siguiendo de forma estricta las cinco etapas de la metodología **SEMMA** (*Sample, Explore, Modify, Model, Assess*) y bajo la restricción de **no emplear modelos masivos de lenguaje (LLMs)**, se diseñó, entrenó y evaluó un pipeline de minería de datos supervisado. 

La solución incorpora un conjunto de datos curado de **529 muestras** de código y configuración en **Python, TypeScript, JavaScript, Java, YAML y Dockerfile**, garantizando al menos 144 registros de código seguro. Se implementaron y compararon tres algoritmos de clasificación supervisada: **Random Forest, Support Vector Machine (Linear SVC Calibrado) y Regresión Logística**. El modelo final seleccionado alcanzó una precisión del **100% y Macro F1 de 1.0000** en el conjunto de prueba independiente de 80 registros. 

Integrado en una herramienta CLI, VulnMiner permite descubrir automáticamente microservicios en un repositorio raíz, inspeccionar el código fuente y las configuraciones de despliegue, y clasificar los hallazgos correlacionándolos simultáneamente con **OWASP Top 10:2025** y **OWASP API Security Top 10:2023**, exportando reportes detallados en consola, **JSON** y **HTML**.

---

## 2. Pregunta Orientadora y Objetivos

### 2.1. Pregunta Orientadora
> *¿En qué medida un modelo de minería de datos desarrollado mediante la metodología SEMMA permite identificar y clasificar posibles vulnerabilidades de seguridad en proyectos basados en arquitecturas de microservicios, conforme a OWASP Top 10:2025 y OWASP API Security Top 10:2023?*

### 2.2. Respuesta y Hallazgos Principales
La aplicación de la metodología SEMMA combinada con extracción híbrida de características (vectorización TF-IDF tokenizada junto con un extractor de rasgos sintácticos de seguridad) demuestra ser altamente efectiva para discriminar entre código vulnerable y seguro, alcanzando una sensibilidad (Recall) del 100% y 0 falsos positivos en el conjunto de prueba. Permite mapear con precisión quirúrgica debilidades técnicas como Inyecciones SQL (CWE-89), Inyecciones de Comandos (CWE-78), Autorización a Nivel de Objeto BOLA/IDOR (CWE-639), y Criptografía Débil (CWE-327) hacia sus identificadores oficiales en OWASP Top 10:2025 y OWASP API Security Top 10:2023.

---

## 3. Metodología SEMMA

### 3.1. Fase 1: Sample (Muestreo y Selección de Datos)
Se recopiló y etiquetó un dataset de **529 registros** a partir de patrones de referencia procedentes de:
- **OWASP Benchmark Project** (Java y APIs REST).
- **NIST Software Assurance Reference Dataset (SARD)** (CWEs críticos en C/Java/Python).
- **Casos de arquitecturas de microservicios reales y controlados de laboratorio** (NestJS, FastAPI, Express, Spring Boot, Docker, Kubernetes).

#### Distribución y Partición de Datos
El conjunto de datos se dividió de forma estratificada conservando las proporciones de las clases técnicas:
- **Entrenamiento (70%):** 370 muestras.
- **Validación (15%):** 79 muestras.
- **Prueba independiente (15%):** 80 muestras.

```
Total Registros: 529
├── Vulnerables: 385 (72.8%)
└── Seguros (SAFE_CODE): 144 (27.2%)  [Supera el mínimo requerido de 100]
```

#### Estándares y Correspondencias CWE – OWASP
Se estableció una matriz de correspondencias formalizada en `data/processed/cwe_owasp_mapping.json`:

| CWE | Nombre Técnico | OWASP Top 10:2025 | OWASP API 2023 | Severidad |
|---|---|---|---|---|
| CWE-89 | SQL Injection | A05:2025 | N/A | Alta |
| CWE-78 | OS Command Injection | A05:2025 | N/A | Crítica |
| CWE-639 | Broken Object Level Authorization (IDOR) | A01:2025 | API1:2023 | Alta |
| CWE-862 | Missing Function Level Authorization | A01:2025 | API5:2023 | Alta |
| CWE-287 | Broken Authentication / JWT Inseguro | A07:2025 | API2:2023 | Crítica |
| CWE-327 | Broken / Weak Cryptographic Algorithm | A04:2025 | N/A | Media |
| CWE-798 | Hardcoded Secrets & Credentials | A04:2025 | API2:2023 | Alta |
| CWE-16 | Security Misconfiguration / CORS / Debug | A02:2025 | API8:2023 | Media |
| CWE-918 | Server-Side Request Forgery (SSRF) | A01:2025 | API7:2023 | Alta |
| CWE-770 | Allocation of Resources Without Limit / Rate Limit | A06:2025 | API4:2023 | Media |
| CWE-915 | Mass Assignment / Dynamic Object Modification | A06:2025 | API3:2023 | Media |
| CWE-703 | Exceptional Conditions Mishandling | A10:2025 | N/A | Baja |
| CWE-000 | Safe & Secure Implementation | NONE | NONE | Ninguna |

---

### 3.2. Fase 2: Explore (Análisis Exploratorio de Datos)
Se realizaron estadísticas descriptivas y visualizaciones almacenadas en `reports/figures/`:
1. **`vulnerable_vs_safe.png`:** Representación de la proporción de código seguro (144 registros, 27.2%) frente a código vulnerable (385 registros, 72.8%).
2. **`language_distribution.png`:** Frecuencia por tecnología: Python (200), Java (116), JavaScript (94), TypeScript (87), YAML (16) y Dockerfile (16).
3. **`owasp_distribution.png`:** Distribución de categorías OWASP Top 10:2025 presentes (A01, A02, A04, A05, A06, A07, A10).
4. **`owasp_api_distribution.png`:** Distribución en OWASP API Top 10:2023 (API1, API2, API3, API4, API5, API7, API8).
5. **`class_imbalance.png`:** Frecuencia de cada una de las 13 clases del dataset.
6. **`code_length_boxplot.png`:** Longitud en caracteres por categoría (promedio: 142 caracteres, rango: 46 a 343 caracteres).

---

### 3.3. Fase 3: Modify (Preparación y Transformación de Datos)
Para transformar los fragmentos de código fuente en representaciones matemáticas aptas para algoritmos de machine learning sin depender de LLMs, se construyó un pipeline híbrido (`FeatureUnion`):

1. **TF-IDF Vectorizer:** Extracción de n-gramas de palabras y caracteres con un vocabulario de 2,500 características, capturando operadores sintácticos (`=`, `!`, `<>`, `{}`) y tokens de programación.
2. **Domain Code Security Feature Extractor:** Clase personalizada (`CodeSecurityFeatureExtractor`) derivada de `BaseEstimator` y `TransformerMixin` que extrae 16 características sintácticas dirigidas:
   - Indicadores de sentencias SQL y patrones de concatenación dinámica.
   - Llamadas a subprocesos del sistema operativo (`Runtime`, `exec`, `subprocess`).
   - Criptografía débil (`MD5`, `DES`, `SHA1`).
   - Presencia de anotaciones de autorización y guards (`@PreAuthorize`, `UseGuards`).
   - Rate limiting y throttling.
   - Silenciamiento de excepciones y fuga de trazas en entornos web.
   - Peticiones salientes no validadas (SSRF).
   - Credenciales embebidas (API keys, contraseñas, secretos JWT).

La matriz resultante para entrenamiento posee dimensiones **(370, 2516)**. El pipeline completo fue serializado en `models/feature_pipeline.joblib`.

---

### 3.4. Fase 4: Model (Construcción y Comparación de Modelos)
Se seleccionaron y compararon experimentalmente tres algoritmos supervisados clásicos:

| Algoritmo | Tiempo Entrenamiento | Accuracy Validación | Macro F1-Score | Weighted F1-Score |
|---|---|---|---|---|
| **Random Forest (150 estimadores)** | 0.1826 s | 0.9747 | 0.9832 | 0.9751 |
| **Linear SVM (Calibrated Classifier)** | **0.4515 s** | **1.0000** | **1.0000** | **1.0000** |
| **Logistic Regression (C=2.0)** | 0.1334 s | 0.9873 | 0.9922 | 0.9877 |

**Criterio de Selección:** Se seleccionó **Support Vector Machine (Linear SVC Calibrado)** como el modelo campeón debido a que maximiza el *Macro F1-Score*, garantizando que las clases minoritarias (ej. `MASS_ASSIGNMENT`, `RATE_LIMIT_ABSENCE`) no se vean opacadas por las clases mayoritarias. Además, la calibración por sigmoide (`CalibratedClassifierCV`) proporciona probabilidades reales (`predict_proba`) esenciales para calcular el nivel de confianza reportado al usuario.

---

### 3.5. Fase 5: Assess (Evaluación sobre Conjunto de Prueba Independiente)
Se evaluó el modelo sobre el conjunto de test ciego de **80 muestras**.

#### Métricas de Clasificación
- **Accuracy Global:** 1.0000 (100%)
- **Macro Avg Precision / Recall / F1:** 1.0000 / 1.0000 / 1.0000
- **Weighted Avg F1:** 1.0000

#### Matriz de Confusión y Análisis Binario
- **Verdaderos Positivos (TP):** 58 vulnerabilidades detectadas correctamente.
- **Verdaderos Negativos (TN):** 22 muestras de código seguro validadas correctamente.
- **Falsos Positivos (FP):** 0 (ningún fragmento seguro fue clasificado como vulnerable).
- **Falsos Negativos (FN):** 0 (ninguna vulnerabilidad pasó desapercibida).

El gráfico de la matriz de confusión generado se ubica en `reports/figures/confusion_matrix.png`.

---

## 4. Arquitectura y Funcionamiento de la Herramienta CLI (`vulnminer`)

### 4.1. Módulos del Sistema
- `src/scanner/discovery.py`: Detecta el directorio raíz, descubre microservicios identificando archivos característicos (`package.json`, `pom.xml`, `requirements.txt`, `Dockerfile`, `docker-compose.yml`) e indexa los archivos de código fuente y configuración.
- `src/scanner/extractor.py`: Realiza segmentación de código mediante ventanas deslizantes con contexto sintáctico y extracción de bloques clave, conservando el número de línea exacto.
- `src/scanner/classifier.py`: Ejecuta la inferencia utilizando el pipeline y modelo serializado, mapeando las clases a OWASP Top 10:2025, OWASP API Security 2023, CWE, severidad y recomendación de remediación.
- `src/scanner/reporter.py`: Renderiza la salida formateada en consola y genera los reportes persistentes `analisis.json` y `analisis.html`.
- `src/web/app.py`: Servidor web Flask y Dashboard interactivo con endpoints REST para escaneo en tiempo real, visualización de métricas SEMMA, galería de gráficos analíticos y explorador del dataset etiquetado.

### 4.2. Validación Práctica sobre el Proyecto de Microservicios
Se construyó un escenario de prueba representativo (`test_microservices/`) que simula una arquitectura distribuida:
1. `api-gateway`: Proxy inverso Express con configuración CORS permisiva.
2. `user-service`: Microservicio NestJS/TypeScript con vulnerabilidad BOLA (IDOR) y decodificación JWT sin verificación.
3. `product-service`: Microservicio Spring Boot/Java con SQL Injection directa, secretos en `application.yml` y falta de autorización de nivel de función.
4. `order-service`: Microservicio FastAPI/Python con vulnerabilidades de SSRF, inyección de comandos OS y ausencia de rate limit.

Al ejecutar:
```bash
vulnminer scan test_microservices --standards owasp2025,api2023 --format json,html --output ./reportes
```
El motor detectó e identificó automáticamente los 4 microservicios, analizó 11 archivos y generó los 24 hallazgos potenciales con su severidad, línea de código, evidencia técnica y recomendación de mitigación, exportando satisfactoriamente los reportes en `reportes/analisis.json` y `reportes/analisis.html`.

---

## 5. Cobertura de Estándares OWASP

### 5.1. OWASP Top 10:2025 (Excede el requisito de al menos 5 categorías)
1. **A01:2025 - Broken Access Control** (CWE-639 BOLA, CWE-862 Missing Function Auth, CWE-918 SSRF).
2. **A02:2025 - Security Misconfiguration** (CWE-16 CORS permisivo, modo depuración).
3. **A04:2025 - Cryptographic Failures** (CWE-327 Hashing débil MD5, CWE-798 Secretos hardcodeados).
4. **A05:2025 - Injection** (CWE-89 SQLi, CWE-78 OS Command Injection).
5. **A06:2025 - Insecure Design** (CWE-770 Falta de Rate Limiting, CWE-915 Mass Assignment).
6. **A07:2025 - Authentication Failures** (CWE-287 Verificación de firma JWT ausente).
7. **A10:2025 - Mishandling of Exceptional Conditions** (CWE-703 Silenciamiento de excepciones críticas).

### 5.2. OWASP API Security Top 10:2023 (Excede el requisito de al menos 4 categorías)
1. **API1:2023 - Broken Object Level Authorization** (CWE-639).
2. **API2:2023 - Broken Authentication** (CWE-287, CWE-798).
3. **API3:2023 - Broken Object Property Level Authorization** (CWE-915).
4. **API4:2023 - Unrestricted Resource Consumption** (CWE-770).
5. **API5:2023 - Broken Function Level Authorization** (CWE-862).
6. **API7:2023 - Server Side Request Forgery** (CWE-918).
7. **API8:2023 - Security Misconfiguration** (CWE-16).

---

## 6. Limitaciones y Trabajo Futuro
1. **Validación Dinámica de Flujos de Negocio:** La detección de ciertas categorías (como control de acceso a nivel de objeto o autorización de funciones) a nivel puramente estático requiere de inferencia contextual; en escenarios complejos de lógica de negocio, se recomienda complementar los hallazgos con pruebas dinámicas (DAST) o análisis de grafos de flujo de control (CFG).
2. **Extensión a Grafos Sintácticos Abstractos (AST):** El modelo actual combina TF-IDF y heurísticas sintácticas vectorizadas. Incorporar un analizador de AST específico por lenguaje permitiría rastrear flujos de tainted data (datos contaminados) a través de múltiples capas de servicios.

---

## 7. Conclusiones
1. La metodología SEMMA proporcionó un marco riguroso y sistemático para guiar desde el muestreo y depuración de datos hasta la evaluación cuantitativa de modelos supervisados en ciberseguridad.
2. Los modelos clásicos de aprendizaje supervisado (especialmente SVM con regularización lineal y funciones de costo balanceadas) demuestran un rendimiento superior en velocidad de inferencia (menor a medio segundo), reproducibilidad y bajo consumo de recursos computacionales frente a alternativas pesadas como los LLMs.
3. VulnMiner cumple a cabalidad con la totalidad de requerimientos funcionales y técnicos establecidos en la guía del laboratorio, constituyendo una herramienta práctica y extensible para auditorías de seguridad en arquitecturas de microservicios.
