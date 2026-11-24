# FASE 1: SAMPLE (MUESTREO Y SELECCIÓN DE DATOS)

## 1. Descripción de las Fuentes Utilizadas
El conjunto de datos etiquetado fue recopilado a partir de fuentes reconocidas internacionalmente en el ámbito de la seguridad de software:
1. **OWASP Benchmark Project:** Banco de pruebas estándar para analizadores de seguridad estáticos en Java y APIs web REST. Provee casos representativos de inyección SQL, algoritmos de dispersión obsoletos y deserialización insegura.
2. **NIST Software Assurance Reference Dataset (SARD):** Conjunto público de casos de prueba patrocinado por el Departamento de Seguridad Nacional de EE. UU. (DHS) y el NIST. Se seleccionaron ejemplos de inyección de comandos en el SO (CWE-78), bypass de autenticación (CWE-287) y SSRF (CWE-918).
3. **Casos Reales y Controlados de Microservicios:** Muestras desarrolladas en entornos controlados de laboratorio modelando arquitecturas distribuidas con FastAPI (Python), NestJS (TypeScript), Express (JavaScript), Spring Boot (Java), YAML y Dockerfiles.

---

## 2. Justificación del Procedimiento de Muestreo
- **Tamaño Muestral:** Se recopilaron **529 registros** válidos, superando la cuota mínima de 500 registros establecida en la especificación.
- **Muestras Seguras (Control Negativo):** Se incluyeron **144 ejemplos de código seguro** (27.2%), superando ampliamente el requisito mínimo de 100 registros. Estos incluyen consultas con `PreparedStatement`, validación de tokens JWT con algoritmos robustos (RS256), middlewares de autorización (`@PreAuthorize`, `UseGuards`), rate limiting y manejo estricto de DTOs.
- **Estratificación:** Para evitar sesgo de clase y fuga de información (*data leakage*), la separación se realizó mediante `StratifiedShuffleSplit` manteniendo idéntica proporción de cada categoría técnica:
  - **Entrenamiento (Train):** 370 registros (69.9%)
  - **Validación (Val):** 79 registros (14.9%)
  - **Prueba Ciega (Test):** 80 registros (15.1%)

---

## 3. Tabla de Correspondencias CWE – OWASP

| CWE | Nombre Técnico | OWASP Top 10:2025 | OWASP API 2023 | Severidad | Muestras |
|---|---|---|---|---|---|
| CWE-89 | SQL Injection | A05:2025 | N/A | Alta | 36 |
| CWE-78 | OS Command Injection | A05:2025 | N/A | Crítica | 35 |
| CWE-639 | Broken Object Level Authorization (IDOR) | A01:2025 | API1:2023 | Alta | 40 |
| CWE-862 | Missing Function Level Authorization | A01:2025 | API5:2023 | Alta | 30 |
| CWE-287 | Broken Authentication / JWT Inseguro | A07:2025 | API2:2023 | Crítica | 30 |
| CWE-327 | Use of Broken/Risky Cryptographic Algorithm | A04:2025 | N/A | Media | 35 |
| CWE-798 | Use of Hard-coded Credentials | A04:2025 | API2:2023 | Alta | 35 |
| CWE-16 | Security Misconfiguration | A02:2025 | API8:2023 | Media | 35 |
| CWE-918 | Server-Side Request Forgery (SSRF) | A01:2025 | API7:2023 | Alta | 30 |
| CWE-770 | Unrestricted Resource Consumption (Rate Limit) | A06:2025 | API4:2023 | Media | 25 |
| CWE-915 | Mass Assignment | A06:2025 | API3:2023 | Media | 24 |
| CWE-703 | Mishandling of Exceptional Conditions | A10:2025 | N/A | Baja | 30 |
| CWE-000 | Safe & Secure Implementation | NONE | NONE | Ninguna | 144 |
| **TOTAL**| | | | | **529** |

---

## 4. Archivos Entregables en esta Carpeta
- `dataset_vulnerabilidades.csv`: Conjunto de datos completo etiquetado.
- `train.csv`: Conjunto de entrenamiento (70%).
- `val.csv`: Conjunto de validación (15%).
- `test.csv`: Conjunto de prueba independiente (15%).
- `data_dictionary.json`: Diccionario formal de metadatos, campos y tipos.
- `cwe_owasp_mapping.json`: Matriz relacional CWE a OWASP Top 10:2025 y API:2023.
- `sample.py`: Código ejecutable para reproducir el proceso de muestreo.
