# FASE 2: EXPLORE (TABLAS ESTADÍSTICAS DESCRIPTIVAS)

## 1. Resumen General del Dataset
- **Total de registros:** 529
- **Dimensiones:** 529 filas × 10 columnas
- **Registros nulos o inconsistentes:** 0 (100% de integridad)

---

## 2. Distribución de Clases (Vulnerable vs Seguro)

| Clase | Indicador Binario | Cantidad de Muestras | Porcentaje (%) |
|---|---|---|---|
| **Vulnerable** | `is_vulnerable = 1` | 385 | 72.78% |
| **Seguro (Control)** | `is_vulnerable = 0` | 144 | 27.22% |
| **Total** | | **529** | **100.00%** |

---

## 3. Distribución por Lenguaje de Programación / Configuración

| Lenguaje / Formato | Muestras | Porcentaje (%) |
|---|---|---|
| **Python** | 200 | 37.81% |
| **Java** | 116 | 21.93% |
| **JavaScript** | 94 | 17.77% |
| **TypeScript** | 87 | 16.45% |
| **YAML** | 16 | 3.02% |
| **Dockerfile** | 16 | 3.02% |
| **Total** | **529** | **100.00%** |

---

## 4. Distribución por Categorías OWASP Top 10:2025

| Código OWASP Top 10:2025 | Denominación Oficial | Frecuencia | % de Vulnerables |
|---|---|---|---|
| **A01:2025** | Broken Access Control (BOLA, BFLA, SSRF) | 100 | 25.97% |
| **A05:2025** | Injection (SQLi, Command Injection) | 71 | 18.44% |
| **A04:2025** | Cryptographic Failures (Hash débil, Secretos) | 70 | 18.18% |
| **A06:2025** | Insecure Design (Rate Limiting, Mass Assignment) | 49 | 12.73% |
| **A02:2025** | Security Misconfiguration (CORS, Debug) | 35 | 9.09% |
| **A07:2025** | Authentication Failures (JWT Inseguro) | 30 | 7.79% |
| **A10:2025** | Mishandling of Exceptional Conditions | 30 | 7.79% |
| **Total Vulnerables** | | **385** | **100.00%** |

---

## 5. Distribución por Categorías OWASP API Security Top 10:2023

| Código OWASP API:2023 | Denominación Oficial | Frecuencia |
|---|---|---|
| **API2:2023** | Broken Authentication (JWT, Credenciales) | 65 |
| **API1:2023** | Broken Object Level Authorization (BOLA/IDOR) | 40 |
| **API8:2023** | Security Misconfiguration | 35 |
| **API5:2023** | Broken Function Level Authorization | 30 |
| **API7:2023** | Server Side Request Forgery (SSRF) | 30 |
| **API4:2023** | Unrestricted Resource Consumption | 25 |
| **API3:2023** | Broken Object Property Level Authorization | 24 |
| **Total Clasificados en API** | | **249** |

---

## 6. Estadísticas Descriptivas de Longitud del Código (Caracteres y Líneas)

| Métrica | Longitud en Caracteres (`char_length`) | Número de Líneas (`line_count`) |
|---|---|---|
| **Media** | 142.02 caracteres | 3.65 líneas |
| **Desviación Estándar** | 57.59 caracteres | 1.82 líneas |
| **Mínimo** | 46 caracteres | 1 línea |
| **Primer Cuartil (25%)** | 100 caracteres | 2 líneas |
| **Mediana (50%)** | 126 caracteres | 4 líneas |
| **Tercer Cuartil (75%)** | 176 caracteres | 5 líneas |
| **Máximo** | 343 caracteres | 11 líneas |
