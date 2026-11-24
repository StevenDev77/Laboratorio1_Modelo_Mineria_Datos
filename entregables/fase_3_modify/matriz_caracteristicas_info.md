# FASE 3: MODIFY (DOCUMENTACIÓN DE LA MATRIZ DE CARACTERÍSTICAS)

## 1. Dimensiones de la Matriz de Características
- **Conjunto de Entrenamiento (X_train):** (370 filas, 2,516 columnas)
- **Conjunto de Validación (X_val):** (79 filas, 2,516 columnas)
- **Conjunto de Prueba (X_test):** (80 filas, 2,516 columnas)

---

## 2. Composición de las 2,516 Características
La matriz de características fue construida integrando dos componentes complementarios mediante `scikit-learn.pipeline.FeatureUnion`:

### Componente 1: TF-IDF Textual y Sintáctico (2,500 dimensiones)
- **Tipo:** `TfidfVectorizer`
- **Rango de n-gramas:** `(1, 2)` (unigramas y bigramas)
- **Patrón de tokens:** `(?u)\b\w+\b|[=<>!]+|[{}();,]`
- **Propósito:** Captura tanto palabras clave del lenguaje (`select`, `exec`, `jwt`, `password`, `PreAuthorize`) como secuencias de caracteres que representan construcciones de programación (concatenaciones, llaves de formato `${`, bloques de excepciones).

### Componente 2: Extractor de Rasgos de Seguridad de Dominio (16 dimensiones)
Transformador personalizado (`CodeSecurityFeatureExtractor`) seguido de normalización estándar (`StandardScaler`):

| Índice | Nombre de Característica | Descripción del Patrón Detectado |
|---|---|---|
| 0 | `has_sql_kw` | Presencia de palabras reservadas SQL (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, etc.) |
| 1 | `has_sql_concat` | Concatenación dinámica en llamadas a BD (`execute(.. + ..)`, `f'SELECT...{id}'`) |
| 2 | `has_cmd_kw` | Invocación de procesos de sistema (`os.system`, `subprocess`, `child_process`, `Runtime`) |
| 3 | `has_hardcoded_secrets` | Asignación directa de contraseñas, secretos JWT o API keys en texto claro |
| 4 | `has_weak_crypto` | Algoritmos obsoletos de dispersión o cifrado (`MD5`, `SHA1`, `DES`, `ECB`) |
| 5 | `has_auth_guards` | Uso defensivo de decoradores de autorización (`@PreAuthorize`, `UseGuards`, `hasRole`) |
| 6 | `has_rate_limit` | Indicadores de protección contra abuso (`rateLimit`, `limiter`, `throttle`) |
| 7 | `has_empty_catch` | Silenciamiento de excepciones críticas (`except Exception: pass`, bloques catch vacíos) |
| 8 | `has_stacktrace_leak` | Fuga de trazas del sistema hacia el cliente (`traceback.format_exc`, `include-stacktrace`) |
| 9 | `has_ssrf` | Peticiones HTTP salientes directas hacia URLs arbitrarias (`requests.get(url)`, `axios.get`) |
| 10 | `has_mass_assign` | Asignación masiva sin filtrado de atributos (`setattr`, `BeanUtils.copyProperties`) |
| 11 | `has_misconfig` | Modos inseguros por defecto (`debug=True`, `origin: '*'`, CSRF deshabilitado) |
| 12 | `char_len` | Longitud total en caracteres del fragmento de código |
| 13 | `line_cnt` | Número total de líneas del bloque de código |
| 14 | `num_parenthesis` | Frecuencia de paréntesis (indicador de densidad de llamadas funcionales) |
| 15 | `num_braces` | Frecuencia de llaves (indicador de anidamiento de bloques de código) |

---

## 3. Pipeline Serializado
El pipeline completo se encuentra serializado y listo para inferencia en:
`entregables/fase_3_modify/feature_pipeline.joblib`
