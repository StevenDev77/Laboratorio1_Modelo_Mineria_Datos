# FASE 3: MODIFY (JUSTIFICACIÓN DE LAS TRANSFORMACIONES APLICADAS)

## 1. Justificación de la Representación Híbrida (TF-IDF + Rasgos Sintácticos)
Dado que la especificación prohíbe taxativamente el uso de LLMs (**"NO SE ACEPTAN LLM"**), el mayor desafío técnico consistía en transformar código fuente heterogéneo (Java, TypeScript, Python, YAML) en un espacio vectorial estructurado que preserve el significado de seguridad sin depender de modelos masivos:

1. **TF-IDF con n-gramas y operadores:** Los analizadores léxicos convencionales de procesamiento de lenguaje natural (NLP) ignoran la puntuación. Para código fuente, los símbolos `= ' + '`, `${`, `&&` y `()` son determinantes para distinguir entre una inyección de código y una instrucción segura. Por ello se configuró una expresión regular especializada (`(?u)\b\w+\b|[=<>!]+|[{}();,]`) que retiene estos delimitadores como tokens semánticos.
2. **Características Sintácticas de Dominio:** Los clasificadores puramente basados en bolsa de palabras pueden fallar ante nombres de variables arbitrarios (`v_bio`, `req_2`). El extractor de dominio `CodeSecurityFeatureExtractor` aporta invariantes lógicas (por ejemplo: si una consulta SQL contiene concatenación directa, el rasgo `has_sql_concat` se activa independientemente del nombre de la tabla).
3. **Escalamiento Estándar (`StandardScaler`):** Las métricas de longitud y conteos presentan magnitudes superiores a los indicadores booleanos. El escalamiento evita que variables como `char_len` dominen la función de pérdida sobre los indicadores críticos de vulnerabilidad.

---

## 2. Garantía de Independencia de Particiones
- El pipeline `fit_transform` se aplicó **exclusivamente sobre el conjunto de entrenamiento (Train)**.
- Los conjuntos de validación (Val) y prueba ciega (Test) fueron transformados únicamente mediante `transform()`, asegurando que no exista filtración de información (*data leakage*) sobre términos o distribuciones no vistos.
