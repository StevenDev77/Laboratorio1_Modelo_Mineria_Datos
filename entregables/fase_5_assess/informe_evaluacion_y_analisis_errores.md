# FASE 5: ASSESS (EVALUACIÓN DEL MODELO Y ANÁLISIS DE ERRORES)

## 1. Resultados Cuantitativos en el Conjunto de Prueba Independiente (80 muestras ciegas)

El conjunto de prueba representa el 15.1% del total de datos y se mantuvo aislado durante el preprocesamiento y entrenamiento.

### Métricas Globales
- **Accuracy Global:** 1.0000 (100.0%)
- **Macro Average Precision:** 1.0000
- **Macro Average Recall:** 1.0000
- **Macro Average F1-Score:** 1.0000
- **Weighted Average F1-Score:** 1.0000

---

## 2. Métricas de Clasificación Detalladas por Categoría

| Categoría Técnica | Precisión (Precision) | Sensibilidad (Recall) | Medida F1 (F1-score) | Muestras de Soporte (Support) |
|---|---|---|---|---|
| **BOLA_IDOR** | 1.00 | 1.00 | 1.00 | 6 |
| **BROKEN_AUTHENTICATION** | 1.00 | 1.00 | 1.00 | 4 |
| **COMMAND_INJECTION** | 1.00 | 1.00 | 1.00 | 6 |
| **EXCEPTIONAL_HANDLING** | 1.00 | 1.00 | 1.00 | 4 |
| **HARDCODED_SECRET** | 1.00 | 1.00 | 1.00 | 5 |
| **MASS_ASSIGNMENT** | 1.00 | 1.00 | 1.00 | 3 |
| **MISSING_FUNCTION_AUTH**| 1.00 | 1.00 | 1.00 | 4 |
| **RATE_LIMIT_ABSENCE** | 1.00 | 1.00 | 1.00 | 3 |
| **SAFE_CODE** (Código Seguro)| 1.00 | 1.00 | 1.00 | 22 |
| **SECURITY_MISCONFIG** | 1.00 | 1.00 | 1.00 | 6 |
| **SQL_INJECTION** | 1.00 | 1.00 | 1.00 | 6 |
| **SSRF** | 1.00 | 1.00 | 1.00 | 5 |
| **WEAK_CRYPTO_HASH** | 1.00 | 1.00 | 1.00 | 6 |
| **PROMEDIO GLOBAL (MACRO)**| **1.00** | **1.00** | **1.00** | **80** |

---

## 3. Matriz de Confusión
La matriz de confusión diagonal sin clasificaciones erróneas fuera de la diagonal principal se visualiza en:
`entregables/fase_5_assess/graficos_evaluacion/confusion_matrix.png`

---

## 4. Análisis de Falsos Positivos y Falsos Negativos
A nivel de detección binaria (Vulnerable vs Seguro):
- **Verdaderos Positivos (TP):** 58 vulnerabilidades detectadas correctamente.
- **Verdaderos Negativos (TN):** 22 muestras de código seguro confirmadas como seguras.
- **Falsos Positivos (FP):** 0 (ningún fragmento seguro fue clasificado erróneamente como vulnerable).
- **Falsos Negativos (FN):** 0 (ninguna vulnerabilidad del test set fue omitida).

### Factores Determinantes de la Ausencia de Falsos Positivos
La inclusión de 144 ejemplos negativos (código seguro) en la Fase 1 proveyó al modelo de patrones contrastantes claros: por ejemplo, la presencia explícita de `conn.prepareStatement(...)` versus `conn.createStatement(...)`, o el uso de decorators `@UseGuards(OwnershipGuard)` frente a endpoints sin verificación.

---

## 5. Conclusiones sobre la Capacidad de Generalización
1. **Robustez ante Proyectos Nuevos:** La prueba funcional de escaneo sobre el repositorio `test_microservices/` (proyecto no utilizado durante el entrenamiento de los datos de Benchmark) demostró que el modelo generaliza efectivamente hacia microservicios heterogéneos (Express, NestJS, Spring Boot, FastAPI), detectando con éxito las 24 vulnerabilidades implantadas y respetando los métodos seguros con DTOs y Guards.
2. **Limitaciones Reconocidas:** La herramienta opera a nivel de análisis estático inteligente. Patrones que dependan de lógica de negocio multi-paso distribuida entre microservicios a través de colas asíncronas (como RabbitMQ o Kafka) requieren validaciones complementarias de análisis dinámico (DAST) o análisis de grafos de dependencias entre servicios.
