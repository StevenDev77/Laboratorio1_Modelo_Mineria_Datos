# FASE 4: MODEL (TABLA DE COMPARACIÓN EXPERIMENTAL)

## 1. Tabla Comparativa de Rendimiento sobre el Conjunto de Validación (79 muestras)

| Algoritmo | Tiempo Entrenamiento (s) | Accuracy Validación | Macro F1-Score | Weighted F1-Score | Decisión |
|---|---|---|---|---|---|
| **Support Vector Machine (Linear SVC Calibrado)** | 0.4515 s | **1.0000** | **1.0000** | **1.0000** | 🏆 **SELECCIONADO (CAMPEÓN)** |
| **Logistic Regression (C=2.0)** | 0.1334 s | 0.9873 | 0.9922 | 0.9877 | Evaluado (Alternativo) |
| **Random Forest (150 estimadores)** | 0.1826 s | 0.9747 | 0.9832 | 0.9751 | Evaluado (Alternativo) |

---

## 2. Justificación de la Selección del Modelo Campeón
1. **Priorización de Macro F1:** En problemas de auditoría de seguridad con 13 clases técnicas, la métrica crítica es el **Macro F1-Score**, ya que promedia el desempeño de cada categoría sin ponderar por tamaño de muestra. De esta forma, clases de menor volumen (como `MASS_ASSIGNMENT` o `RATE_LIMIT_ABSENCE`) no sufren falsos negativos en favor de clases más numerosas.
2. **Capacidad Probabilística:** Gracias al envoltorio `CalibratedClassifierCV`, la SVM lineal no solo emite una decisión binaria/multiclase, sino que produce una distribución de probabilidad calibrada (`predict_proba`). Esto permite a VulnMiner reportar con exactitud matemática el nivel de confianza al auditor (ej. `Confianza del modelo: 0.86`).
3. **Velocidad de Inferencia:** Con menos de 0.5 segundos de entrenamiento y menos de 5 milisegundos por predicción, el modelo permite auditar proyectos enteros de microservicios en segundos sin requerir GPU ni conexión a servicios externos.
