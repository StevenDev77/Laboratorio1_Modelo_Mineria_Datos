# FASE 4: MODEL (DESCRIPCIÓN DE ALGORITMOS E HIPERPARÁMETROS)

## 1. Algoritmos de Clasificación Supervisada Seleccionados
Se implementaron y compararon experimentalmente tres algoritmos de machine learning supervisado clásicos:

### 1. Support Vector Machine (Linear SVC Calibrado) - **Modelo Campeón**
- **Arquitectura:** Máquina de Soporte Vectorial Lineal encapsulada en `CalibratedClassifierCV` mediante regresión sigmoide (método de Platt).
- **Hiperparámetros:**
  - `C = 1.0`: Parámetro de regularización que equilibra el margen y el error de clasificación.
  - `class_weight = 'balanced'`: Ajusta los pesos de las clases inversamente proporcionales a sus frecuencias para contrarrestar el desbalance de clases.
  - `max_iter = 2000`: Número de iteraciones del optimizador de descenso de gradiente.
  - `random_state = 42`: Semilla de reproducibilidad.
- **Justificación:** Los espacios de características generados por TF-IDF son de alta dimensionalidad (2,516 rasgos) y relativamente dispersos. Las SVM lineales son teóricamente óptimas para separar hiperplanos en espacios dispersos y evitan el sobreajuste.

### 2. Random Forest Classifier
- **Arquitectura:** Ensamble de árboles de decisión con agregación por votación (*bagging*).
- **Hiperparámetros:**
  - `n_estimators = 150`: Número de árboles de decisión en el bosque.
  - `max_depth = 25`: Profundidad máxima para prevenir sobreajuste memorístico.
  - `min_samples_split = 2`: Mínimo de muestras para dividir un nodo.
  - `class_weight = 'balanced'`: Compensación del desbalance de categorías.
  - `random_state = 42`.
- **Justificación:** Provee no-linealidad intrínseca y robustez ante ruido, además de permitir analizar la importancia relativa de variables de seguridad.

### 3. Regresión Logística Multinomial
- **Arquitectura:** Clasificador lineal multinomial con función softmax.
- **Hiperparámetros:**
  - `C = 2.0`: Intensidad de regularización L2 inversa.
  - `max_iter = 1000`.
  - `class_weight = 'balanced'`.
  - `random_state = 42`.
- **Justificación:** Modelo de referencia (*baseline*) probabilístico, altamente interpretable y computacionalmente eficiente.

---

## 2. Pipeline de Inferencia
El modelo final serializado (`models/vulnerability_classifier.joblib`) no requiere re-entrenamiento y se ejecuta directamente desde la CLI o la interfaz web mediante:
```python
X = pipeline.transform([codigo_fuente])
pred_idx = model.predict(X)[0]
probas = model.predict_proba(X)[0]
categoria = label_encoder.inverse_transform([pred_idx])[0]
confianza = np.max(probas)
```
