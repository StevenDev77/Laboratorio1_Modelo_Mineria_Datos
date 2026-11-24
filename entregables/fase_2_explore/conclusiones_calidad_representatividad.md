# FASE 2: EXPLORE (CONCLUSIONES SOBRE LA CALIDAD Y REPRESENTATIVIDAD DEL DATASET)

## 1. Conclusiones sobre la Calidad de los Datos
1. **Completitud y Ausencia de Valores Nulos:** Todos los registros contienen código fuente no vacío, etiqueta técnica verificada, lenguaje asignado e identificador CWE/OWASP correspondiente. No existen valores faltantes (`NaN`).
2. **Diversidad Multilenguaje Equilibrada:** El dataset contempla cuatro lenguajes de programación principales para microservicios (**Python, Java, JavaScript, TypeScript**) más dos formatos clave de infraestructura de despliegue (**YAML y Dockerfile**). Esto garantiza que el modelo aprenda patrones sintácticos universales en vez de memorizar palabras reservadas de un único ecosistema.
3. **Consistencia en el Etiquetado:** La correspondencia entre debilidades CWE y categorías OWASP Top 10:2025 y API:2023 respeta la documentación oficial del NIST y OWASP, evitando asignaciones ambiguas o contradictorias.

---

## 2. Conclusiones sobre la Representatividad
1. **Garantía del Grupo de Control (Código Seguro):** Con **144 muestras seguras** (27.2%), el dataset supera holgadamente el requisito de 100 registros. Estas muestras contienen construcciones defensivas canónicas (consultas parametrizadas, decorators de rol, verificación estricta de firma JWT, rate limiters y DTOs tipados), lo cual es crítico para que el modelo aprenda a suprimir falsos positivos.
2. **Cobertura de Estándares Internacionales:**
   - **OWASP Top 10:2025:** 7 categorías representadas (A01, A02, A04, A05, A06, A07, A10), superando el mínimo requerido de 5.
   - **OWASP API Security Top 10:2023:** 7 categorías representadas (API1, API2, API3, API4, API5, API7, API8), superando el mínimo requerido de 4.
3. **Control del Desbalance de Clases:** Aunque existe una mayor proporción de código vulnerable frente a seguro (72.8% vs 27.2%), la estratificación implementada y el posterior uso de funciones de pérdida balanceadas (`class_weight='balanced'`) en los clasificadores mitigan cualquier sesgo predictivo, como se demostró experimentalmente en la Fase 5.

---

## 3. Gráficos Interpretados Asociados
Todos los gráficos generados en alta resolución se encuentran en la subcarpeta `graficos_interpretados/`:
- `vulnerable_vs_safe.png`: Proporción de clases binarias.
- `language_distribution.png`: Frecuencia por tecnología.
- `owasp_distribution.png`: Cobertura OWASP Top 10:2025.
- `owasp_api_distribution.png`: Cobertura OWASP API Security:2023.
- `class_imbalance.png`: Distribución de las 13 clases del problema.
- `code_length_boxplot.png`: Dispersión de longitud de fragmentos de código.
