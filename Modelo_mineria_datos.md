

**Universidad de las Fuerzas Armadas ESPE Departamento de Ciencias de la Computaci´on** 

**Carrera de Ingenier´ıa en Software** 

**Desarrollo de Software Seguro** 

# **Laboratorio 1** 

Docente: Prof. Geovanny Cudco 19 de noviembre de 2026 

# **1. Tema** 

Miner´ıa de datos aplicada a la clasificaci´on de vulnerabilidades en arquitecturas de microservicios 

# **2. Descripci´on de la actividad** 

El Laboratorio consiste en desarrollar una herramienta inteligente para el an´alisis de seguridad de proyectos de software basados en arquitecturas de microservicios, mediante la aplicaci´on de t´ecnicas de miner´ıa de datos y aprendizaje autom´atico. 

La soluci´on deber´a identificar patrones asociados con posibles vulnerabilidades de seguridad presentes en el c´odigo fuente, las interfaces de programaci´on de aplicaciones (API) y los archivos de configuraci´on, clasific´andolos conforme a los siguientes est´andares: 

- **OWASP Top 10:2025:** principales categor´ıas de riesgos de seguridad en aplicaciones web. 

- **OWASP API Security Top 10:2023:** principales categor´ıas de riesgos de seguridad asociados con las API. 

El desarrollo deber´a seguir obligatoriamente la metodolog´ıa **SEMMA (Sample, Explore, Modify, Model, Assess)** , contemplando la selecci´on de datos, el an´alisis exploratorio, el preprocesamiento, el entrenamiento de modelos y la evaluaci´on de resultados. 

Como resultado, los estudiantes deber´an implementar una herramienta ejecutable mediante una interfaz de l´ınea de comandos (CLI), capaz de analizar autom´aticamente un proyecto de microservicios desde su directorio ra´ız y generar un reporte de posibles vulnerabilidades clasificadas seg´un los est´andares establecidos. 

1 

# **3. Objetivos** 

## **3.1. Objetivo general** 

Desarrollar e integrar un modelo de miner´ıa de datos capaz de analizar proyectos de software basados en arquitecturas de microservicios, identificar patrones asociados con posibles vulnerabilidades de seguridad y clasificarlos conforme a OWASP Top 10:2025 y OWASP API Security Top 10:2023, mediante una herramienta ejecutable por l´ınea de comandos, siguiendo las fases de la metodolog´ıa SEMMA. 

## **3.2. Objetivos espec´ıficos** 

1. Construir un conjunto de datos etiquetado que contenga ejemplos de c´odigo fuente y configuraciones seguras y vulnerables, asociados con categor´ıas de seguridad OWASP. 

2. Aplicar las fases de la metodolog´ıa SEMMA para explorar, preparar y transformar los datos utilizados en el entrenamiento del modelo. 

3. Implementar y comparar al menos dos algoritmos de clasificaci´on supervisada para identificar patrones asociados con vulnerabilidades de software. 

4. Integrar el modelo seleccionado en una herramienta CLI que permita analizar autom´aticamente proyectos desarrollados mediante arquitecturas de microservicios. 

5. Clasificar los posibles hallazgos conforme a OWASP Top 10:2025 y OWASP API Security Top 10:2023, generando reportes estructurados con evidencias y recomendaciones. 

6. Evaluar el desempe˜no del modelo y la herramienta utilizando m´etricas de clasificaci´on y proyectos de software no utilizados durante el entrenamiento. 

# **4. Est´andares de clasificaci´on** 

La herramienta deber´a contemplar las categor´ıas de ambos est´andares OWASP, utilizando sus identificadores oficiales. 

2 

## **4.1. OWASP Top 10:2025** 

Tabla 1: Categor´ıas de clasificaci´on OWASP Top 10:2025 

|**C´odigo**|**Categor´ıa**|
|---|---|
|A01:2025|P´erdida de control de acceso (Broken Access Control)|
|A02:2025|Configuraci´on de seguridad incorrecta (Security Misconfiguration)|
|A03:2025|Fallas en la cadena de suministro de software (Software Supply Chain<br>Failures)|
|A04:2025|Fallas criptogr´aficas (Cryptographic Failures)|
|A05:2025|Inyecci´on (Injection)|
|A06:2025|Dise˜no inseguro (Insecure Design)|
|A07:2025|Fallas de autenticaci´on (Authentication Failures)|
|A08:2025|Fallas en la integridad del software o de los datos (Software or Data<br>Integrity Failures)|
|A09:2025|Fallas en el registro, alerta y monitoreo de seguridad (Security<br>Logging and Alerting Failures)|
|A10:2025|Manejo inadecuado de condiciones excepcionales (Mishandling of<br>Exceptional Conditions)|



## **4.2. OWASP API Security Top 10:2023** 

Tabla 2: Categor´ıas de clasificaci´on OWASP API Security Top 10:2023 

|**C´odigo**|**Categor´ıa**|
|---|---|
|API1:2023|Autorizaci´on incorrecta a nivel de objeto (Broken Object Level<br>Authorization)|
|API2:2023|Autenticaci´on incorrecta (Broken Authentication)|
|API3:2023|Autorizaci´on incorrecta a nivel de propiedades del objeto (Broken<br>Object Property Level Authorization)|
|API4:2023|Consumo ilimitado de recursos(Unrestricted Resource Consumption)|
|API5:2023|Autorizaci´on incorrecta a nivel de funci´on (Broken Function Level<br>Authorization)|
|API6:2023|Acceso ilimitado a flujos de negocio sensibles (Unrestricted Access to<br>Sensitive Business Flows)|
|API7:2023|Falsificaci´on de solicitudes del lado del servidor (Server Side Request<br>Forgery)|
|API8:2023|Configuraci´on de seguridad incorrecta (Security Misconfiguration)|
|API9:2023|Gesti´on inadecuada del inventario de API (Improper Inventory<br>Management)|
|API10:2023|Consumo inseguro de API (Unsafe Consumption of APIs)|



**Consideraciones de clasificaci´on** Una vulnerabilidad puede corresponder simult´aneamente a categor´ıas de ambos est´andares. Por lo tanto, la soluci´on deber´a permitir la asignaci´on de m´ultiples etiquetas cuando exista evidencia suficiente. 

La clasificaci´on deber´a apoyarse en caracter´ısticas extra´ıdas del c´odigo y, cuando corresponda, en relaciones documentadas entre debilidades CWE y categor´ıas OWASP. Cuando el modelo no disponga de evidencia suficiente para determinar una categor´ıa, 

3 

el hallazgo deber´a identificarse como pendiente de revisi´on, evitando asignaciones arbitrarias. 

# **5. Requerimientos funcionales** 

La soluci´on propuesta deber´a cumplir los requerimientos establecidos en la Tabla 3. 

Tabla 3: Requerimientos funcionales del proyecto 

|**C´odigo**|**Requerimiento**|
|---|---|
|RF01|Construir un conjunto de datos que contenga ejemplos de c´odigo<br>vulnerable y no vulnerable.|
|RF02|Aplicar y documentar las cinco fases de la metodolog´ıa SEMMA.|
|RF03|Entrenar y comparar al menos dos algoritmos de clasificaci´on<br>supervisada.|
|RF04|Implementar<br>mecanismos<br>de<br>an´alisis<br>est´atico<br>para<br>identificar<br>patrones asociados con posibles vulnerabilidades en c´odigo fuente y<br>configuraciones.|
|RF05|Clasificar los hallazgos conforme a OWASP Top 10:2025 y OWASP<br>API Security Top 10:2023.|
|RF06|Identificar autom´aticamente los microservicios que forman parte de<br>un proyecto de software.|
|RF07|Implementar una herramienta CLI ejecutable desde el directorio ra´ız<br>del proyecto analizado.|
|RF08|Identificar el microservicio, archivo y ubicaci´on correspondiente a cada<br>posible hallazgo.|
|RF09|Generar reportes de resultados en formatos JSON y HTML.|
|RF10|Evaluar el desempe˜no del modelo mediante m´etricas de clasificaci´on<br>y pruebas sobre proyectos no utilizados durante el entrenamiento.|



# **6. Alcance t´ecnico** 

La herramienta deber´a analizar proyectos de software que implementen arquitecturas de microservicios y soportar, como m´ınimo, dos de los siguientes lenguajes de programaci´on: 

- Java. 

- Python. 

- JavaScript. 

- TypeScript. 

Adem´as del c´odigo fuente, deber´a considerar archivos de configuraci´on cuando est´en presentes, tales como: 

`application.yml` y `application.properties` . 

4 

`Dockerfile` . 

- `docker-compose.yml` . 

- Archivos de definici´on de API. 

Archivos de dependencias y configuraci´on de seguridad. 

El sistema deber´a incorporar el cat´alogo de las veinte categor´ıas OWASP establecidas en ambos est´andares. 

Para la demostraci´on pr´actica se exigir´a evidencia de clasificaci´on sobre, al menos, cinco categor´ıas de OWASP Top 10:2025 y cuatro categor´ıas de OWASP API Security Top 10:2023. 

Las categor´ıas que no cuenten con datos suficientes o mecanismos adecuados de detecci´on deber´an declararse expl´ıcitamente como no evaluadas. 

# **7. Desarrollo del proyecto mediante la metodolog´ıa SEMMA** 

El desarrollo deber´a organizarse obligatoriamente en las cinco fases de la metodolog´ıa SEMMA. 

## **7.1. Fase 1. Sample: Muestreo y selecci´on de datos** 

**Objetivo:** construir un conjunto de datos representativo que contenga ejemplos de c´odigo fuente y configuraciones asociados con diferentes categor´ıas de vulnerabilidades. 

### **Actividades** 

1. Identificar repositorios y conjuntos de datos p´ublicos que contengan ejemplos de c´odigo vulnerable y seguro. 

2. Seleccionar fragmentos de c´odigo y configuraciones relacionados con vulnerabilidades de aplicaciones y API. 

3. Registrar informaci´on sobre el lenguaje de programaci´on, procedencia, tipo de vulnerabilidad y categor´ıa de seguridad. 

4. Construir un dataset etiquetado que diferencie ejemplos vulnerables y no vulnerables. 

5. Establecer una correspondencia documentada entre las debilidades CWE y las categor´ıas OWASP aplicables. 

6. Separar los datos en conjuntos de entrenamiento, validaci´on y prueba, evitando duplicados y filtraciones de informaci´on entre particiones. 

5 

### **Fuentes de datos sugeridas** 

- OWASP Benchmark: `https://owasp.org/www-project-benchmark/` 

- NIST Software Assurance Reference Dataset (SARD): `https://samate.nist.gov/SARD/` 

- Repositorios p´ublicos con ejemplos documentados de vulnerabilidades. 

- Casos controlados de vulnerabilidades desarrollados por los estudiantes. 

**Condiciones m´ınimas** El conjunto de datos deber´a contener al menos 500 registros etiquetados, incluyendo un m´ınimo de 100 ejemplos no vulnerables. 

Se recomienda distribuir los datos en un 70 % para entrenamiento, 15 % para validaci´on y 15 % para prueba, utilizando una separaci´on por proyecto de origen cuando corresponda. 

### **Entregables de la fase** 

Dataset etiquetado en formato CSV o equivalente. 

- Diccionario de datos. 

Descripci´on de las fuentes utilizadas. 

Justificaci´on del procedimiento de muestreo. 

Tabla de correspondencias CWE–OWASP. 

## **7.2. Fase 2. Explore: An´alisis exploratorio de datos** 

**Objetivo:** examinar las caracter´ısticas y distribuciones del conjunto de datos para identificar patrones, inconsistencias, desequilibrios y relaciones relevantes. 

### **Actividades** 

1. Determinar el n´umero de registros disponibles y su distribuci´on por categor´ıas de vulnerabilidad. 

2. Analizar la proporci´on de ejemplos vulnerables y no vulnerables. 

3. Identificar las categor´ıas OWASP con mayor y menor representaci´on. 

4. Analizar la distribuci´on de los lenguajes de programaci´on. 

5. Examinar las caracter´ısticas de los fragmentos de c´odigo, incluyendo longitud, estructuras sint´acticas y patrones frecuentes. 

6. Identificar datos duplicados, valores faltantes e inconsistencias en las etiquetas. 

7. Generar visualizaciones que permitan interpretar las caracter´ısticas del dataset. 

6 

### **Visualizaciones m´ınimas** 

- Gr´afico de barras con la distribuci´on de categor´ıas OWASP. 

- Gr´afico de distribuci´on de ejemplos vulnerables y no vulnerables. 

- Distribuci´on de registros por lenguaje de programaci´on. 

- Gr´afico de frecuencias de caracter´ısticas o patrones relevantes. 

- Visualizaci´on del desbalance entre clases. 

### **Entregables de la fase** 

Notebook de an´alisis exploratorio. 

Tablas estad´ısticas descriptivas. 

Gr´aficos interpretados. 

Conclusiones sobre la calidad y representatividad del dataset. 

## **7.3. Fase 3. Modify: Preparaci´on y transformaci´on de datos** 

**Objetivo:** transformar los registros originales en una representaci´on adecuada para el entrenamiento de algoritmos de miner´ıa de datos. 

### **Actividades** 

1. Limpiar registros duplicados, incompletos o inconsistentes. 

2. Normalizar la estructura de los datos y las etiquetas. 

3. Implementar mecanismos de tokenizaci´on o representaci´on del c´odigo fuente. 

4. Extraer caracter´ısticas relevantes para identificar posibles vulnerabilidades. 

5. Construir representaciones num´ericas mediante t´ecnicas como TF-IDF, caracter´ısticas sint´acticas, m´etricas de c´odigo o embeddings. 

6. Aplicar t´ecnicas de tratamiento del desbalance entre clases cuando resulte necesario. 

7. Preparar los conjuntos de entrenamiento, validaci´on y prueba conservando su independencia. 

7 

### **Caracter´ısticas sugeridas** 

- Presencia de consultas din´amicas a bases de datos. 

- Uso de mecanismos de autenticaci´on y autorizaci´on. 

- Validaci´on de par´ametros de entrada. 

- Uso de funciones criptogr´aficas. 

- Gesti´on de errores y excepciones. 

- Configuraciones relacionadas con permisos y seguridad. 

- Gesti´on de tokens y credenciales. 

- Caracter´ısticas de rutas y endpoints REST. 

- Dependencias y configuraciones de componentes externos. 

### **Entregables de la fase** 

Scripts de limpieza y transformaci´on. 

- Pipeline reproducible de preprocesamiento. 

- Matriz de caracter´ısticas. 

Justificaci´on de las transformaciones aplicadas. 

## **7.4. Fase 4. Model: Construcci´on del modelo** 

**Objetivo:** desarrollar modelos de clasificaci´on supervisada que permitan reconocer patrones asociados con vulnerabilidades de seguridad. 

### **Actividades** 

1. Seleccionar al menos dos algoritmos de clasificaci´on supervisada. 

2. Entrenar los modelos utilizando los datos preparados. 

3. Ajustar hiperpar´ametros mediante un procedimiento de validaci´on adecuado. 

4. Comparar el desempe˜no de los algoritmos seleccionados. 

5. Implementar la asignaci´on de etiquetas correspondientes a los est´andares OWASP. 

6. Seleccionar el modelo con mejor desempe˜no, justificando los criterios utilizados. 

7. Serializar el modelo y el pipeline de preprocesamiento para su utilizaci´on posterior. 

8 

### **Algoritmos sugeridos** 

- Regresi´on log´ıstica. 

- Random Forest. 

- Support Vector Machine (SVM). 

Otros algoritmos de clasificaci´on supervisada debidamente justificados. 

El modelo deber´a aprender patrones a partir de los datos de entrenamiento. No se aceptar´a como ´unico mecanismo de clasificaci´on la implementaci´on de expresiones regulares o condiciones predefinidas que asignen directamente categor´ıas OWASP. 

Podr´an incorporarse reglas de an´alisis est´atico como mecanismos complementarios de extracci´on de caracter´ısticas, identificaci´on de evidencias o validaci´on. 

### **Entregables de la fase** 

C´odigo de entrenamiento de los modelos. 

Descripci´on de algoritmos e hiperpar´ametros. 

- Comparaci´on experimental. 

Modelo entrenado y serializado. 

Pipeline necesario para realizar nuevas predicciones. 

## **7.5. Fase 5. Assess: Evaluaci´on del modelo** 

**Objetivo:** evaluar la capacidad del modelo para clasificar posibles vulnerabilidades y determinar sus limitaciones sobre datos y proyectos no utilizados en el entrenamiento. 

### **Actividades** 

1. Evaluar los modelos utilizando un conjunto de prueba independiente. 

2. Calcular m´etricas de clasificaci´on apropiadas para el problema. 

3. Elaborar matrices de confusi´on cuando corresponda. 

4. Analizar los falsos positivos y falsos negativos. 

5. Evaluar el desempe˜no por categor´ıa OWASP. 

6. Identificar posibles problemas de sobreajuste y generalizaci´on. 

7. Ejecutar pruebas funcionales de la herramienta sobre proyectos de microservicios no utilizados durante el entrenamiento. 

9 

### **M´etricas obligatorias** 

- Precisi´on ( _Precision_ ). 

- Sensibilidad o exhaustividad ( _Recall_ ). 

- Medida F1 ( _F1-score_ ). 

- F1 macro y m´etricas por categor´ıa. 

- Matrices de confusi´on cuando sean aplicables. 

An´alisis de falsos positivos y falsos negativos. 

En escenarios de clasificaci´on multietiqueta deber´an utilizarse m´etricas compatibles con esta configuraci´on. 

### **Entregables de la fase** 

- Resultados cuantitativos de evaluaci´on. 

- Tablas comparativas de desempe˜no. 

- Gr´aficos de evaluaci´on. 

An´alisis de errores. 

- Conclusiones sobre la capacidad de generalizaci´on. 

# **8. Integraci´on del modelo mediante una herramienta CLI** 

Una vez seleccionado y evaluado el modelo, los estudiantes deber´an integrarlo en una aplicaci´on ejecutable mediante l´ınea de comandos. 

La herramienta deber´a permitir analizar un repositorio completo de microservicios, utilizando el modelo entrenado para clasificar los posibles hallazgos. 

## **8.1. Escenario de evaluaci´on** 

El docente proporcionar´a un proyecto de software que podr´a incluir una arquitectura similar a la siguiente: 

```
proyecto-microservicios/
|
```

- `|-- api-gateway/` 

- `|` 

- `|-- user-service/` 

- `| |-- src/` 

- `| |-- package.json` 

- `|` 

- `|-- product-service/` 

10 

- `| |-- src/` 

- `| |--` 

   - `pom.xml` 

- `| |-- Dockerfile` 

- `|` 

- `|-- order-service/` 

- `| |-- app/` 

- `| |-- requirements.txt` 

- `|` 

- `|-- docker-compose.yml` 

El proyecto podr´a integrar microservicios desarrollados con tecnolog´ıas diferentes, como NestJS, Spring Boot y FastAPI. 

## **8.2. Ejecuci´on de la herramienta** 

La aplicaci´on deber´a instalarse o configurarse de manera que pueda ejecutarse desde el directorio ra´ız del proyecto que se desea analizar. 

Se propone la siguiente interfaz de ejecuci´on: 

```
cdproyecto-microservicios
```

```
vulnminerscan.\
```

```
--standardsowasp2025,api2023\
```

```
--formatjson,html\
```

```
--output./reportes
```

El nombre `vulnminer` es referencial y podr´a ser sustituido por el nombre seleccionado por cada equipo. 

## **8.3. Proceso de an´alisis** 

Durante la ejecuci´on, la herramienta deber´a realizar las siguientes operaciones: 

1. Identificar el directorio ra´ız del proyecto. 

2. Descubrir los microservicios y reconocer los lenguajes y tecnolog´ıas soportados. 

3. Identificar los archivos de c´odigo fuente y configuraci´on que ser´an analizados. 

4. Extraer las caracter´ısticas requeridas por el modelo de clasificaci´on. 

5. Aplicar el pipeline de preprocesamiento y el modelo previamente entrenado. 

6. Obtener las predicciones correspondientes a posibles vulnerabilidades. 

7. Asignar las categor´ıas OWASP aplicables, considerando las relaciones entre ambos est´andares. 

8. Registrar la ubicaci´on y las evidencias correspondientes a cada hallazgo. 

9. Presentar un resumen de resultados en consola. 

10. Generar reportes estructurados en formatos JSON y HTML. 

11 

### **8.3.1. Ejemplo de salida esperada** 

El siguiente resultado es ilustrativo y representa el formato esperado de la herramienta: 

```
========================================
```

```
VULNMINER-SECURITYSCAN
========================================
```

```
Proyecto:proyecto-microservicios
Microserviciosidentificados:3
Archivosanalizados:125
Hallazgospotenciales:8
```

```
----------------------------------------
HALLAZGO001
```

```
Servicio:user-service
Archivo:src/users/users.controller.ts
Linea:42
OWASPTop10:A01:2025
OWASPAPI:API1:2023
```

```
Problemapotencial:
Autorizacioninsuficientesobreobjetos
```

```
Confianzadelmodelo:0.86
Severidadestimada:Alta
Estado:Requiereverificacion
```

```
----------------------------------------
HALLAZGO002
```

```
Servicio:product-service
Archivo:application.yml
Linea:18
```

```
OWASPTop10:A02:2025
OWASPAPI:API8:2023
Problemapotencial:
Configuracioninsegura
```

```
Confianzadelmodelo:0.81
Severidadestimada:Media
Estado:Requiereverificacion
```

12 

```
REPORTESGENERADOS
```

```
reportes/analisis.json
reportes/analisis.html
```

```
========================================
```

### **8.3.2. Informaci´on m´ınima de cada hallazgo** 

Cada posible vulnerabilidad reportada deber´a contener: 

1. Identificador ´unico del hallazgo. 

2. Nombre del microservicio analizado. 

3. Ruta del archivo. 

4. L´ınea o ubicaci´on del patr´on identificado, cuando pueda determinarse. 

5. Descripci´on del posible problema de seguridad. 

6. Evidencia t´ecnica que respalda el hallazgo. 

7. Categor´ıa OWASP Top 10:2025 aplicable. 

8. Categor´ıa OWASP API Security Top 10:2023 aplicable, cuando corresponda. 

9. Identificador CWE, cuando pueda establecerse. 

10. Nivel de confianza de la predicci´on. 

11. Severidad estimada y su justificaci´on. 

12. Recomendaci´on de remediaci´on. 

13. Estado de verificaci´on. 

La confianza del modelo no deber´a interpretarse autom´aticamente como el nivel de severidad de la vulnerabilidad. 

Asimismo, la herramienta deber´a diferenciar entre hallazgos potenciales y vulnerabilidades confirmadas. Algunas categor´ıas, como los problemas de autorizaci´on a nivel de objeto, los errores de l´ogica de negocio o las deficiencias de monitoreo, pueden requerir validaci´on din´amica o revisi´on manual. 

13 

# **9. Entregables** 

Los estudiantes deber´an presentar los siguientes productos: 

1. **Repositorio Git del proyecto:** c´odigo fuente completo, organizaci´on de directorios, dependencias y documentaci´on de instalaci´on. 

2. **Dataset etiquetado:** conjunto de registros utilizados, fuentes, diccionario de datos y correspondencias con categor´ıas OWASP. 

3. **Notebooks SEMMA:** evidencia de las cinco fases, incluyendo procesamiento, estad´ısticas, visualizaciones, entrenamiento y evaluaci´on. 

4. **Modelo entrenado:** archivo serializado del modelo seleccionado, junto con su pipeline de transformaci´on. 

5. **Herramienta CLI:** aplicaci´on funcional capaz de analizar proyectos de microservicios sin necesidad de ejecutar nuevamente el entrenamiento. 

6. **Reportes de seguridad:** resultados exportados en JSON y HTML, con evidencias y clasificaci´on por microservicio. 

7. **Informe t´ecnico:** documento que describa el problema, metodolog´ıa, arquitectura de la soluci´on, experimentos, resultados, limitaciones y conclusiones. 

8. **Demostraci´on funcional:** ejecuci´on de la herramienta sobre un proyecto de microservicios desconocido, proporcionado por el docente. 

# **10. R´ubrica de evaluaci´on** 

La evaluaci´on se realizar´a sobre un total de 20 puntos, considerando el cumplimiento de la metodolog´ıa SEMMA y la integraci´on funcional del modelo. 

Tabla 4: R´ubrica de evaluaci´on del proyecto integrador 

|**Criterio de evaluaci´on**|**Puntaje**|
|---|---|
|Sample: calidad, etiquetado y trazabilidad del conjunto de datos|2|
|Explore: an´alisis exploratorio, estad´ısticas y visualizaciones|2|
|Modify:<br>preprocesamiento,<br>transformaci´on<br>y<br>extracci´on<br>de<br>caracter´ısticas|2|
|Model: entrenamiento, comparaci´on y selecci´on de modelos|4|
|Assess: evaluaci´on, m´etricas y an´alisis de resultados|3|
|CLI: integraci´on, clasificaci´on OWASP, funcionamiento y reportes|5|
|Documentaci´on t´ecnica y demostraci´on funcional|2|
|**Total**|**20**|



## **10.1. Condiciones de aceptaci´on** 

Para considerar satisfactoria la implementaci´on, el proyecto deber´a cumplir las siguientes condiciones: 

14 

1. Demostrar la aplicaci´on de las cinco fases de SEMMA mediante c´odigo, resultados y documentaci´on. 

2. Disponer de un conjunto de datos etiquetado que permita reproducir el proceso de entrenamiento. 

3. Comparar al menos dos algoritmos de clasificaci´on y justificar la selecci´on del modelo final. 

4. Utilizar el modelo previamente entrenado para analizar proyectos nuevos, sin requerir un nuevo entrenamiento durante cada ejecuci´on. 

5. Ejecutar la herramienta mediante una ´unica instrucci´on CLI desde el directorio ra´ız del proyecto analizado. 

6. Analizar c´odigo fuente de al menos dos lenguajes de programaci´on soportados. 

7. Generar hallazgos con categor´ıas OWASP, ubicaci´on, evidencia y recomendaciones. 

8. Demostrar cobertura funcional sobre al menos cinco categor´ıas de OWASP Top 10:2025 y cuatro categor´ıas de OWASP API Security Top 10:2023. 

9. Generar reportes JSON y HTML que permitan examinar los resultados por microservicio y categor´ıa. 

10. Presentar resultados de evaluaci´on que permitan interpretar la precisi´on, los errores y las limitaciones del modelo. 

**Restricci´on principal** No se aceptar´an soluciones que consistan exclusivamente en ejecutar herramientas de an´alisis est´atico preexistentes o implementar reglas manuales de b´usqueda. 

El componente central del proyecto deber´a ser un modelo de miner´ıa de datos entrenado, evaluado e integrado funcionalmente mediante la metodolog´ıa SEMMA. **<mark>NO</mark>** 

### **<mark>SE ACEPTAN LLM</mark>** 

Las herramientas de an´alisis est´atico, las reglas de seguridad y los analizadores sint´acticos podr´an utilizarse como componentes complementarios de la soluci´on, siempre que se evidencie la contribuci´on del modelo de clasificaci´on desarrollado. 

## **10.2. Pregunta orientadora** 

_¿En qu´e medida un modelo de miner´ıa de datos desarrollado mediante la metodolog´ıa SEMMA permite identificar y clasificar posibles vulnerabilidades de seguridad en proyectos basados en arquitecturas de microservicios, conforme a OWASP Top 10:2025 y OWASP API Security Top 10:2023?_ 

## **10.3. Resultado esperado** 

Al finalizar el proyecto, los estudiantes deber´an disponer de una soluci´on funcional que integre miner´ıa de datos, aprendizaje autom´atico, an´alisis de c´odigo fuente y seguridad de software. 

15 

La herramienta deber´a permitir analizar un repositorio de microservicios mediante una interfaz de l´ınea de comandos, identificar patrones asociados con posibles vulnerabilidades y generar reportes estructurados conforme a los est´andares OWASP establecidos. 

Adem´as del funcionamiento de la herramienta, los estudiantes deber´an demostrar capacidad para interpretar los resultados del modelo, justificar sus predicciones, reconocer las limitaciones del enfoque y proponer mejoras orientadas a incrementar la confiabilidad del an´alisis de seguridad. 

## **10.4. Fecha de entrega** 

La entrega del proyecto integrador se realizar´a el **<mark>jueves 26 de noviembre de 2026</mark>** <mark>,</mark> en el **<mark>horario habitual de clases</mark>** <mark>.</mark> 

Los estudiantes deber´an presentar todos los entregables establecidos y realizar la demostraci´on funcional de la herramienta CLI, ejecutando el an´alisis de un proyecto de microservicios y mostrando los resultados de clasificaci´on de vulnerabilidades conforme a los est´andares OWASP establecidos. 

16 

