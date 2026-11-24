"""
Fase 2 de SEMMA: Explore (Análisis Exploratorio de Datos)
Genera estadísticas descriptivas y visualizaciones analíticas del conjunto de datos.
"""

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configuración visual
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
FIGURES_DIR = "reports/figures"
os.makedirs(FIGURES_DIR, exist_ok=True)

def run_explore_phase():
    dataset_path = "data/processed/dataset_vulnerabilidades.csv"
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"No se encontró el dataset en {dataset_path}")

    df = pd.read_csv(dataset_path)
    df['char_length'] = df['code_snippet'].apply(len)
    df['line_count'] = df['code_snippet'].apply(lambda x: len(x.splitlines()))

    print("=== FASE 2: EXPLORE (ANÁLISIS EXPLORATORIO DE DATOS) ===")
    print(f"Total registros: {len(df)}")
    print(f"Variables presentes: {list(df.columns)}")
    print("\nResumen de longitudes de código:")
    print(df[['char_length', 'line_count']].describe())

    # 1. Gráfico de distribución de ejemplos vulnerables vs no vulnerables
    plt.figure(figsize=(7, 5))
    vuln_counts = df['is_vulnerable'].value_counts()
    colors = ['#2ecc71', '#e74c3c']
    labels = ['Seguro (0)', 'Vulnerable (1)']
    bars = plt.bar(labels, [vuln_counts.get(0, 0), vuln_counts.get(1, 0)], color=colors, width=0.5)
    plt.title('Distribución de Clases: Seguro vs Vulnerable', fontsize=13, fontweight='bold')
    plt.ylabel('Cantidad de Muestras')
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 5, f"{yval} ({yval/len(df)*100:.1f}%)", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "vulnerable_vs_safe.png"), dpi=300)
    plt.close()

    # 2. Distribución de registros por lenguaje de programación
    plt.figure(figsize=(9, 5))
    lang_counts = df['language'].value_counts()
    sns.barplot(x=lang_counts.index, y=lang_counts.values, hue=lang_counts.index, palette='mako', legend=False)
    plt.title('Distribución de Muestras por Lenguaje / Tipo de Archivo', fontsize=13, fontweight='bold')
    plt.xlabel('Lenguaje / Formato')
    plt.ylabel('Cantidad de Muestras')
    for i, val in enumerate(lang_counts.values):
        plt.text(i, val + 2, str(val), ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "language_distribution.png"), dpi=300)
    plt.close()

    # 3. Distribución de Categorías OWASP Top 10:2025
    plt.figure(figsize=(10, 6))
    owasp_counts = df[df['owasp_top10'] != 'NONE']['owasp_top10'].value_counts()
    sns.barplot(x=owasp_counts.values, y=owasp_counts.index, hue=owasp_counts.index, palette='viridis', legend=False)
    plt.title('Distribución de Muestras por OWASP Top 10:2025', fontsize=13, fontweight='bold')
    plt.xlabel('Cantidad de Muestras')
    plt.ylabel('Categoría OWASP Top 10')
    for i, val in enumerate(owasp_counts.values):
        plt.text(val + 1, i, str(val), va='center', fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "owasp_distribution.png"), dpi=300)
    plt.close()

    # 4. Distribución de Categorías OWASP API Security Top 10:2023
    plt.figure(figsize=(10, 5))
    api_counts = df[df['owasp_api'] != 'NONE']['owasp_api'].value_counts()
    sns.barplot(x=api_counts.values, y=api_counts.index, hue=api_counts.index, palette='rocket', legend=False)
    plt.title('Distribución de Muestras por OWASP API Security Top 10:2023', fontsize=13, fontweight='bold')
    plt.xlabel('Cantidad de Muestras')
    plt.ylabel('Categoría OWASP API')
    for i, val in enumerate(api_counts.values):
        plt.text(val + 1, i, str(val), va='center', fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "owasp_api_distribution.png"), dpi=300)
    plt.close()

    # 5. Desbalance entre Clases / Categorías Técnicas
    plt.figure(figsize=(12, 6))
    cat_counts = df['category'].value_counts()
    sns.barplot(x=cat_counts.values, y=cat_counts.index, hue=cat_counts.index, palette='Spectral', legend=False)
    plt.title('Distribución de Todas las Clases Técnicas (Desbalance de Clases)', fontsize=13, fontweight='bold')
    plt.xlabel('Frecuencia')
    plt.ylabel('Categoría')
    for i, val in enumerate(cat_counts.values):
        plt.text(val + 1, i, str(val), va='center')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "class_imbalance.png"), dpi=300)
    plt.close()

    # 6. Diagrama de caja de longitud de código por categoría
    plt.figure(figsize=(12, 6))
    sns.boxplot(data=df, x='char_length', y='category', hue='category', palette='coolwarm', legend=False)
    plt.title('Longitud en Caracteres del Fragmento por Categoría Técnica', fontsize=13, fontweight='bold')
    plt.xlabel('Longitud en Caracteres')
    plt.ylabel('Categoría')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "code_length_boxplot.png"), dpi=300)
    plt.close()

    print(f"\n[OK] Gráficos estadísticos generados exitosamente en '{FIGURES_DIR}/'")

if __name__ == "__main__":
    run_explore_phase()
