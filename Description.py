import mysql.connector
import pandas as pd
from Tools.Functions import *
from collections import Counter
import re
import matplotlib.pyplot as plt
from nltk.corpus import stopwords
import plotly.graph_objects as go
import seaborn as sns

# Descargar stopwords de NLTK si no las tienes
import nltk


db_config = load_config('./Config/Parameters.json')
db_config = db_config['database']

# Conectar a la base de datos
conn = mysql.connector.connect(**db_config)

query = "SELECT id, description_en FROM cve_data"

# Ejecutar la consulta y cargar los resultados en un DataFrame de pandas
data = pd.read_sql(query, conn)



# Aplicar el análisis de sentimientos a las descripciones en inglés
data['sentiment_en'] = data['description_en'].apply(analyze_sentiment)
sentiment_summary = data['sentiment_en'].describe()
print("Resumen de sentimientos de las descripciones en inglés:")
print(sentiment_summary)
data['sentiment_class'] = data['sentiment_en'].apply(classify_sentiment)
print(data[['id', 'sentiment_en', 'sentiment_class']])


nltk.download('stopwords')

# Obtener las stopwords en inglés
stop_words = set(stopwords.words('english'))

# Función para contar palabras en las descripciones excluyendo stop words y números
def word_frequency(descriptions):
    words = []
    for desc in descriptions:
        if desc:  # Evitar descripciones nulas
            # Extraer palabras, evitar números y convertir todo a minúsculas
            filtered_words = [word for word in re.findall(r'\w+', desc.lower()) 
                              if word not in stop_words and not word.isdigit()]
            words.extend(filtered_words)
    return Counter(words)

# Analizar frecuencia de palabras en las descripciones en inglés
en_word_freq = word_frequency(data['description_en'])

# Obtener las 10 palabras más comunes
common_words = en_word_freq.most_common(50)

# Mostrar las palabras más comunes
print("Palabras más comunes en descripciones en inglés:")
for word, freq in common_words:
    print(f"{word}: {freq}")

# Extraer palabras y frecuencias para el gráfico
words, frequencies = zip(*common_words)



# Crear gráfico interactivo de barras con Plotly
fig = go.Figure(data=[go.Bar(x=words, y=frequencies, marker_color='skyblue')])

fig.update_layout(
    title='10 Palabras más comunes en las descripciones en inglés',
    xaxis=dict(title='Palabras clave'),
    yaxis=dict(title='Frecuencia'),
    hovermode='x',  # Mostrar leyenda al pasar el puntero por la barra
    barmode='group',
    bargap=0.15,
    bargroupgap=0.1
)

fig.show()


conn = mysql.connector.connect(**db_config)
cursor = conn.cursor()

# Consultas para cada tipo de score
queries = {
    'Exploitability Score': """
        SELECT
            cve_data.id AS cve_id,
            cvss_v31.exploitabilityScore AS exploitability_v31,
            cvss_v2.exploitabilityScore AS exploitability_v2
        FROM
            cve_data
        JOIN
            cvss_metrics_v31 AS cvss_v31 ON cve_data.id = cvss_v31.cve_id
        JOIN
            cvss_metrics_v2 AS cvss_v2 ON cve_data.id = cvss_v2.cve_id;
    """,
    'Impact Score': """
        SELECT
            cve_data.id AS cve_id,
            cvss_v31.impactScore AS impact_v31,
            cvss_v2.impactScore AS impact_v2
        FROM
            cve_data
        JOIN
            cvss_metrics_v31 AS cvss_v31 ON cve_data.id = cvss_v31.cve_id
        JOIN
            cvss_metrics_v2 AS cvss_v2 ON cve_data.id = cvss_v2.cve_id;
    """,
    'Base Score': """
        SELECT
            cve_data.id AS cve_id,
            cvss_v31.baseScore AS base_score_v31,
            cvss_v2.baseScore AS base_score_v2
        FROM
            cve_data
        JOIN
            cvss_metrics_v31 AS cvss_v31 ON cve_data.id = cvss_v31.cve_id
        JOIN
            cvss_metrics_v2 AS cvss_v2 ON cve_data.id = cvss_v2.cve_id;
    """,
    'Base Severity': """
        SELECT
            cve_data.id AS cve_id,
            cvss_v31.baseSeverity AS base_severity_v31,
            cvss_v2.baseSeverity AS base_severity_v2
        FROM
            cve_data
        JOIN
            cvss_metrics_v31 AS cvss_v31 ON cve_data.id = cvss_v31.cve_id
        JOIN
            cvss_metrics_v2 AS cvss_v2 ON cve_data.id = cvss_v2.cve_id;
    """
}

# Función para ejecutar consulta y analizar diferencias
def analyze_scores(query, title, severity_map_v2=None, severity_map_v31=None):
    cursor = conn.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    columns = [col.split(' AS ')[1].strip() for col in query.split('SELECT')[1].split('FROM')[0].split(',')]

    df = pd.DataFrame(results, columns=columns)
    cursor.close()
    
    if title == 'Base Severity':
        # Verificar si las columnas existen en el DataFrame
        if 'base_severity_v2' in df.columns and 'base_severity_v31' in df.columns:
            # Mapear severidades a puntuaciones numéricas
            severity_map_v2 = {
                'NONE': 0.0,
                'LOW': 0.0,
                'MEDIUM': 4.0,
                'HIGH': 7.0
            }

            severity_map_v31 = {
                'NONE': 0.0,
                'LOW': 0.1,
                'MEDIUM': 4.0,
                'HIGH': 7.0,
                'CRITICAL': 9.0
            }
            df['base_severity_v2'] = df['base_severity_v2'].map(severity_map_v2)
            df['base_severity_v31'] = df['base_severity_v31'].map(severity_map_v31)
            df['difference'] = df['base_severity_v31'] - df['base_severity_v2']
        else:
            print(f"Las columnas 'base_severity_v2' o 'base_severity_v31' no están en el DataFrame para {title}.")
            return
    else:
        # Convertir columnas a float y manejar errores
        df[columns[1]] = pd.to_numeric(df[columns[1]], errors='coerce')
        df[columns[2]] = pd.to_numeric(df[columns[2]], errors='coerce')
        # Calcular diferencias
        df['difference'] = df[columns[2]] - df[columns[1]]
    
    # Imprimir el resumen estadístico de las diferencias
    print(f"Resumen estadístico de {title} (v3.1 vs v2.0):")
    print(df['difference'].describe())
    print("\n")
    
    # Visualizar la distribución de las diferencias
    plt.figure(figsize=(10, 6))
    sns.histplot(df['difference'], kde=True)
    plt.title(f"Distribución de las diferencias entre {title} (v3.1 vs v2.0)")
    plt.xlabel(f"Diferencia de {title} (v3.1 - v2.0)")
    plt.ylabel("Frecuencia")
    plt.show()

# Ejecutar análisis para todos los scores
for title, query in queries.items():
    analyze_scores(query, title)

# Cerrar la conexión
conn.close()

conn = mysql.connector.connect(**db_config)
cursor = conn.cursor()

# Define la consulta SQL
query = """
SELECT cve_id, vectorString, baseScore, impactScore, exploitabilityScore
FROM cvss_metrics_v31

LIMIT 3
"""

# Ejecutar la consulta
cursor.execute(query)

# Recuperar los resultados
results = cursor.fetchall()

# Cerrar la conexión
cursor.close()
conn.close()


import math

# Define the weights as constants
WEIGHTS = {
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
    'AC': {'H': 0.44, 'L': 0.77},
    'PR': {'U': {'N': 0.85, 'L': 0.62, 'H': 0.27}, 'C': {'N': 0.85, 'L': 0.68, 'H': 0.5}},
    'UI': {'N': 0.85, 'R': 0.62},
    'S': {'U': 6.42, 'C': 7.52},
    'CIA': {'N': 0, 'L': 0.22, 'H': 0.56},
    'E': {'X': 1, 'U': 0.91, 'P': 0.94, 'F': 0.97, 'H': 1},
    'RL': {'X': 1, 'O': 0.95, 'T': 0.96, 'W': 0.97, 'U': 1},
    'RC': {'X': 1, 'U': 0.92, 'R': 0.96, 'C': 1},
    'CIAR': {'X': 1, 'L': 0.5, 'M': 1, 'H': 1.5}
}

def parse_vector_string(vector_string):
    """Parse the CVSS vector string into a dictionary of metrics."""
    metrics = {}
    for part in vector_string.split('/'):
        key, value = part.split(':')
        metrics[key] = value
    return metrics

def round_up1(value):
    """Round up to the nearest 0.1"""
    return math.ceil(value * 10) / 10.0

def calculate_cvss_v3_1(vector_string):
    """
    Calculate the CVSS Base Score, Exploitability, and Impact Score based on the given vector string.

    Parameters:
    - vector_string (str): The CVSS vector string.

    Returns:
    - tuple: (Base Score, Exploitability, Impact Score)
    """
    # Parse the vector string
    metrics = parse_vector_string(vector_string)
    
    # Extract the metric weights
    metricWeightAV = WEIGHTS['AV'][metrics['AV']]
    metricWeightAC = WEIGHTS['AC'][metrics['AC']]
    metricWeightPR = WEIGHTS['PR'][metrics['S']][metrics['PR']]
    metricWeightUI = WEIGHTS['UI'][metrics['UI']]
    metricWeightC = WEIGHTS['CIA'][metrics['C']]
    metricWeightI = WEIGHTS['CIA'][metrics['I']]
    metricWeightA = WEIGHTS['CIA'][metrics['A']]
    metricWeightS = WEIGHTS['S'][metrics['S']]
    
    # Calculate Impact Sub-Score (ISS)
    iss = 1 - ((1 - metricWeightC) * (1 - metricWeightI) * (1 - metricWeightA))
    
    # Calculate Impact Score
    if metrics['S'] == 'U':
        impact_score = metricWeightS * iss
    else:
        impact_score = metricWeightS * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)
    
    # Calculate Exploitability
    exploitability = 8.22 * metricWeightAV * metricWeightAC * metricWeightPR * metricWeightUI
    
    # Calculate Base Score
    if impact_score <= 0:
        base_score = 0
    else:
        if metrics['S'] == 'U':
            base_score = round_up1(min((exploitability + impact_score), 10))
        else:
            base_score = round_up1(min(WEIGHTS['CIAR']['H'] * (exploitability + impact_score), 10))
    
    return base_score, exploitability, impact_score



# Process and print the results
for row in results:
    cve_id, vector_string, base_score, impact_score,exploitability_score = row
    # Calculate the values using the vectorString
    calculated_base_score, calculated_exploitability, calculated_impact_score = calculate_cvss_v3_1(vector_string)
    
    # Print results
    print(f"CVE ID: {cve_id}")
    print(f"Vector String: {vector_string}")
    print(f"Base Score (calculated): {calculated_base_score}")
    print(f"Exploitability (calculated): {calculated_exploitability}")
    print(f"Impact Score (calculated): {calculated_impact_score}")
    print(f"Base Score (from database): {base_score}")
    print(f"Exploitability (from database): {exploitability_score}")
    print(f"Impact Score (from database): {impact_score}")

    print()

# Close the connection
cursor.close()
conn.close()

import plotly.graph_objects as go

# Conectar a la base de datos y recuperar los datos
conn = mysql.connector.connect(**db_config)
cursor = conn.cursor()

query = """SELECT cwe.id,
                  cwe.cve_id,
                  cwe.cwe_id
            FROM cwe"""

cursor.execute(query)
results = cursor.fetchall()
df = pd.DataFrame(results, columns=['id', 'cve_id', 'cwe_id'])

# Extraer el año del CVE ID
df['year'] = df['cve_id'].str.extract(r'CVE-(\d{4})').astype(int)

# Contar la cantidad de vulnerabilidades por año y cwe_id
count_df = df.groupby(['year', 'cwe_id']).size().reset_index(name='count')

# Crear la gráfica interactiva con Plotly
fig = go.Figure()

for cwe_id in count_df['cwe_id'].unique():
    subset = count_df[count_df['cwe_id'] == cwe_id]
    fig.add_trace(go.Scatter(
        x=subset['year'],
        y=subset['count'],
        mode='lines+markers',
        name=cwe_id,
        line=dict(smoothing=0.3)  # Suaviza la línea
    ))

# Configurar el diseño de la gráfica
fig.update_layout(
    title='Número de Vulnerabilidades por CWE ID a lo Largo del Tiempo',
    xaxis_title='Año',
    yaxis_title='Cantidad de Vulnerabilidades',
    legend_title='CWE ID',
    template='plotly_white'
)

# Mostrar la gráfica
fig.show()

# Cerrar la conexión
cursor.close()
conn.close()
conn = mysql.connector.connect(**db_config)
cursor = conn.cursor()

# Ejecutar la consulta para obtener la relación CWE-CVE
cursor.execute("SELECT cve_id, cwe_id FROM cwe")
cwe_data = cursor.fetchall()
df_cwe = pd.DataFrame(cwe_data, columns=['cve_id', 'cwe_id'])

# Ejecutar la consulta para obtener las métricas de CVSS v3.1
cursor.execute("SELECT cve_id, baseScore, exploitabilityScore, impactScore FROM cvss_metrics_v31")
cvss_metrics_v31_data = cursor.fetchall()
df_v31 = pd.DataFrame(cvss_metrics_v31_data, columns=['cve_id', 'baseScore', 'exploitabilityScore', 'impactScore'])

# Ejecutar la consulta para obtener las métricas de CVSS v2
cursor.execute("SELECT cve_id, baseScore, exploitabilityScore, impactScore FROM cvss_metrics_v2")
cvss_metrics_v2_data = cursor.fetchall()
df_v2 = pd.DataFrame(cvss_metrics_v2_data, columns=['cve_id', 'baseScore', 'exploitabilityScore', 'impactScore'])

# Cerrar la conexión a la base de datos
cursor.close()
conn.close()

# Relación CWE-CVE
df_cwe_cve_relation = df_cwe.groupby('cwe_id').size().reset_index(name='count')

# Top de CWE más repetidos
top_cwe = df_cwe_cve_relation.sort_values(by='count', ascending=False)

# Métricas combinadas CVSS v3.1 y v2
df_combined = df_v31.merge(df_v2, on='cve_id', suffixes=('_v31', '_v2'))

# Relacionar métricas CVE con CWE
df_full = df_cwe.merge(df_combined, on='cve_id')

# Agrupar por CWE y calcular las métricas promedio
cwe_metrics = df_full.groupby('cwe_id').agg({
    'baseScore_v31': 'mean',
    'exploitabilityScore_v31': 'mean',
    'impactScore_v31': 'mean',
    'baseScore_v2': 'mean',
    'exploitabilityScore_v2': 'mean',
    'impactScore_v2': 'mean'
}).reset_index()

# Mostrar resultados: Top CWE y métricas calculadas
print("Top CWE más comunes:")
print(top_cwe)
# Top de CWE por cada métrica
top_baseScore_v31 = cwe_metrics[['cwe_id', 'baseScore_v31']].sort_values(by='baseScore_v31', ascending=False).head(10)
top_exploitabilityScore_v31 = cwe_metrics[['cwe_id', 'exploitabilityScore_v31']].sort_values(by='exploitabilityScore_v31', ascending=False).head(10)
top_impactScore_v31 = cwe_metrics[['cwe_id', 'impactScore_v31']].sort_values(by='impactScore_v31', ascending=False).head(10)

top_baseScore_v2 = cwe_metrics[['cwe_id', 'baseScore_v2']].sort_values(by='baseScore_v2', ascending=False).head(10)
top_exploitabilityScore_v2 = cwe_metrics[['cwe_id', 'exploitabilityScore_v2']].sort_values(by='exploitabilityScore_v2', ascending=False).head(10)
top_impactScore_v2 = cwe_metrics[['cwe_id', 'impactScore_v2']].sort_values(by='impactScore_v2', ascending=False).head(10)

# Mostrar los resultados
print("Top CWE por baseScore v3.1:")
print(top_baseScore_v31)
print("\nTop CWE por exploitabilityScore v3.1:")
print(top_exploitabilityScore_v31)
print("\nTop CWE por impactScore v3.1:")
print(top_impactScore_v31)

print("\nTop CWE por baseScore v2:")
print(top_baseScore_v2)
print("\nTop CWE por exploitabilityScore v2:")
print(top_exploitabilityScore_v2)
print("\nTop CWE por impactScore v2:")
print(top_impactScore_v2)
import plotly.express as px
import plotly.subplots as sp

# Crear subplots
fig = sp.make_subplots(rows=3, cols=2, subplot_titles=[
    "Top 10 CWE por baseScore (v3.1)", 
    "Top 10 CWE por baseScore (v2.0)", 
    "Top 10 CWE por exploitabilityScore (v3.1)", 
    "Top 10 CWE por exploitabilityScore (v2.0)", 
    "Top 10 CWE por impactScore (v3.1)", 
    "Top 10 CWE por impactScore (v2.0)"
])

# Gráfico de barras para baseScore v3.1
fig_baseScore_v31 = px.bar(top_baseScore_v31.head(10), 
                           x='cwe_id', y='baseScore_v31', 
                           labels={'baseScore_v31': 'Base Score (v3.1)', 'cwe_id': 'CWE ID'},
                           color='baseScore_v31')

# Gráfico de barras para baseScore v2.0
fig_baseScore_v2 = px.bar(top_baseScore_v2.head(10), 
                          x='cwe_id', y='baseScore_v2', 
                          labels={'baseScore_v2': 'Base Score (v2.0)', 'cwe_id': 'CWE ID'},
                          color='baseScore_v2')

# Gráfico de barras para exploitabilityScore v3.1
fig_exploitability_v31 = px.bar(top_exploitabilityScore_v31.head(10), 
                                x='cwe_id', y='exploitabilityScore_v31', 
                                labels={'exploitabilityScore_v31': 'Exploitability (v3.1)', 'cwe_id': 'CWE ID'},
                                color='exploitabilityScore_v31')

# Gráfico de barras para exploitabilityScore v2.0
fig_exploitability_v2 = px.bar(top_exploitabilityScore_v2.head(10), 
                               x='cwe_id', y='exploitabilityScore_v2', 
                               labels={'exploitabilityScore_v2': 'Exploitability (v2.0)', 'cwe_id': 'CWE ID'},
                               color='exploitabilityScore_v2')

# Gráfico de barras para impactScore v3.1
fig_impact_v31 = px.bar(top_impactScore_v31.head(10), 
                        x='cwe_id', y='impactScore_v31', 
                        labels={'impactScore_v31': 'Impact Score (v3.1)', 'cwe_id': 'CWE ID'},
                        color='impactScore_v31')

# Gráfico de barras para impactScore v2.0
fig_impact_v2 = px.bar(top_impactScore_v2.head(10), 
                       x='cwe_id', y='impactScore_v2', 
                       labels={'impactScore_v2': 'Impact Score (v2.0)', 'cwe_id': 'CWE ID'},
                       color='impactScore_v2')

# Añadir gráficos a los subplots
fig.add_traces(fig_baseScore_v31['data'], rows=1, cols=1)
fig.add_traces(fig_baseScore_v2['data'], rows=1, cols=2)
fig.add_traces(fig_exploitability_v31['data'], rows=2, cols=1)
fig.add_traces(fig_exploitability_v2['data'], rows=2, cols=2)
fig.add_traces(fig_impact_v31['data'], rows=3, cols=1)
fig.add_traces(fig_impact_v2['data'], rows=3, cols=2)

# Ajustes finales
fig.update_layout(height=1000, width=1200, title_text="Subplots de Métricas CVSS v3.1 y v2.0 por CWE")
fig.update_xaxes(categoryorder='total descending')

fig.show()
import plotly.figure_factory as ff

# Crear una tabla de correlación
corr = df_full[['baseScore_v31', 'exploitabilityScore_v31', 'impactScore_v31', 'baseScore_v2', 'exploitabilityScore_v2', 'impactScore_v2']].corr()

# Crear el heatmap
fig = ff.create_annotated_heatmap(
    z=corr.values, 
    x=list(corr.columns), 
    y=list(corr.columns), 
    annotation_text=corr.round(2).values,
    colorscale='Viridis'
)

fig.update_layout(title_text='Correlación entre Métricas CVSS v3.1 y v2', height=500)
fig.show()
# Scatterplot interactivo para v3.1
fig = px.scatter(df_full, 
                 x='exploitabilityScore_v31', y='impactScore_v31', 
                 color='cwe_id', 
                 title='Exploitability Score vs Impact Score (v3.1)',
                 labels={'exploitabilityScore_v31': 'Exploitability Score (v3.1)', 'impactScore_v31': 'Impact Score (v3.1)'},
                 height=600)

fig.update_traces(marker=dict(size=12))
fig.show()
