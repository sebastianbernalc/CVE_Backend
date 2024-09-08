from flask import Flask, jsonify, request
import mysql.connector
import pandas as pd
import json
from nltk.corpus import stopwords
import re
from collections import Counter
import plotly.graph_objects as go
import plotly.express as px
import math
from textblob import TextBlob
import plotly.subplots as sp

import plotly.figure_factory as ff

app = Flask(__name__)

# Cargar configuración de la base de datos
def load_config(filename):
    with open(filename, 'r') as file:
        return json.load(file)

db_config = load_config('./Config/Parameters.json')['database']

def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except mysql.connector.Error as err:
        app.logger.error(f"Error de conexión a la base de datos: {err}")
        raise


# Función de análisis de sentimientos (placeholder)
def analyze_sentiment(text):
    if text and text.strip():  # Evitar textos vacíos o nulos
        blob = TextBlob(text)
        return blob.sentiment.polarity
    return None


def classify_sentiment(polarity):
    if polarity > 0.1:
        return 'Positiva'
    elif polarity < -0.1:
        return 'Negativa'
    else:
        return 'Neutra'

@app.route('/api/sentiment', methods=['GET'])
def get_sentiment_summary():
    conn = get_db_connection()
    query = "SELECT id, description_en FROM cve_data"
    data = pd.read_sql(query, conn)
    conn.close()

    data['sentiment_en'] = data['description_en'].apply(analyze_sentiment)
    sentiment_summary = data['sentiment_en'].describe().to_dict()
    data['sentiment_class'] = data['sentiment_en'].apply(classify_sentiment)
    sentiment_data = data[['id', 'sentiment_en', 'sentiment_class']].to_dict(orient='records')

    return jsonify({
        'summary': sentiment_summary,
        'data': sentiment_data
    })


@app.route('/api/word-frequency', methods=['GET'])
def get_word_frequency():
    conn = get_db_connection()
    query = "SELECT description_en FROM cve_data"
    data = pd.read_sql(query, conn)
    conn.close()

    stop_words = set(stopwords.words('english'))
    def word_frequency(descriptions):
        words = []
        for desc in descriptions:
            if desc:
                filtered_words = [word for word in re.findall(r'\w+', desc.lower()) if word not in stop_words and not word.isdigit()]
                words.extend(filtered_words)
        return Counter(words)

    en_word_freq = word_frequency(data['description_en'])
    common_words = en_word_freq.most_common(50)
    words, frequencies = zip(*common_words)

    fig = go.Figure(data=[go.Bar(x=words, y=frequencies, marker_color='skyblue')])
    fig.update_layout(
        title='Palabras más comunes en las descripciones en inglés',
        xaxis=dict(title='Palabras clave'),
        yaxis=dict(title='Frecuencia')
    )
    fig_json = fig.to_json()

    return jsonify({
        'figure': fig_json
    })

@app.route('/api/score-differences', methods=['GET'])
def get_score_differences():
    conn = get_db_connection()
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

    results = {}
    for title, query in queries.items():
        df = pd.read_sql(query, conn)
        
        # Adjust column names based on the title
        if title == 'Base Severity':
            severity_map_v2 = {'NONE': 0.0, 'LOW': 0.0, 'MEDIUM': 4.0, 'HIGH': 7.0}
            severity_map_v31 = {'NONE': 0.0, 'LOW': 0.1, 'MEDIUM': 4.0, 'HIGH': 7.0, 'CRITICAL': 9.0}
            df['base_severity_v2'] = df['base_severity_v2'].map(severity_map_v2)
            df['base_severity_v31'] = df['base_severity_v31'].map(severity_map_v31)
            df['difference'] = df['base_severity_v31'] - df['base_severity_v2']
        else:
            # Use actual column names directly
            df['difference'] = pd.to_numeric(df.filter(like='v2').iloc[:, 0], errors='coerce') - pd.to_numeric(df.filter(like='v31').iloc[:, 0], errors='coerce')

        summary = df['difference'].describe().to_dict()

        # Usar Plotly para la visualización
        fig = go.Figure()
        fig.add_trace(go.Histogram(x=df['difference'], histnorm='probability', name='Distribución', marker_color='skyblue'))
        fig.update_layout(
            title=f"Distribución de las diferencias entre {title} (v3.1 vs v2.0)",
            xaxis_title=f"Diferencia de {title} (v3.1 - v2.0)",
            yaxis_title="Frecuencia",
            template='plotly_white'
        )

        fig_json = fig.to_json()
        results[title] = {
            'summary': summary,
            'plot': fig_json
        }

    conn.close()

    return jsonify(results)



@app.route('/api/cwe-vulnerabilities', methods=['GET'])
def get_cwe_vulnerabilities():
    conn = get_db_connection()
    query = """
    SELECT cwe.id, cwe.cve_id, cwe.cwe_id
    FROM cwe
    """
    df = pd.read_sql(query, conn)
    conn.close()

    df['year'] = df['cve_id'].str.extract(r'CVE-(\d{4})').astype(int)
    count_df = df.groupby(['year', 'cwe_id']).size().reset_index(name='count')

    fig = go.Figure()
    for cwe_id in count_df['cwe_id'].unique():
        subset = count_df[count_df['cwe_id'] == cwe_id]
        fig.add_trace(go.Scatter(
            x=subset['year'],
            y=subset['count'],
            mode='lines+markers',
            name=cwe_id,
            line=dict(smoothing=0.3)
        ))

    fig.update_layout(
        title='Número de Vulnerabilidades por CWE ID a lo Largo del Tiempo',
        xaxis_title='Año',
        yaxis_title='Cantidad de Vulnerabilidades',
        legend_title='CWE ID',
        template='plotly_white'
    )
    fig_json = fig.to_json()

    return jsonify({
        'figure': fig_json
    })

@app.route('/api/cwe-cve-metrics_table', methods=['GET'])
def get_cwe_cve_metrics_table():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Consulta para obtener la relación CWE-CVE
    cursor.execute("SELECT cve_id, cwe_id FROM cwe")
    cwe_data = cursor.fetchall()
    df_cwe = pd.DataFrame(cwe_data, columns=['cve_id', 'cwe_id'])

    # Consulta para obtener las métricas de CVSS v3.1
    cursor.execute("SELECT cve_id, baseScore, exploitabilityScore, impactScore FROM cvss_metrics_v31")
    cvss_metrics_v31_data = cursor.fetchall()
    df_v31 = pd.DataFrame(cvss_metrics_v31_data, columns=['cve_id', 'baseScore', 'exploitabilityScore', 'impactScore'])

    # Consulta para obtener las métricas de CVSS v2
    cursor.execute("SELECT cve_id, baseScore, exploitabilityScore, impactScore FROM cvss_metrics_v2")
    cvss_metrics_v2_data = cursor.fetchall()
    df_v2 = pd.DataFrame(cvss_metrics_v2_data, columns=['cve_id', 'baseScore', 'exploitabilityScore', 'impactScore'])

    # Cerrar el cursor y la conexión
    cursor.close()
    conn.close()

    # Relación CWE-CVE
    df_cwe_cve_relation = df_cwe.groupby('cwe_id').size().reset_index(name='count')

    # Top de CWE más repetidos
    top_cwe = df_cwe_cve_relation.sort_values(by='count', ascending=False).head(10).to_dict(orient='records')

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

    # Top CWE por baseScore, exploitabilityScore e impactScore para CVSS v3.1 y v2
    top_baseScore_v31 = cwe_metrics[['cwe_id', 'baseScore_v31']].sort_values(by='baseScore_v31', ascending=False).head(10).to_dict(orient='records')
    top_exploitabilityScore_v31 = cwe_metrics[['cwe_id', 'exploitabilityScore_v31']].sort_values(by='exploitabilityScore_v31', ascending=False).head(10).to_dict(orient='records')
    top_impactScore_v31 = cwe_metrics[['cwe_id', 'impactScore_v31']].sort_values(by='impactScore_v31', ascending=False).head(10).to_dict(orient='records')

    top_baseScore_v2 = cwe_metrics[['cwe_id', 'baseScore_v2']].sort_values(by='baseScore_v2', ascending=False).head(10).to_dict(orient='records')
    top_exploitabilityScore_v2 = cwe_metrics[['cwe_id', 'exploitabilityScore_v2']].sort_values(by='exploitabilityScore_v2', ascending=False).head(10).to_dict(orient='records')
    top_impactScore_v2 = cwe_metrics[['cwe_id', 'impactScore_v2']].sort_values(by='impactScore_v2', ascending=False).head(10).to_dict(orient='records')

    return jsonify({
        'top_cwe': top_cwe,
        'top_baseScore_v31': top_baseScore_v31,
        'top_exploitabilityScore_v31': top_exploitabilityScore_v31,
        'top_impactScore_v31': top_impactScore_v31,
        'top_baseScore_v2': top_baseScore_v2,
        'top_exploitabilityScore_v2': top_exploitabilityScore_v2,
        'top_impactScore_v2': top_impactScore_v2
    })

@app.route('/api/cwe-cve-metrics_top_graph', methods=['GET'])
def get_cwe_cve_metrics_top_graph():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Consulta para obtener la relación CWE-CVE
    cursor.execute("SELECT cve_id, cwe_id FROM cwe")
    cwe_data = cursor.fetchall()
    df_cwe = pd.DataFrame(cwe_data, columns=['cve_id', 'cwe_id'])

    # Consulta para obtener las métricas de CVSS v3.1
    cursor.execute("SELECT cve_id, baseScore, exploitabilityScore, impactScore FROM cvss_metrics_v31")
    cvss_metrics_v31_data = cursor.fetchall()
    df_v31 = pd.DataFrame(cvss_metrics_v31_data, columns=['cve_id', 'baseScore', 'exploitabilityScore', 'impactScore'])

    # Consulta para obtener las métricas de CVSS v2
    cursor.execute("SELECT cve_id, baseScore, exploitabilityScore, impactScore FROM cvss_metrics_v2")
    cvss_metrics_v2_data = cursor.fetchall()
    df_v2 = pd.DataFrame(cvss_metrics_v2_data, columns=['cve_id', 'baseScore', 'exploitabilityScore', 'impactScore'])

    # Cerrar el cursor y la conexión
    cursor.close()
    conn.close()

    # Relacionar CWE con CVE y métricas de CVSS v3.1 y v2
    df_combined = df_v31.merge(df_v2, on='cve_id', suffixes=('_v31', '_v2'))
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

    # Top CWE por baseScore, exploitabilityScore e impactScore para CVSS v3.1 y v2
    top_baseScore_v31 = cwe_metrics[['cwe_id', 'baseScore_v31']].sort_values(by='baseScore_v31', ascending=False).head(10)
    top_exploitabilityScore_v31 = cwe_metrics[['cwe_id', 'exploitabilityScore_v31']].sort_values(by='exploitabilityScore_v31', ascending=False).head(10)
    top_impactScore_v31 = cwe_metrics[['cwe_id', 'impactScore_v31']].sort_values(by='impactScore_v31', ascending=False).head(10)

    top_baseScore_v2 = cwe_metrics[['cwe_id', 'baseScore_v2']].sort_values(by='baseScore_v2', ascending=False).head(10)
    top_exploitabilityScore_v2 = cwe_metrics[['cwe_id', 'exploitabilityScore_v2']].sort_values(by='exploitabilityScore_v2', ascending=False).head(10)
    top_impactScore_v2 = cwe_metrics[['cwe_id', 'impactScore_v2']].sort_values(by='impactScore_v2', ascending=False).head(10)

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
    fig_baseScore_v31 = px.bar(top_baseScore_v31, x='cwe_id', y='baseScore_v31', title="Top 10 CWE por baseScore (v3.1)", labels={'baseScore_v31': 'Base Score (v3.1)'})
    for trace in fig_baseScore_v31.data:
        fig.add_trace(trace, row=1, col=1)

    # Gráfico de barras para baseScore v2.0
    fig_baseScore_v2 = px.bar(top_baseScore_v2, x='cwe_id', y='baseScore_v2', title="Top 10 CWE por baseScore (v2.0)", labels={'baseScore_v2': 'Base Score (v2.0)'})
    for trace in fig_baseScore_v2.data:
        fig.add_trace(trace, row=1, col=2)

    # Gráfico de barras para exploitabilityScore v3.1
    fig_exploitabilityScore_v31 = px.bar(top_exploitabilityScore_v31, x='cwe_id', y='exploitabilityScore_v31', title="Top 10 CWE por exploitabilityScore (v3.1)", labels={'exploitabilityScore_v31': 'Exploitability Score (v3.1)'})
    for trace in fig_exploitabilityScore_v31.data:
        fig.add_trace(trace, row=2, col=1)

    # Gráfico de barras para exploitabilityScore v2.0
    fig_exploitabilityScore_v2 = px.bar(top_exploitabilityScore_v2, x='cwe_id', y='exploitabilityScore_v2', title="Top 10 CWE por exploitabilityScore (v2.0)", labels={'exploitabilityScore_v2': 'Exploitability Score (v2.0)'})
    for trace in fig_exploitabilityScore_v2.data:
        fig.add_trace(trace, row=2, col=2)

    # Gráfico de barras para impactScore v3.1
    fig_impactScore_v31 = px.bar(top_impactScore_v31, x='cwe_id', y='impactScore_v31', title="Top 10 CWE por impactScore (v3.1)", labels={'impactScore_v31': 'Impact Score (v3.1)'})
    for trace in fig_impactScore_v31.data:
        fig.add_trace(trace, row=3, col=1)

    # Gráfico de barras para impactScore v2.0
    fig_impactScore_v2 = px.bar(top_impactScore_v2, x='cwe_id', y='impactScore_v2', title="Top 10 CWE por impactScore (v2.0)", labels={'impactScore_v2': 'Impact Score (v2.0)'})
    for trace in fig_impactScore_v2.data:
        fig.add_trace(trace, row=3, col=2)

    fig.update_layout(height=1200, title_text="Top 10 CWE por Métricas de CVSS")

    fig_json = fig.to_json()
    return jsonify({'plot': fig_json})



@app.route('/api/cwe-cve-metrics_corre_graph', methods=['GET'])
def get_cwe_cve_metrics_corre_graph():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Consulta para obtener la relación CWE-CVE
    cursor.execute("SELECT cve_id, cwe_id FROM cwe")
    cwe_data = cursor.fetchall()
    df_cwe = pd.DataFrame(cwe_data, columns=['cve_id', 'cwe_id'])

    # Consulta para obtener las métricas de CVSS v3.1
    cursor.execute("SELECT cve_id, baseScore, exploitabilityScore, impactScore FROM cvss_metrics_v31")
    cvss_metrics_v31_data = cursor.fetchall()
    df_v31 = pd.DataFrame(cvss_metrics_v31_data, columns=['cve_id', 'baseScore', 'exploitabilityScore', 'impactScore'])

    # Consulta para obtener las métricas de CVSS v2
    cursor.execute("SELECT cve_id, baseScore, exploitabilityScore, impactScore FROM cvss_metrics_v2")
    cvss_metrics_v2_data = cursor.fetchall()
    df_v2 = pd.DataFrame(cvss_metrics_v2_data, columns=['cve_id', 'baseScore', 'exploitabilityScore', 'impactScore'])

    # Cerrar el cursor y la conexión
    cursor.close()
    conn.close()

    # Relacionar CWE con CVE y métricas de CVSS v3.1 y v2
    df_combined = df_v31.merge(df_v2, on='cve_id', suffixes=('_v31', '_v2'))
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

    # Top CWE por baseScore, exploitabilityScore e impactScore para CVSS v3.1 y v2
    top_baseScore_v31 = cwe_metrics[['cwe_id', 'baseScore_v31']].sort_values(by='baseScore_v31', ascending=False).head(10)
    top_exploitabilityScore_v31 = cwe_metrics[['cwe_id', 'exploitabilityScore_v31']].sort_values(by='exploitabilityScore_v31', ascending=False).head(10)
    top_impactScore_v31 = cwe_metrics[['cwe_id', 'impactScore_v31']].sort_values(by='impactScore_v31', ascending=False).head(10)

    top_baseScore_v2 = cwe_metrics[['cwe_id', 'baseScore_v2']].sort_values(by='baseScore_v2', ascending=False).head(10)
    top_exploitabilityScore_v2 = cwe_metrics[['cwe_id', 'exploitabilityScore_v2']].sort_values(by='exploitabilityScore_v2', ascending=False).head(10)
    top_impactScore_v2 = cwe_metrics[['cwe_id', 'impactScore_v2']].sort_values(by='impactScore_v2', ascending=False).head(10)

    # Crear subplots para las métricas CVSS
    fig = sp.make_subplots(rows=3, cols=2, subplot_titles=[
        "Top 10 CWE por baseScore (v3.1)", 
        "Top 10 CWE por baseScore (v2.0)", 
        "Top 10 CWE por exploitabilityScore (v3.1)", 
        "Top 10 CWE por exploitabilityScore (v2.0)", 
        "Top 10 CWE por impactScore (v3.1)", 
        "Top 10 CWE por impactScore (v2.0)"
    ])

    # Añadir los gráficos (como en el código anterior)

    # Generar la correlación entre las métricas de CVSS v3.1 y v2
    corr = df_full[['baseScore_v31', 'exploitabilityScore_v31', 'impactScore_v31', 
                    'baseScore_v2', 'exploitabilityScore_v2', 'impactScore_v2']].corr()

    # Crear el heatmap
    fig_corr = ff.create_annotated_heatmap(
        z=corr.values, 
        x=list(corr.columns), 
        y=list(corr.columns), 
        annotation_text=corr.round(2).values,
        colorscale='Viridis'
    )

    fig_corr.update_layout(title_text='Correlación entre Métricas CVSS v3.1 y v2', height=500)

    # Convertir las figuras a JSON
    fig_json = fig.to_json()
    fig_corr_json = fig_corr.to_json()

    return jsonify({
        'correlation_heatmap': fig_corr_json
    })

@app.route('/api/cwe-cve-metrics_Scatterplot', methods=['GET'])
def get_cwe_cve_metrics_Scatterplot():
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Consulta para obtener la relación CWE-CVE
    cursor.execute("SELECT cve_id, cwe_id FROM cwe")
    cwe_data = cursor.fetchall()
    df_cwe = pd.DataFrame(cwe_data, columns=['cve_id', 'cwe_id'])

    # Consulta para obtener las métricas de CVSS v3.1
    cursor.execute("SELECT cve_id, baseScore, exploitabilityScore, impactScore FROM cvss_metrics_v31")
    cvss_metrics_v31_data = cursor.fetchall()
    df_v31 = pd.DataFrame(cvss_metrics_v31_data, columns=['cve_id', 'baseScore', 'exploitabilityScore', 'impactScore'])

    # Consulta para obtener las métricas de CVSS v2
    cursor.execute("SELECT cve_id, baseScore, exploitabilityScore, impactScore FROM cvss_metrics_v2")
    cvss_metrics_v2_data = cursor.fetchall()
    df_v2 = pd.DataFrame(cvss_metrics_v2_data, columns=['cve_id', 'baseScore', 'exploitabilityScore', 'impactScore'])

    # Cerrar el cursor y la conexión
    cursor.close()
    conn.close()

    # Relacionar CWE con CVE y métricas de CVSS v3.1 y v2
    df_combined = df_v31.merge(df_v2, on='cve_id', suffixes=('_v31', '_v2'))
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

    # Top CWE por baseScore, exploitabilityScore e impactScore para CVSS v3.1 y v2
    top_baseScore_v31 = cwe_metrics[['cwe_id', 'baseScore_v31']].sort_values(by='baseScore_v31', ascending=False).head(10)
    top_exploitabilityScore_v31 = cwe_metrics[['cwe_id', 'exploitabilityScore_v31']].sort_values(by='exploitabilityScore_v31', ascending=False).head(10)
    top_impactScore_v31 = cwe_metrics[['cwe_id', 'impactScore_v31']].sort_values(by='impactScore_v31', ascending=False).head(10)

    top_baseScore_v2 = cwe_metrics[['cwe_id', 'baseScore_v2']].sort_values(by='baseScore_v2', ascending=False).head(10)
    top_exploitabilityScore_v2 = cwe_metrics[['cwe_id', 'exploitabilityScore_v2']].sort_values(by='exploitabilityScore_v2', ascending=False).head(10)
    top_impactScore_v2 = cwe_metrics[['cwe_id', 'impactScore_v2']].sort_values(by='impactScore_v2', ascending=False).head(10)

    # Crear subplots para las métricas CVSS
    fig = sp.make_subplots(rows=3, cols=2, subplot_titles=[
        "Top 10 CWE por baseScore (v3.1)", 
        "Top 10 CWE por baseScore (v2.0)", 
        "Top 10 CWE por exploitabilityScore (v3.1)", 
        "Top 10 CWE por exploitabilityScore (v2.0)", 
        "Top 10 CWE por impactScore (v3.1)", 
        "Top 10 CWE por impactScore (v2.0)"
    ])

    # Añadir los gráficos (como en el código anterior)

    # Generar la correlación entre las métricas de CVSS v3.1 y v2
    corr = df_full[['baseScore_v31', 'exploitabilityScore_v31', 'impactScore_v31', 
                    'baseScore_v2', 'exploitabilityScore_v2', 'impactScore_v2']].corr()

    # Crear el heatmap
    fig_corr = ff.create_annotated_heatmap(
        z=corr.values, 
        x=list(corr.columns), 
        y=list(corr.columns), 
        annotation_text=corr.round(2).values,
        colorscale='Viridis'
    )

    fig_corr.update_layout(title_text='Correlación entre Métricas CVSS v3.1 y v2', height=500)

    # Convertir las figuras a JSON
    fig_json = fig.to_json()
    fig_corr_json = fig_corr.to_json()


    fig = px.scatter(df_full, 
                 x='exploitabilityScore_v31', y='impactScore_v31', 
                 color='cwe_id', 
                 title='Exploitability Score vs Impact Score (v3.1)',
                 labels={'exploitabilityScore_v31': 'Exploitability Score (v3.1)', 'impactScore_v31': 'Impact Score (v3.1)'},
                 height=600)

    fig.update_traces(marker=dict(size=12))

    fig_json = fig.to_json()
    return jsonify({'plot': fig_json})

@app.route('/api/get_cve_info_detail', methods=['POST'])
def get_cve_info_detail():
    # Obtener el ID del cuerpo de la solicitud
    data = request.get_json()
    cve_id = data.get('id')

    if not cve_id:
        return jsonify({'error': 'ID no proporcionado'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Consultar la tabla cve_data
    cursor.execute('SELECT * FROM cve_data WHERE id = %s', (cve_id,))
    cve_data = cursor.fetchone()

    if not cve_data:
        return jsonify({'error': 'CVE no encontrado'}), 404

    # Consultar la tabla cvss_metrics_v31
    cursor.execute('SELECT * FROM cvss_metrics_v31 WHERE cve_id = %s', (cve_id,))
    cvss_metrics_v31 = cursor.fetchall()

    # Consultar la tabla cvss_metrics_v2
    cursor.execute('SELECT * FROM cvss_metrics_v2 WHERE cve_id = %s', (cve_id,))
    cvss_metrics_v2 = cursor.fetchall()

    # Consultar la tabla cwe
    cursor.execute('SELECT * FROM cwe WHERE cve_id = %s', (cve_id,))
    cwe_data = cursor.fetchall()

    # Cerrar la conexión
    cursor.close()
    conn.close()

    # Preparar la respuesta
    response = {
        'cve_data': cve_data,
        'cvss_metrics_v31': cvss_metrics_v31,
        'cvss_metrics_v2': cvss_metrics_v2,
        'cwe': cwe_data
    }

    return jsonify(response)


if __name__ == '__main__':
    app.run(debug=True)
