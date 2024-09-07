import json
import mysql.connector
import pandas as pd
import requests
import csv

from textblob import TextBlob
# Función para leer un archivo SQL
def read_sql_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()
    
# Lee la configuración desde el archivo JSON
def load_config(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Función para leer CVE IDs desde un archivo CSV
def read_cve_ids_from_csv(file_path):
    """Lee los IDs de CVE desde un archivo CSV y devuelve una lista de IDs."""
    try:
        df = pd.read_csv(file_path)
        # Verificar si la columna 'CVE_ID' existe en el DataFrame
        if 'cveID' not in df.columns:
            raise ValueError("La columna 'CVE_ID' no se encuentra en el archivo CSV.")
        if 'vendorProject' not in df.columns:
            raise ValueError("La columna 'Vendor' no se encuentra en el archivo CSV.")
        return df['cveID'].tolist(), df['vendorProject'].tolist()
    except FileNotFoundError:
        print(f"Error: El archivo '{file_path}' no se encontró.")
    except pd.errors.EmptyDataError:
        print(f"Error: El archivo '{file_path}' está vacío.")
    except pd.errors.ParserError:
        print(f"Error: El archivo '{file_path}' tiene un formato incorrecto.")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")

    # Retorna una lista vacía en caso de error
    return []

# Función para obtener datos de la API
def fetch_cve_data(cve_id, api_config):
    """Obtiene datos del CVE usando el API."""
    try:
        url = f"{api_config['url']}{api_config['endpoint']}{cve_id}"
        response = requests.get(url)
        response.raise_for_status()  # Lanza un error si la solicitud falla
        return response.json()  # Retorna la respuesta en formato JSON
    except requests.RequestException as e:
        print(f"Error al obtener datos del CVE: {e}")
        return None

# Función para guardar los datos en la base de datos
def insert_cve_data(cve_data, db_config, vendor):
    """Inserta datos del CVE en la base de datos."""
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Asegurarse de que hay datos en 'vulnerabilities'
        if not cve_data.get('vulnerabilities'):
            raise ValueError("No vulnerabilities data found")

        # Acceder a la primera vulnerabilidad en la lista
        cve = cve_data['vulnerabilities'][0]['cve']
        cve_id = cve.get('id', '')
        source_identifier = cve.get('sourceIdentifier', '')
        published = cve.get('published', '')
        last_modified = cve.get('lastModified', '')
        vuln_status = cve.get('vulnStatus', '')
        description_en = ''
        description_es = ''
        vendor = vendor

        for desc in cve.get('descriptions', []):
            if desc['lang'] == 'en':
                description_en = desc['value']
            elif desc['lang'] == 'es':
                description_es = desc['value']

        # Insertar datos en la tabla cve_data
        insert_cve_query = """
        INSERT INTO cve_data (id, sourceIdentifier, published, lastModified, vulnStatus, description_en, description_es, vendor)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE sourceIdentifier=%s, published=%s, lastModified=%s, vulnStatus=%s, description_en=%s, description_es=%s, vendor=%s
        """
        cursor.execute(insert_cve_query, (cve_id, source_identifier, published, last_modified, vuln_status, description_en, description_es, vendor,
                                           source_identifier, published, last_modified, vuln_status, description_en, description_es, vendor))

        # Insertar datos en cvss_metrics_v31
        for metric in cve.get('metrics', {}).get('cvssMetricV31', []):
            cvss_data = metric.get('cvssData', {})
            insert_cvss_v31_query = """
            INSERT INTO cvss_metrics_v31 (cve_id, version, vectorString, attackVector, attackComplexity, privilegesRequired, userInteraction,
                                          scope, confidentialityImpact, integrityImpact, availabilityImpact, baseScore, baseSeverity,
                                          exploitabilityScore, impactScore)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_cvss_v31_query, (cve_id, cvss_data.get('version', ''), cvss_data.get('vectorString', ''),
                                                   cvss_data.get('attackVector', ''), cvss_data.get('attackComplexity', ''),
                                                   cvss_data.get('privilegesRequired', ''), cvss_data.get('userInteraction', ''),
                                                   cvss_data.get('scope', ''), cvss_data.get('confidentialityImpact', ''),
                                                   cvss_data.get('integrityImpact', ''), cvss_data.get('availabilityImpact', ''),
                                                   cvss_data.get('baseScore', 0), cvss_data.get('baseSeverity', ''),
                                                   metric.get('exploitabilityScore', 0), metric.get('impactScore', 0)))

        # Insertar datos en cvss_metrics_v2
        for metric in cve.get('metrics', {}).get('cvssMetricV2', []):
            cvss_data = metric.get('cvssData', {})
            insert_cvss_v2_query = """
            INSERT INTO cvss_metrics_v2 (cve_id, version, vectorString, accessVector, accessComplexity, authentication, confidentialityImpact,
                                         integrityImpact, availabilityImpact, baseScore, baseSeverity, exploitabilityScore, impactScore)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_cvss_v2_query, (cve_id, cvss_data.get('version', ''), cvss_data.get('vectorString', ''),
                                                  cvss_data.get('accessVector', ''), cvss_data.get('accessComplexity', ''),
                                                  cvss_data.get('authentication', ''), cvss_data.get('confidentialityImpact', ''),
                                                  cvss_data.get('integrityImpact', ''), cvss_data.get('availabilityImpact', ''),
                                                  cvss_data.get('baseScore', 0), metric.get('baseSeverity', 0),
                                                  metric.get('exploitabilityScore', 0), metric.get('impactScore', 0)))

        # Insertar datos en cwe
        for weakness in cve.get('weaknesses', []):
            for desc in weakness.get('description', []):
                cwe_id = desc.get('value', '')
                if cwe_id:
                    insert_cwe_query = """
                    INSERT INTO cwe (cve_id, cwe_id)
                    VALUES (%s, %s)
                    """
                    cursor.execute(insert_cwe_query, (cve_id, cwe_id))

        # Insertar datos en references
        for reference in cve.get('references', []):
            url = reference.get('url', '')
            source = reference.get('source', '')
            tags = ', '.join(reference.get('tags', []))  # Convertir lista de tags a string
            insert_ref_query = """
            INSERT INTO referencess (cve_id, url, source, tags)
            VALUES (%s, %s, %s, %s)
            """
            cursor.execute(insert_ref_query, (cve_id, url, source, tags))

        conn.commit()
    except mysql.connector.Error as e:
        print(f"Error al insertar datos en la base de datos: {e}")
    except ValueError as e:
        print(f"Error en los datos del CVE: {e}")
    finally:
        cursor.close()
        conn.close()


def analyze_sentiment(text):
    if text:  # Evitar textos vacíos o nulos
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