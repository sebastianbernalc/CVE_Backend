from Tools.Functions import *
from Tools.CreateDB import *

if __name__ == "__main__":

    config_file_path = './Config/Parameters.json'
    config = load_config(config_file_path)
    db_config = config['database']

    # Primero, crear la base de datos si no existe
    create_database_if_not_exists(db_config)

    # Ahora, actualizar db_config para incluir la base de datos
    db_config['database'] = 'vulnerabilities_db'

    query = read_sql_file('./Sql/CreateDB.sql')

    # Llamar a la función para crear las tablas
    create_tables(query, db_config)

    cve_ids,vendors = read_cve_ids_from_csv('./Documents/known_exploited_vulnerabilities (2).csv')
    
    for cve_id, vendor in zip(cve_ids, vendors):
        # Obtener datos del CVE desde la API
        cve_data = fetch_cve_data(cve_id, config['api'])
        if cve_data:
            # Insertar los datos en la base de datos
            insert_cve_data(cve_data, db_config, vendor)