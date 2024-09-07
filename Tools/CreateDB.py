import mysql.connector
from mysql.connector import Error
from Tools.Functions import load_config, read_sql_file

def create_database_if_not_exists(db_config):
    """Crea la base de datos si no existe."""
    try:
        # Conectar a MySQL sin especificar una base de datos
        conn = mysql.connector.connect(
            user=db_config['user'],
            password=db_config['password'],
            host=db_config['host']
        )
        cursor = conn.cursor()
        
        # Crear base de datos si no existe
        cursor.execute("CREATE DATABASE IF NOT EXISTS vulnerabilities_db")
        conn.commit()
        cursor.execute("USE vulnerabilities_db")

        print("Base de datos creada o ya existe.")
    except Error as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        conn.close()

def create_tables(query, db_config):
    """Crea las tablas en la base de datos especificada."""
    try:
        # Conectar a MySQL con la base de datos ya creada
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Ejecutar el script para crear tablas
        for statement in query.split(';'):
            if statement.strip():  # Ejecutar solo declaraciones no vacías
                cursor.execute(statement)
        conn.commit()

        print("Tablas creadas exitosamente.")
    except Error as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        conn.close()

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
