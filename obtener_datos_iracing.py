import requests
import hashlib
import base64
import json
# Importar credenciales
from credenciales import email, password


def encode_pw(username, password):
    initial_hash = hashlib.sha256((password + username.lower()).encode('utf-8')).digest()
    hash_in_base64 = base64.b64encode(initial_hash).decode('utf-8')
    return hash_in_base64

def guardar_json_local(data, filename='datos_iracing.json'):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file)
        print(f"Archivo guardado correctamente en {filename}")
    except Exception as e:
        print(f"Error al guardar el archivo: {e}")

def leer_json_local(filename='datos_iracing.json'):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print(f"El archivo {filename} no se encontró.")
        return None
    except json.JSONDecodeError:
        print(f"Error al decodificar el JSON en {filename}.")
        return None

def obtener_datos_iracing(email, password):
    hashed_password = encode_pw(email, password)
    session = requests.Session()
    
    # Autenticación
    login_url = 'https://members-ng.iracing.com/auth'
    payload = {
        'email': email,
        'password': hashed_password
    }
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        response = session.post(login_url, json=payload, headers=headers)
        response.raise_for_status()
        
        # Verifica si se redirige a una URL específica para obtener un token o cookies de sesión
        if response.status_code == 200 and 'Set-Cookie' in response.headers:
            cookies = session.cookies.get_dict()
        else:
            raise Exception("Authentication failed or cookies not set.")
        
        # Obtener datos del usuario
        user_url = 'https://members-ng.iracing.com/data/member/info'
        link_response = session.get(user_url, headers=headers, cookies=cookies)
        link_response.raise_for_status()
        link_result = link_response.json()

        # Asegurarse de que 'link' exista en link_result
        if 'link' not in link_result:
            raise ValueError("La respuesta JSON no contiene la clave 'link'")
        
        # Realizar una solicitud a la URL del link
        data_url = link_result['link']
        
        response = session.get(data_url, headers=headers, cookies=cookies)
        response.raise_for_status()

        result = response.json()

        # Guardar el JSON en un archivo local
        guardar_json_local(result)

        # Asegurarse de que 'name' e 'irating' existan en result
        if 'name' not in result or 'irating' not in result:
            raise ValueError("La respuesta JSON no contiene las claves 'name' e 'irating' necesarias")

        nombre = result['name']
        irating = result['irating']

        return nombre, irating
    
    except requests.exceptions.RequestException as e:
        print(f"Error de solicitud: {e}")
        return None, None
    except ValueError as ve:
        print(f"Error en los datos: {ve}")
        return None, None
    except Exception as ex:
        print(f"Error general: {ex}")
        return None, None

def procesar_datos_locales(filename='datos_iracing.json'):
    try:
        data = leer_json_local(filename)
        if not data:
            return None, None
        nombre = data.get('name')
        irating = data.get('irating')

        if not nombre or not irating:
            raise ValueError("Los datos locales no contienen las claves 'name' o 'irating' necesarias")

        return nombre, irating
    except ValueError as ve:
        print(f"Error en los datos locales: {ve}")
        return None, None
    except Exception as ex:
        print(f"Error general al procesar los datos locales: {ex}")
        return None, None

# Ejemplo de uso
if __name__ == "__main__":
   # Importar credenciales
    from credenciales import email, password

    
    # Obtener y guardar los datos de iRacing en un archivo local
    nombre, irating = obtener_datos_iracing(email, password)
    if nombre and irating:
        print(f'Datos obtenidos y guardados localmente: Nombre: {nombre}, iRating: {irating}')
    else:
        print('No se pudieron obtener los datos de iRacing')

    # Procesar los datos guardados localmente
    nombre_local, irating_local = procesar_datos_locales()
    if nombre_local and irating_local:
        print(f'Datos procesados desde el archivo local: Nombre: {nombre_local}, iRating: {irating_local}')
    else:
        print('No se pudieron procesar los datos locales')
