import requests
import hashlib
import base64

def encode_pw(username, password):
    initial_hash = hashlib.sha256((password + username.lower()).encode('utf-8')).digest()
    hash_in_base64 = base64.b64encode(initial_hash).decode('utf-8')
    return hash_in_base64

# Función para obtener el iRating y el nombre de usuario de iRacing
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
    response = session.post(login_url, json=payload, headers=headers)
    response.raise_for_status()
    
    # Verifica si se redirige a una URL específica para obtener un token o cookies de sesión
    if response.status_code == 200 and 'Set-Cookie' in response.headers:
        cookies = session.cookies.get_dict()
    else:
        raise Exception("Authentication failed or cookies not set.")
    
    # Obtener datos del usuario
    user_url = 'https://members-ng.iracing.com/data/driver/get'
    response = session.get(user_url, headers=headers, cookies=cookies)
    response.raise_for_status()
    user_data = response.json()

    nombre = user_data['name']
    irating = user_data['irating']

    return nombre, irating

# Ejemplo de uso
if __name__ == "__main__":
    email = 'xxxxxxxxxx'
    password = 'xxxxxxxxxxxxxx'
    nombre, irating = obtener_datos_iracing(email, password)
    print(f'Nombre: {nombre}, iRating: {irating}')
