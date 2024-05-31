import http.server
import socketserver
import json
from obtener_datos_iracing import obtener_datos_iracing

PORT = 8000

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/datos.json':
            try:
                # Llama a la función para obtener los datos
                email = 'xxxxxxx'
                password = 'xxxxxxx'
                nombre, irating = obtener_datos_iracing(email, password)
                
                # Crea el JSON con los datos
                data = {
                    'nombre': nombre,
                    'irating': irating
                }
                # Envía la respuesta con los datos JSON
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())
            except Exception as e:
                # Si hay un error, envía una respuesta de error con el mensaje
                self.send_response(500)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(str(e).encode())
        else:
            # Maneja las solicitudes de archivos estáticos (HTML, CSS, JS)
            super().do_GET()

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()
