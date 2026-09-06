import os
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

NOTES_DIR = "/tmp/notes"
os.makedirs(NOTES_DIR, exist_ok=True)

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        note_id = str(uuid.uuid4())
        with open(os.path.join(NOTES_DIR, note_id), "w") as f:
            f.write(body["content"])
        self._respond(200, {"id": note_id})

    def do_GET(self):
        note_id = self.path.split("/note/")[-1]
        path = os.path.join(NOTES_DIR, note_id) 
        try:
            with open(path) as f:
                self._respond(200, {"content": f.read()})
        except FileNotFoundError:
            self._respond(404, {"error": "not found"})

    def _respond(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()