#!/usr/bin/env python3
import argparse
import http.server
import json
import pathlib
import ssl
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "CandyWebhookTest/1"

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/messages":
            with self.server.messages_lock:
                body = json.dumps(self.server.messages).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self):
        if self.path != "/candy-identity":
            self.send_error(404)
            return
        if self.headers.get("Authorization") != self.server.authorization:
            self.send_error(401)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            message = json.loads(self.rfile.read(length))
            if sorted(message) != ["purpose", "recipient", "token"]:
                raise ValueError("unexpected message shape")
            if not all(isinstance(message[key], str) and message[key] for key in message):
                raise ValueError("empty message field")
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)
            return
        with self.server.messages_lock:
            self.server.messages.append(message)
        self.send_response(202)
        self.end_headers()

    def log_message(self, format, *args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", type=pathlib.Path, required=True)
    parser.add_argument("--key", type=pathlib.Path, required=True)
    parser.add_argument("--authorization", required=True)
    args = parser.parse_args()

    server = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    server.messages = []
    server.messages_lock = threading.Lock()
    server.authorization = args.authorization
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
