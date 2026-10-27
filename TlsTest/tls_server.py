"""A local HTTPS server for TlsTest's Local tests. Standard library only.

Listens on [::1]:8443 (IPv6 loopback only) and serves:

  GET /5mb        5 MiB of the pattern byte[i] = i % 251, then close_notify
  GET /64k        64 KiB of the same pattern, then close_notify
  GET /shutdown   a short body, then close_notify
  GET /abrupt     100000 pattern bytes with no Content-Length, then a TCP
                  close without close_notify
  POST /echo-len  checks the request body against the pattern and answers
                  "length <n> pattern ok" (or "bad"), then close_notify

A query string is ignored for routing but kept in every log line, so a test
can tag its request with a nonce and find its own lines.

After close_notify the server waits for the client's and logs
"close_notify received for <path>" when unwrap() succeeds, or
"no close_notify for <path>: <error>" when it does not.

With --optional-port, a second listener on [::1] serves the same paths but
asks every client for a certificate (CERT_OPTIONAL) and logs whether one
came: "client certificate requested for <path>: none" or ": present".

  python tls_server.py --cert cert.pem --key key.pem --log server.log [--optional-port 8444]
"""

import argparse
import http.server
import socket
import socketserver
import ssl
import threading
import time
import urllib.parse

LOG_LOCK = threading.Lock()
LOG_PATH = None

CONNECTION_TIMEOUT = 30


def log(message):
    line = "%s %s\n" % (time.strftime("%H:%M:%S"), message)
    with LOG_LOCK:
        with open(LOG_PATH, "a", encoding="utf-8") as log_file:
            log_file.write(line)


def pattern(size):
    block = bytes(i % 251 for i in range(251))
    return (block * (size // 251 + 1))[:size]


BODIES = {
    "/5mb": pattern(5 * 1024 * 1024),
    "/64k": pattern(65536),
    "/shutdown": b"bye\n",
}
ABRUPT_BODY = pattern(100000)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A002 - the base class's name
        log("%s %s" % (self.address_string(), format % args))

    def route(self):
        return urllib.parse.urlsplit(self.path).path

    def log_client_certificate(self):
        if self.server.context.verify_mode == ssl.CERT_OPTIONAL:
            present = self.connection.getpeercert(binary_form=True)
            log("client certificate requested for %s: %s" % (self.path, "present" if present else "none"))

    def do_GET(self):
        self.log_client_certificate()
        route = self.route()
        if route in BODIES:
            self.send_and_close(BODIES[route])
        elif route == "/abrupt":
            self.send_abrupt()
        else:
            self.send_error(404)

    def do_POST(self):
        self.log_client_certificate()
        if self.route() != "/echo-len":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        verdict = "ok" if body == pattern(len(body)) else "bad"
        reply = "length %d pattern %s\n" % (len(body), verdict)
        log("echo-len %s: %s" % (self.path, reply.strip()))
        self.send_and_close(reply.encode("ascii"), "text/plain")

    def send_and_close(self, body, content_type="application/octet-stream"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True
        # Sends close_notify, then waits for the client's.
        try:
            self.connection.unwrap()
        except (OSError, ValueError) as error:
            log("no close_notify for %s: %r" % (self.path, error))
        else:
            log("close_notify received for %s" % self.path)

    def send_abrupt(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(ABRUPT_BODY)
        self.close_connection = True
        # SSLSocket.shutdown() drops the TLS layer and shuts the TCP socket
        # down: the client sees the connection end without close_notify.
        self.connection.shutdown(socket.SHUT_RDWR)
        log("closed %s without close_notify" % self.path)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def __init__(self, address, context):
        self.context = context
        super().__init__(address, Handler)

    def server_bind(self):
        # HTTPServer.server_bind() resolves the host name; nothing needs it.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]

    def finish_request(self, request, client_address):
        # The handshake runs in the connection's thread, so a slow client
        # cannot hold up accept().
        request.settimeout(CONNECTION_TIMEOUT)
        try:
            connection = self.context.wrap_socket(request, server_side=True)
        except (OSError, ValueError) as error:
            log("handshake failed: %r" % (error,))
            return
        try:
            log("handshake done: %s %s" % (connection.version(), connection.cipher()[0]))
            self.RequestHandlerClass(connection, client_address, self)
        except (OSError, ValueError) as error:
            log("connection failed: %r" % (error,))
        finally:
            connection.close()


def main():
    global LOG_PATH
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--optional-port", type=int, default=0)
    args = parser.parse_args()
    LOG_PATH = args.log

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server = Server(("::1", args.port, 0, 0), context)

    if args.optional_port:
        # Asks for a client certificate; the client is expected to send none.
        optional = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        optional.load_cert_chain(args.cert, args.key)
        optional.load_verify_locations(args.cert)
        optional.verify_mode = ssl.CERT_OPTIONAL
        optional_server = Server(("::1", args.optional_port, 0, 0), optional)
        threading.Thread(target=optional_server.serve_forever, daemon=True).start()
        log("listening on [::1]:%d, client certificate requested" % args.optional_port)

    log("listening on [::1]:%d" % args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
