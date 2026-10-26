"""A local HTTPS server for TlsTest's Local tests. Standard library only.

Listens on [::1]:8443 (IPv6 loopback only) and serves:

  /5mb       5 MiB of the pattern byte[i] = i % 251, then close_notify
  /64k       64 KiB of the same pattern, then close_notify
  /shutdown  a short body, then close_notify
  /abrupt    100000 pattern bytes with no Content-Length, then a TCP close
             without close_notify

After close_notify the server waits for the client's and logs
"close_notify received for <path>" when unwrap() succeeds, or
"no close_notify for <path>: <error>" when it does not.

  python tls_server.py --cert cert.pem --key key.pem --log server.log
"""

import argparse
import http.server
import socket
import socketserver
import ssl
import threading
import time

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

    def do_GET(self):
        if self.path in BODIES:
            self.send_and_close(BODIES[self.path])
        elif self.path == "/abrupt":
            self.send_abrupt()
        else:
            self.send_error(404)

    def send_and_close(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
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
    args = parser.parse_args()
    LOG_PATH = args.log

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)

    server = Server(("::1", args.port, 0, 0), context)
    log("listening on [::1]:%d" % args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
