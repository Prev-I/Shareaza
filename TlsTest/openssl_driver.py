"""Drives openssl s_server for TlsTest's post-handshake tests. Standard library only.

Runs one s_server on [::1]:<port> (IPv6 loopback only) with a single protocol
version. Whenever a client sends the line "go", the driver writes a command to
s_server's stdin, waits a second, then writes "hello", which s_server sends to
the client as application data:

  --protocol tls1_2 --command R   the server starts a TLS 1.2 renegotiation
  --protocol tls1_3 --command K   the server sends a TLS 1.3 KeyUpdate that
                                  asks the client to update its keys too

Everything s_server prints goes to the log, after "listening on [::1]:<port>"
once s_server reports ACCEPT.

  python openssl_driver.py --openssl openssl.exe --cert cert.pem --key key.pem
      --port 8445 --protocol tls1_2 --command R --log driver.log
"""

import argparse
import os
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--protocol", choices=["tls1_2", "tls1_3"], required=True)
    parser.add_argument("--command", choices=["R", "K"], required=True)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    def log(message):
        with open(args.log, "a", encoding="utf-8") as log_file:
            log_file.write("%s %s\n" % (time.strftime("%H:%M:%S"), message))

    # The MSYS runtime of Git's openssl must not rewrite arguments as paths.
    env = dict(os.environ, MSYS2_ARG_CONV_EXCL="*", MSYS_NO_PATHCONV="1")
    command = [args.openssl, "s_server", "-accept", "[::1]:%d" % args.port,
               "-cert", args.cert, "-key", args.key, "-" + args.protocol]
    server = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, env=env, bufsize=0)
    listening = False
    for raw in iter(server.stdout.readline, b""):
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        log("s_server: %s" % line)
        if line == "ACCEPT" and not listening:
            listening = True
            log("listening on [::1]:%d" % args.port)
        if line.strip() == "go":
            server.stdin.write(("%s\n" % args.command).encode("ascii"))
            server.stdin.flush()
            log("sent %s" % args.command)
            time.sleep(1)
            server.stdin.write(b"hello\n")
            server.stdin.flush()
            log("sent hello")
    log("s_server exited with %d" % server.wait())


if __name__ == "__main__":
    main()
