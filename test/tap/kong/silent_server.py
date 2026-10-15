#!/usr/bin/env python3
"""Socket-transport server for tests that accepts sessions and never
answers with a verdict. Appends one line to <dir>/sessions per session."""
import os, socket, struct, sys, threading

d = sys.argv[1]
path = os.path.join(d, "worker-0.stream.sock")
if os.path.exists(path):
    os.unlink(path)
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
os.chmod(path, 0o777)
srv.listen(16)

def serve(c):
    with c:
        hello = b""
        while len(hello) < 64:
            b = c.recv(64 - len(hello))
            if not b:
                return
            hello += b
        # Count the session before WELCOME: the client may look right after.
        with open(os.path.join(d, "sessions"), "a") as f:
            f.write("session\n")
        welcome = struct.pack("<IHHHHI", 0x50415453, 1, 0, 0, 1, 65536).ljust(64, b"\0")
        c.sendall(welcome)
        while c.recv(65536):
            pass

while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
