#!/usr/bin/env python3
"""Prints the SASL mechanisms a server offers over TLS, for the rig log.

usage: sasl-mechanisms.py <host> <port> <user> <dbname>

Diagnostic only: the certificate is not verified and no credential is sent.
"""
import socket
import ssl
import struct
import sys

host, port, user, dbname = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
raw = socket.create_connection((host, port), timeout=10)
raw.sendall(struct.pack("!ii", 8, 80877103))
if raw.recv(1) != b"S":
    sys.exit(f"{host}:{port}: server refused TLS")
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
tls = context.wrap_socket(raw)
params = b"user\0" + user.encode() + b"\0database\0" + dbname.encode() + b"\0\0"
tls.sendall(struct.pack("!ii", 8 + len(params), 196608) + params)


def read(n):
    buf = b""
    while len(buf) < n:
        chunk = tls.recv(n - len(buf))
        if not chunk:
            sys.exit(f"{host}:{port}: connection closed")
        buf += chunk
    return buf


tag = read(1)
(length,) = struct.unpack("!i", read(4))
body = read(length - 4)
cert = tls.getpeercert(binary_form=True)
print(f"{host}:{port} tls={tls.version()} cipher={tls.cipher()[0]} leaf_der_bytes={len(cert)}")
if tag != b"R":
    sys.exit(f"{host}:{port}: first message {tag!r}: {body!r}")
(code,) = struct.unpack("!i", body[:4])
if code == 10:
    mechanisms = [m.decode() for m in body[4:].split(b"\0") if m]
    print(f"{host}:{port} user={user} AuthenticationSASL mechanisms={','.join(mechanisms)}")
else:
    print(f"{host}:{port} user={user} authentication request code={code}")
