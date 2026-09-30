#!/usr/bin/env python3
"""Enclave side: framed vsock streams from the parent <-> UDP server on 127.0.0.1:4433.

Each vsock connection from the parent is one client. Datagrams are framed as
[2-byte big-endian length][payload] on the vsock.
"""
import socket
import struct
import threading

VSOCK_PORT = 5000
SERVER_ADDR = ("127.0.0.1", 4433)
IDLE_TIMEOUT = 120  # seconds without a reply from the server before giving up
HDR = struct.Struct("!H")


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def close_pair(vs, udp):
    for s in (vs, udp):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        s.close()


def vsock_to_udp(vs, udp):
    # client (via parent) -> server
    try:
        while True:
            hdr = recv_exact(vs, HDR.size)
            if hdr is None:
                break
            data = recv_exact(vs, HDR.unpack(hdr)[0])
            if data is None:
                break
            try:
                udp.send(data)
            except ConnectionRefusedError:
                pass  # server not listening (yet); drop the packet
    except OSError:
        pass
    finally:
        close_pair(vs, udp)


def udp_to_vsock(vs, udp):
    # server -> client (via parent)
    try:
        while True:
            try:
                data = udp.recv(65535)
            except ConnectionRefusedError:
                continue
            if not data:
                break
            vs.sendall(HDR.pack(len(data)) + data)
    except OSError:  # includes idle timeout
        pass
    finally:
        close_pair(vs, udp)


def main():
    srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
    srv.listen(128)
    print(f"vsock {VSOCK_PORT} -> UDP {SERVER_ADDR[0]}:{SERVER_ADDR[1]}", flush=True)

    while True:
        vs, _ = srv.accept()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.connect(SERVER_ADDR)
        udp.settimeout(IDLE_TIMEOUT)
        threading.Thread(target=vsock_to_udp, args=(vs, udp), daemon=True).start()
        threading.Thread(target=udp_to_vsock, args=(vs, udp), daemon=True).start()


if __name__ == "__main__":
    main()