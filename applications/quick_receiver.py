# этот скрипт только для отладки

import json
import socket
import sys

mode = sys.argv[1]          # udp | tcp
port = int(sys.argv[2])     # 5000

s = socket.socket(socket.AF_INET,
                  socket.SOCK_DGRAM if mode == "udp" else socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))


def dump(raw: bytes) -> None:
    try:
        print(json.loads(raw), flush=True)
    except Exception as e:
        print(f"[bad msg] {e}: {raw!r}", flush=True)


try:
    if mode == "udp":
        s.settimeout(0.5)
        while True:
            try:
                data, _ = s.recvfrom(65535)
                dump(data)
            except socket.timeout:
                continue

    elif mode == "tcp":
        s.listen(1)
        s.settimeout(0.5)
        while True:
            try:
                c, _ = s.accept()
                break
            except socket.timeout:
                continue

        c.settimeout(0.5)
        buf = b""
        while True:
            try:
                chunk = c.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                print("[conn closed]", flush=True)
                break
            buf += chunk
            while b"\n" in buf:
                line, _, buf = buf.partition(b"\n")
                dump(line)
    else:
        print(f"unknown mode: {mode}", file=sys.stderr)
        sys.exit(2)

except KeyboardInterrupt:
    print("\n[stopped by user]", file=sys.stderr)
finally:
    s.close()