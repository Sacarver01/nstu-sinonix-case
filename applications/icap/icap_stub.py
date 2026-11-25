#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Лёгкая ICAP-заглушка для стенда «Синоникс» (только стандартная библиотека).

Нужна, чтобы отладить связку «комплекс — ICAP» и тесты, пока не поднят настоящий
c-icap + ClamAV (см. ../icap_docker). Это НЕ антивирус: она ловит только
  • тестовую строку EICAR в теле файла,
  • расширения вне списка разрешённых (--allow-ext),
  • файлы больше лимита (--max-size).

Поддержано: OPTIONS, REQMOD, RESPMOD (без Preview), ответ 204 при Allow: 204.
Каждое решение пишется в CSV (--log) — это свидетельство для протокола.

  python3 icap_stub.py --port 1344 --allow-ext txt,bin,json --max-size 1048576 --log logs/icap.csv
"""
import argparse, csv, re, socketserver, sys, threading, time
from pathlib import Path

EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
ISTAG = '"icap-stub-1"'
LOCK = threading.Lock()


def read_until(f, marker):
    buf = b""
    while not buf.endswith(marker):
        c = f.read(1)
        if not c: raise EOFError
        buf += c
    return buf


def read_chunked(f):
    body = b""
    while True:
        line = read_until(f, b"\r\n").strip()
        size = int(line.split(b";")[0], 16)
        if size == 0:
            # trailer до пустой строки
            while read_until(f, b"\r\n") != b"\r\n": pass
            return body
        body += f.read(size); f.read(2)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            while True:
                head = read_until(self.rfile, b"\r\n\r\n").decode("latin1")
                lines = head.split("\r\n")
                m = re.match(r"(\w+) icap://([^/ ]+)(/[^ ?]*)?\S* ICAP/1\.0", lines[0])
                if not m: self.reply("400 Bad Request"); return
                method, service = m[1].upper(), (m[3] or "/")
                hdr = {k.strip().lower(): v.strip() for k, v in
                       (l.split(":", 1) for l in lines[1:] if ":" in l)}
                if method == "OPTIONS":
                    self.reply("200 OK", {"Methods": "REQMOD, RESPMOD", "Service": "ICAP stub",
                                          "ISTag": ISTAG, "Allow": "204", "Max-Connections": "100",
                                          "Options-TTL": "3600", "Encapsulated": "null-body=0"})
                    continue
                if method not in ("REQMOD", "RESPMOD"):
                    self.reply("405 Method Not Allowed"); return
                self.process(method, service, hdr)
        except (EOFError, ConnectionError, ValueError):
            pass

    def process(self, method, service, hdr):
        t0 = time.time()
        enc = [(k, int(v)) for k, v in re.findall(r"([a-z-]+)=(\d+)", hdr.get("encapsulated", ""))]
        sections = {}
        for i, (k, off) in enumerate(enc):
            nxt = enc[i + 1][1] if i + 1 < len(enc) else None
            if k.endswith("hdr") and nxt is not None:
                sections[k] = self.rfile.read(nxt - off)
        body = b"" if any(k == "null-body" for k, _ in enc) else read_chunked(self.rfile)
        first = (sections.get("req-hdr") or b"").split(b"\r\n")[0].decode("latin1")
        mm = re.match(r"\w+ (\S+)", first)
        name = (mm[1] if mm else "").split("?")[0].rsplit("/", 1)[-1] or "unknown"
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        verdict, reason = "clean", ""
        if EICAR in body: verdict, reason = "blocked", "EICAR-Test-Signature"
        elif self.server.allow_ext and ext not in self.server.allow_ext:
            verdict, reason = "blocked", f"extension .{ext or '-'} not allowed"
        elif len(body) > self.server.max_size:
            verdict, reason = "blocked", f"size {len(body)} > {self.server.max_size}"
        self.server.log(self.client_address[0], method, service, name, len(body), verdict, reason,
                        round(1000 * (time.time() - t0), 2))
        if verdict == "clean" and "204" in hdr.get("allow", ""):
            self.reply("204 No Content", {"ISTag": ISTAG, "Encapsulated": "null-body=0"}); return
        if verdict == "clean":  # вернуть как есть
            if method == "REQMOD":
                h = sections.get("req-hdr", b""); key = "req"
            else:
                h = sections.get("res-hdr", b""); key = "res"
            out = h + b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
            self.reply("200 OK", {"ISTag": ISTAG, "Encapsulated": f"{key}-hdr=0, {key}-body={len(h)}"}, out); return
        page = f"<html><body>Blocked: {reason}</body></html>".encode()
        h = (b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n" % len(page))
        out = h + b"%x\r\n" % len(page) + page + b"\r\n0\r\n\r\n"
        self.reply("200 OK", {"ISTag": ISTAG, "X-Infection-Found": f"Type=0; Resolution=2; Threat={reason};",
                              "X-Virus-ID": reason, "Encapsulated": f"res-hdr=0, res-body={len(h)}"}, out)

    def reply(self, status, headers=None, body=b""):
        out = f"ICAP/1.0 {status}\r\n"
        for k, v in (headers or {}).items(): out += f"{k}: {v}\r\n"
        self.wfile.write(out.encode() + b"\r\n" + body); self.wfile.flush()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True; daemon_threads = True

    def __init__(self, a):
        super().__init__((a.bind, a.port), Handler)
        self.allow_ext = {e.strip().lower() for e in a.allow_ext.split(",") if e.strip()}
        self.max_size = a.max_size; self.path = Path(a.log) if a.log else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("w", newline="") as f:
                csv.writer(f).writerow(["time", "client", "method", "service", "file", "size", "verdict", "reason", "ms"])

    def log(self, *row):
        line = (time.strftime("%Y-%m-%d %H:%M:%S"),) + row
        print("[ICAP] " + " | ".join(map(str, line)), file=sys.stderr, flush=True)
        if self.path:
            with LOCK, self.path.open("a", newline="") as f: csv.writer(f).writerow(line)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bind", default="0.0.0.0"); p.add_argument("--port", type=int, default=1344)
    p.add_argument("--allow-ext", default="", help="разрешённые расширения через запятую; пусто = любые")
    p.add_argument("--max-size", type=int, default=10 * 1024 * 1024, help="лимит размера, байт")
    p.add_argument("--log", default=None, help="CSV с решениями")
    a = p.parse_args(); s = Server(a)
    print(f"[INFO] ICAP stub on {a.bind}:{a.port}", file=sys.stderr)
    try: s.serve_forever()
    except KeyboardInterrupt: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
