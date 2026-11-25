#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modbus TCP коллектор-приёмник (сервер) для стенда «Синоникс». Только стандартная библиотека.
Принимает записи регистров от modbus_emulator.py (карта регистров описана в нём),
считает потери по seq и одностороннюю задержку по ts, пишет CSV и сводку в том же
формате, что collector.py (совместимо с run_test.py).

Поддержано: 0x03 чтение, 0x06 запись одного, 0x10 запись нескольких регистров.
Остальные функции: исключение 0x01 (illegal function).

Без --bidirectional ответы НЕ отправляются (режим diode). С --bidirectional сервер
отвечает как обычный Modbus-сервер (режим transport).

  python3 modbus_collector.py --port 5020 --csv logs/m.csv
  python3 modbus_collector.py --port 5020 --csv logs/m.csv --bidirectional
"""
import argparse, csv, json, signal, socket, struct, sys, threading, time
from collections import OrderedDict
from pathlib import Path

NREG = 12
FIELDS = ["recv_unix", "sid", "seq", "sent_unix", "latency_ms",
          "temperature_c", "pressure_kpa", "vibration", "flow", "level_pct"]


def _p(v, q):
    s = sorted(v); return s[int(round(q * (len(s) - 1)))] if s else 0.0


class Session:
    def __init__(self, sid):
        self.sid = sid; self.received = 0; self.exp = 1; self.lost = 0; self.ooo = 0
        self.lat = []; self.first = 0.0; self.last = 0.0

    def ingest(self, seq, ts, now):
        if self.received == 0: self.first = ts
        self.last = ts; self.received += 1
        self.lat.append(now - ts)
        if seq < self.exp: self.ooo += 1
        elif seq == self.exp: self.exp += 1
        else: self.lost += seq - self.exp; self.exp = seq + 1

    def summary(self):
        l = self.lat; n = len(l); span = self.last - self.first if self.received > 1 else 0
        return {"sid": self.sid, "received": self.received, "lost": self.lost,
                "out_of_order": self.ooo, "expected_last_seq": self.exp - 1,
                "loss_pct": round(100.0 * self.lost / max(1, self.received + self.lost), 3),
                "latency_avg_ms": round(1000 * sum(l) / n, 3) if n else 0,
                "latency_min_ms": round(1000 * min(l), 3) if n else 0,
                "latency_max_ms": round(1000 * max(l), 3) if n else 0,
                "latency_p95_ms": round(1000 * _p(l, .95), 3) if n else 0,
                "source_rate_msg_s": round(self.received / span, 3) if span > 0 else 0}


class Server:
    def __init__(self, a):
        self.a = a; self.stop = threading.Event(); self.lock = threading.Lock()
        self.regs = [0] * 65536; self.sessions = OrderedDict(); self.rows = []
        self.csv = Path(a.csv) if a.csv else None
        if self.csv: self.csv.parent.mkdir(parents=True, exist_ok=True)

    def on_write(self, addr, data):
        with self.lock:
            for i in range(len(data) // 2):
                self.regs[addr + i] = struct.unpack(">H", data[2*i:2*i+2])[0]
            if addr == 0 and len(data) >= NREG * 2:
                seq, sec, ms, t, p, vib, fl, lv, sid = struct.unpack(">IIHhhHHHI", data[:NREG*2])
                now = time.time(); ts = sec + ms / 1000.0; sids = f"{sid:08x}"
                st = self.sessions.get(sids)
                if st is None:
                    st = self.sessions[sids] = Session(sids)
                    print(f"[SESSION] new sid={sids}", file=sys.stderr)
                st.ingest(seq, ts, now)
                self.rows.append((round(now, 6), sids, seq, round(ts, 3), round(1000*(now-ts), 3),
                                  t/10, p/10, vib/1000, fl/10, lv/10))

    def handle(self, pdu):
        fc = pdu[0]
        if fc == 0x10 and len(pdu) >= 6:
            addr, qty, bc = struct.unpack(">HHB", pdu[1:6]); data = pdu[6:6+bc]
            if len(data) != bc or bc != qty * 2 or addr + qty > 65536:
                return bytes([0x90, 0x03])
            self.on_write(addr, data); return struct.pack(">BHH", 0x10, addr, qty)
        if fc == 0x06 and len(pdu) >= 5:
            addr, val = struct.unpack(">HH", pdu[1:5]); self.on_write(addr, pdu[3:5])
            return pdu[:5]
        if fc == 0x03 and len(pdu) >= 5:
            addr, qty = struct.unpack(">HH", pdu[1:5])
            if not 1 <= qty <= 125 or addr + qty > 65536: return bytes([0x83, 0x03])
            with self.lock: vals = self.regs[addr:addr+qty]
            return bytes([0x03, qty * 2]) + b"".join(struct.pack(">H", v) for v in vals)
        return bytes([fc | 0x80, 0x01])

    def client(self, c, addr):
        print(f"[INFO] client connected from {addr}", file=sys.stderr)
        c.settimeout(0.5); buf = b""
        try:
            while not self.stop.is_set():
                try: chunk = c.recv(4096)
                except socket.timeout: continue
                if not chunk: break
                buf += chunk
                while len(buf) >= 7:
                    tid, pid, ln, unit = struct.unpack(">HHHB", buf[:7])
                    if len(buf) < 6 + ln: break
                    pdu, buf = buf[7:6+ln], buf[6+ln:]
                    resp = self.handle(pdu) if pdu else None
                    if resp and self.a.bidirectional:
                        try: c.sendall(struct.pack(">HHHB", tid, 0, len(resp) + 1, unit) + resp)
                        except OSError: return
        finally:
            c.close(); print(f"[INFO] client {addr} disconnected", file=sys.stderr)

    def run(self):
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.a.bind, self.a.port)); s.listen(8); s.settimeout(0.5)
        print(f"[INFO] Modbus TCP server on {self.a.bind}:{self.a.port} "
              f"({'отвечает' if self.a.bidirectional else 'не отвечает, режим diode'})", file=sys.stderr)
        th = []
        try:
            while not self.stop.is_set():
                try: c, addr = s.accept()
                except socket.timeout: continue
                t = threading.Thread(target=self.client, args=(c, addr), daemon=True); t.start(); th.append(t)
        finally:
            s.close()
            for t in th: t.join(timeout=2)
        if self.csv and self.rows:
            with self.csv.open("w", newline="") as f:
                w = csv.writer(f); w.writerow(FIELDS); w.writerows(self.rows)
        print("\n=== SUMMARY ===", file=sys.stderr)
        with self.lock:
            for st in self.sessions.values(): print(json.dumps(st.summary(), ensure_ascii=False), file=sys.stderr)


def main(argv=None):
    p = argparse.ArgumentParser(description="Modbus TCP коллектор для стенда «Синоникс».",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--mode", choices=["tcp"], default="tcp"); p.add_argument("--port", type=int, default=502)
    p.add_argument("--bind", default="0.0.0.0"); p.add_argument("--csv", default=None)
    p.add_argument("--bidirectional", action="store_true", help="отвечать на запросы (transport)")
    a = p.parse_args(argv); srv = Server(a)
    for sg in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sg, lambda *_: srv.stop.set())
    srv.run(); return 0


if __name__ == "__main__":
    sys.exit(main())
