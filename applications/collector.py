#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Коллектор-приёмник телеметрии для стенда на базе ПК «Синоникс».
Совместим с форматом telemetry_emulator.py.

Что делает:
  • принимает UDP-датаграммы и TCP-поток (построчный JSON);
  • по sid различает сессии (перезапуск эмулятора — новая сессия);
  • по seq считает потери и перестановки;
  • по ts считает одностороннюю задержку (при синхронизированных часах);
  • пишет CSV с каждым сообщением и итоговую сводку;
  • в режиме --bidirectional отвечает "ack:<seq>\n" (для transport).

Запуск:
  python3 collector.py --mode udp --port 5001 --csv logs/udp.csv
  python3 collector.py --mode tcp --port 5000 --csv logs/tcp.csv --bidirectional
"""

from __future__ import annotations

import argparse
import csv
import json
import signal
import socket
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SessionStats:
    sid: str
    received: int = 0
    expected_seq: int = 1
    lost: int = 0
    out_of_order: int = 0
    latencies: list[float] = field(default_factory=list)
    first_ts: float = 0.0
    last_ts: float = 0.0
    first_recv: float = 0.0
    last_recv: float = 0.0

    def ingest(self, msg: dict) -> tuple:
        now = time.time()
        seq = int(msg["seq"])
        ts = float(msg["ts"])

        if self.received == 0:
            self.first_ts = ts
            self.first_recv = now
        self.last_ts = ts
        self.last_recv = now
        self.received += 1
        lat = now - ts
        self.latencies.append(lat)

        if seq < self.expected_seq:
            self.out_of_order += 1
        elif seq == self.expected_seq:
            self.expected_seq += 1
        else:
            gap = seq - self.expected_seq
            self.lost += gap
            self.expected_seq = seq + 1
        return seq, ts, now, lat

    def summary(self) -> dict:
        lat = self.latencies
        n = len(lat)
        span = self.last_ts - self.first_ts if self.received > 1 else 0.0
        return {
            "sid": self.sid,
            "received": self.received,
            "lost": self.lost,
            "out_of_order": self.out_of_order,
            "expected_last_seq": self.expected_seq - 1,
            "loss_pct": round(100.0 * self.lost / max(1, self.received + self.lost), 3),
            "latency_avg_ms": round(1000 * sum(lat) / n, 3) if n else 0,
            "latency_min_ms": round(1000 * min(lat), 3) if n else 0,
            "latency_max_ms": round(1000 * max(lat), 3) if n else 0,
            "latency_p95_ms": round(1000 * _p(lat, 0.95), 3) if n else 0,
            "source_rate_msg_s": round(self.received / span, 3) if span > 0 else 0,
        }


def _p(values: list[float], q: float) -> float:
    s = sorted(values)
    if not s:
        return 0.0
    i = int(round(q * (len(s) - 1)))
    return s[i]


class Collector:
    def __init__(self, args):
        self.args = args
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.sessions: "OrderedDict[str, SessionStats]" = OrderedDict()
        self.rows: list[tuple] = []
        self.csv_path = Path(args.csv) if args.csv else None
        if self.csv_path:
            self.csv_path.parent.mkdir(parents=True, exist_ok=True)
            with self.csv_path.open("w", newline="") as f:
                csv.writer(f).writerow(
                    ["recv_unix", "sid", "seq", "sent_unix", "latency_ms"])

    def handle_line(self, raw: bytes, writer=None) -> Optional[bytes]:
        try:
            msg = json.loads(raw)
        except Exception as e:
            print(f"[bad msg] {e}: {raw!r}", file=sys.stderr)
            return None

        sid = str(msg.get("sid", "?"))
        with self.lock:
            st = self.sessions.get(sid)
            if st is None:
                st = SessionStats(sid=sid)
                self.sessions[sid] = st
                print(f"[SESSION] new sid={sid}", file=sys.stderr)
            seq, ts, now, lat = st.ingest(msg)
            row = (round(now, 6), sid, seq, round(ts, 6), round(1000 * lat, 3))
            self.rows.append(row)
            if writer:
                writer.writerow(row)

        if self.args.bidirectional:
            return f"ack:{seq}\n".encode()
        return None

    # ---------- UDP ----------
    def serve_udp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.args.bind, self.args.port))
        s.settimeout(0.5)
        print(f"[INFO] UDP listening on {self.args.bind}:{self.args.port}",
              file=sys.stderr)
        f = self._open_csv_stream()
        writer = csv.writer(f) if f else None
        try:
            while not self.stop.is_set():
                try:
                    data, addr = s.recvfrom(65535)
                except socket.timeout:
                    continue
                resp = self.handle_line(data, writer)
                if resp:
                    s.sendto(resp, addr)
        finally:
            s.close()
            self._close_csv_stream(f)

    # ---------- TCP ----------
    def serve_tcp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.args.bind, self.args.port))
        s.listen(8)
        s.settimeout(0.5)
        print(f"[INFO] TCP listening on {self.args.bind}:{self.args.port}",
              file=sys.stderr)
        threads: list[threading.Thread] = []
        try:
            while not self.stop.is_set():
                try:
                    c, addr = s.accept()
                except socket.timeout:
                    continue
                t = threading.Thread(target=self._client_loop, args=(c, addr),
                                     daemon=True)
                t.start()
                threads.append(t)
        finally:
            s.close()
            for t in threads:
                t.join(timeout=2)

    def _client_loop(self, c: socket.socket, addr):
        print(f"[INFO] client connected from {addr}", file=sys.stderr)
        c.settimeout(0.5)
        buf = b""
        f = self._open_csv_stream()
        writer = csv.writer(f) if f else None
        try:
            while not self.stop.is_set():
                try:
                    chunk = c.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, _, buf = buf.partition(b"\n")
                    resp = self.handle_line(line, writer)
                    if resp:
                        try:
                            c.sendall(resp)
                        except OSError:
                            return
        finally:
            try:
                c.close()
            except OSError:
                pass
            self._close_csv_stream(f)
            print(f"[INFO] client {addr} disconnected", file=sys.stderr)

    def _open_csv_stream(self):
        return None  # CSV пишется единым файлом в run()

    def _close_csv_stream(self, f):
        pass

    def run(self):
        if self.args.mode == "udp":
            self.serve_udp()
        else:
            self.serve_tcp()
        self._dump_summary()

    def _dump_summary(self):
        # переписываем CSV полностью в конце, чтобы не было гонки
        if self.csv_path and self.rows:
            with self.csv_path.open("w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["recv_unix", "sid", "seq", "sent_unix", "latency_ms"])
                w.writerows(self.rows)

        print("\n=== SUMMARY ===", file=sys.stderr)
        with self.lock:
            for st in self.sessions.values():
                print(json.dumps(st.summary(), ensure_ascii=False),
                      file=sys.stderr)


def build_parser():
    p = argparse.ArgumentParser(
        description="Коллектор-приёмник телеметрии (совместим с telemetry_emulator.py).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--mode", choices=["tcp", "udp"], required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--csv", default=None, help="Путь к CSV с сообщениями")
    p.add_argument("--bidirectional", action="store_true",
                   help="Отвечать ack:<seq> (режим transport)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    c = Collector(args)

    def stop(sig, _):
        print(f"\n[INFO] signal {sig}, stopping...", file=sys.stderr)
        c.stop.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    c.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())