#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Эмулятор источника технологических данных (телеметрии) для стенда
контролируемого информационного обмена на базе ПК «Синоникс».

Сценарии (флаги эмулятора):
  • diode  TCP   --mode tcp
  • diode  UDP   --mode udp
  • transport TCP --mode tcp --bidirectional
  • transport UDP --mode udp --bidirectional

Формат сообщения — построчный JSON (для TCP) / отдельная датаграмма (UDP):
    {"sid":"...","seq":1,"ts":1717000000.123,"source":"sensor-sim",
     "payload":{"temperature":20.1,"pressure":101.2,...}}

Коллектор по seq считает потери, по ts — одностороннюю задержку
(при синхронизированных часах на всех узлах).
"""

from __future__ import annotations

import argparse
import json
import random
import signal
import socket
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Optional


# ---------- Формат сообщения ----------

@dataclass
class Message:
    sid: str        # идентификатор сессии (UUID эмулятора)
    seq: int        # порядковый номер, стартует с 1
    ts: float       # метка времени отправки, Unix time (сек, float)
    source: str     # идентификатор источника
    payload: dict   # полезная нагрузка


def make_payload(seq: int, padding: int) -> dict:
    p = {
        "temperature": round(20.0 + random.uniform(-2.0, 2.0), 3),
        "pressure": round(101.3 + random.uniform(-0.5, 0.5), 3),
        "vibration": round(random.uniform(0.0, 1.0), 3),
        "flow": round(50.0 + random.uniform(-5.0, 5.0), 3),
        "level": round(75.0 + random.uniform(-3.0, 3.0), 3),
    }
    if padding > 0:
        p["_pad"] = "x" * padding
    return p


def encode(msg: Message) -> bytes:
    return (json.dumps(asdict(msg), separators=(",", ":"), ensure_ascii=False)
            + "\n").encode("utf-8")


# ---------- Отправители ----------

class SenderBase:
    def send(self, data: bytes) -> None: ...
    def try_recv(self, timeout: float) -> Optional[bytes]: return None
    def close(self) -> None: ...


class UdpSender(SenderBase):
    def __init__(self, host, port, bind_addr=None, bind_port=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if bind_addr or bind_port:
            self.sock.bind((bind_addr or "", bind_port))
        self.target = (host, port)

    def send(self, data):
        self.sock.sendto(data, self.target)

    def try_recv(self, timeout):
        self.sock.settimeout(timeout)
        try:
            data, _ = self.sock.recvfrom(65535)
            return data
        except socket.timeout:
            return None
        finally:
            try:
                self.sock.settimeout(None)
            except OSError:
                pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class TcpSender(SenderBase):
    def __init__(self, host, port, connect_timeout=5.0, reconnect_delay=1.0):
        self.target = (host, port)
        self.connect_timeout = connect_timeout
        self.reconnect_delay = reconnect_delay
        self.sock: Optional[socket.socket] = None
        self.buffer = b""

    def _connect(self):
        s = socket.create_connection(self.target, timeout=self.connect_timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(None)
        self.sock = s
        self.buffer = b""

    def send(self, data):
        while True:
            try:
                if self.sock is None:
                    self._connect()
                self.sock.settimeout(None)
                self.sock.sendall(data)
                return
            except (ConnectionError, OSError) as e:
                print(f"[WARN] TCP send error: {e}; reconnecting in "
                      f"{self.reconnect_delay}s", file=sys.stderr)
                self.close()
                time.sleep(self.reconnect_delay)

    def try_recv(self, timeout):
        if self.sock is None:
            return None
        deadline = time.monotonic() + timeout
        try:
            while b"\n" not in self.buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self.sock.settimeout(remaining)
                try:
                    chunk = self.sock.recv(4096)
                except socket.timeout:
                    return None
                if not chunk:
                    self.close()
                    return None
                self.buffer += chunk
            line, _, self.buffer = self.buffer.partition(b"\n")
            return line
        finally:
            if self.sock is not None:
                try:
                    self.sock.settimeout(None)
                except OSError:
                    pass

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            self.buffer = b""


# ---------- Эмулятор ----------

class Emulator:
    def __init__(self, args):
        self.args = args
        self.sid = args.session_id or str(uuid.uuid4())
        self.sender = self._make_sender()
        self.seq = 0
        self.sent = 0
        self.acks = 0
        self.ack_timeouts = 0
        self.stop = False

    def _make_sender(self) -> SenderBase:
        a = self.args
        if a.mode == "udp":
            return UdpSender(a.host, a.port, a.bind_addr, a.bind_port)
        if a.mode == "tcp":
            return TcpSender(a.host, a.port, a.connect_timeout, a.reconnect_delay)
        raise ValueError(f"unknown mode: {a.mode}")

    def request_stop(self, *_):
        self.stop = True

    def run(self) -> int:
        a = self.args
        interval = 1.0 / a.rate if a.rate > 0 else 0.0
        started_at = time.monotonic()
        next_at = started_at
        next_stats = (started_at + a.stats_interval
                      if a.stats_interval > 0 else float("inf"))

        print(f"[INFO] emulator started: sid={self.sid} mode={a.mode} "
              f"target={a.host}:{a.port} rate={a.rate} msg/s "
              f"{'bidirectional' if a.bidirectional else 'unidirectional'}",
              file=sys.stderr)

        while not self.stop:
            if interval > 0:
                wait = next_at - time.monotonic()
                if wait > 0:
                    time.sleep(min(wait, 0.05))
                    continue

            self.seq += 1
            msg = Message(
                sid=self.sid,
                seq=self.seq,
                ts=time.time(),
                source=a.source,
                payload=make_payload(self.seq, a.padding),
            )
            data = encode(msg)

            if a.dry_run:
                print(data.decode("utf-8").rstrip())
            else:
                self.sender.send(data)
            self.sent += 1

            if a.bidirectional:
                resp = self.sender.try_recv(a.response_timeout)
                if resp:
                    self.acks += 1
                    if a.verbose:
                        print(f"[ACK] seq={self.seq} resp={resp!r}",
                              file=sys.stderr)
                else:
                    self.ack_timeouts += 1
                    if a.verbose:
                        print(f"[TIMEOUT] seq={self.seq}", file=sys.stderr)

            if a.count and self.sent >= a.count:
                break

            if interval > 0:
                next_at += interval
                if next_at < time.monotonic():
                    next_at = time.monotonic()

            if time.monotonic() >= next_stats:
                self._print_stats(started_at)
                next_stats += a.stats_interval

        self._print_stats(started_at, final=True)
        self.sender.close()
        return 0

    def _print_stats(self, started_at, final=False):
        elapsed = max(1e-9, time.monotonic() - started_at)
        parts = [
            f"[{'FINAL' if final else 'STATS'}]",
            f"sent={self.sent}",
            f"elapsed={elapsed:.1f}s",
            f"rate={self.sent / elapsed:.1f} msg/s",
            f"sid={self.sid}",
        ]
        if self.args.bidirectional:
            parts.append(f"acks={self.acks}")
            parts.append(f"timeouts={self.ack_timeouts}")
        print(" ".join(parts), file=sys.stderr)


# ---------- CLI ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Эмулятор источника технологических данных для стенда "
                    "на базе ПК «Синоникс».",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Примеры:\n"
            "  # diode, UDP, 100 msg/s, 60 секунд\n"
            "  python emulator.py --mode udp --host 10.10.10.1 --port 5001 --rate 100 --count 6000\n"
            "  # transport, TCP, с ожиданием ACK\n"
            "  python emulator.py --mode tcp --host 10.10.10.1 --port 5000 --rate 50 --bidirectional\n"
            "  # локальная проверка без комплекса\n"
            "  python emulator.py --mode udp --host 127.0.0.1 --port 5000 --count 5 --dry-run\n"
        ),
    )
    p.add_argument("--mode", choices=["tcp", "udp"], required=True,
                   help="Транспорт: TCP или UDP")
    p.add_argument("--host", required=True,
                   help="Адрес получателя (Узел А или коллектор)")
    p.add_argument("--port", type=int, required=True, help="Порт получателя")

    p.add_argument("--rate", type=float, default=10.0,
                   help="Сообщений в секунду; 0 = максимально быстро")
    p.add_argument("--count", type=int, default=0,
                   help="Сколько сообщений отправить; 0 = бесконечно")
    p.add_argument("--size", type=int, default=0, dest="padding",
                   help="Дополнительный padding payload, байт")
    p.add_argument("--source", default="sensor-sim",
                   help="Идентификатор источника в сообщениях")
    p.add_argument("--session-id", default=None,
                   help="Идентификатор сессии (UUID); по умолчанию — случайный")

    p.add_argument("--bind-addr", default=None, help="Локальный адрес (bind)")
    p.add_argument("--bind-port", type=int, default=0, help="Локальный порт (bind)")

    p.add_argument("--bidirectional", action="store_true",
                   help="Ждать ответ на каждое сообщение (режим «transport»)")
    p.add_argument("--response-timeout", type=float, default=1.0,
                   help="Таймаут ожидания ответа, с")
    p.add_argument("--connect-timeout", type=float, default=5.0,
                   help="Таймаут TCP-подключения, с")
    p.add_argument("--reconnect-delay", type=float, default=1.0,
                   help="Пауза перед переподключением TCP, с")

    p.add_argument("--stats-interval", type=float, default=5.0,
                   help="Период печати статистики, с; 0 = отключить")
    p.add_argument("--dry-run", action="store_true",
                   help="Не отправлять, только печатать сообщения в stdout")
    p.add_argument("--verbose", "-v", action="store_true", help="Подробный вывод")

    return p


def install_signal_handlers(emulator: Emulator) -> None:
    def handler(signum, frame):
        print(f"\n[INFO] received signal {signum}, stopping...", file=sys.stderr)
        emulator.request_stop()
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.padding > 1400 and args.mode == "udp":
        print("[WARN] padding > 1400 при UDP может привести к фрагментации/потерям",
              file=sys.stderr)
    emulator = Emulator(args)
    install_signal_handlers(emulator)
    try:
        return emulator.run()
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    finally:
        emulator.sender.close()


if __name__ == "__main__":
    sys.exit(main())