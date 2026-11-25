#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modbus TCP эмулятор источника для стенда «Синоникс» (только стандартная библиотека).

Эмулятор работает как Modbus-клиент и САМ записывает показания датчиков в регистры
сервера на стороне коллектора (функция 0x10, Write Multiple Registers). Опроса нет,
поэтому схема подходит для однонаправленной передачи (diode).

Карта регистров (holding registers, адрес с 0, 12 регистров):
  0-1   seq       номер сообщения, uint32 (с 1)
  2-3   ts_sec    время отправки, секунды Unix, uint32
  4     ts_ms     миллисекунды времени отправки, uint16
  5     temperature  °C  x10,  int16
  6     pressure     кПа x10,  int16
  7     vibration    мм/с x1000, uint16
  8     flow         м3/ч x10, uint16
  9     level        %   x10,  uint16
  10-11 sid       идентификатор сессии, uint32 (меняется при перезапуске)

Режимы:
  без --bidirectional  diode: ответы сервера не ждём (fire-and-forget)
  --bidirectional      transport: ждём стандартный ответ Modbus и считаем acks/timeouts

Примеры:
  python3 modbus_emulator.py --host 127.0.0.1 --port 5020 --rate 10 --count 100
  python3 modbus_emulator.py --host 127.0.0.1 --port 5020 --rate 10 --count 100 --bidirectional
"""
import argparse, random, signal, socket, struct, sys, time

NREG = 12


def build_regs(seq, ts, sid):
    sec = int(ts); ms = int((ts - sec) * 1000)
    t = int(round((20.0 + random.uniform(-2, 2)) * 10))
    p = int(round((101.3 + random.uniform(-0.5, 0.5)) * 10))
    vib = int(random.uniform(0, 1) * 1000)
    fl = int(round((50.0 + random.uniform(-5, 5)) * 10))
    lv = int(round((75.0 + random.uniform(-3, 3)) * 10))
    return struct.pack(">IIHhhHHHI", seq, sec, ms, t, p, vib, fl, lv, sid)


def build_frame(tid, unit, regs_bytes):
    # PDU: FC16, start addr 0, quantity, byte count, data
    pdu = struct.pack(">BHHB", 0x10, 0, NREG, len(regs_bytes)) + regs_bytes
    mbap = struct.pack(">HHHB", tid & 0xFFFF, 0, len(pdu) + 1, unit)
    return mbap + pdu


class Client:
    def __init__(self, host, port, connect_timeout, reconnect_delay):
        self.target = (host, port); self.ct = connect_timeout; self.rd = reconnect_delay
        self.sock = None; self.buf = b""

    def _connect(self):
        s = socket.create_connection(self.target, timeout=self.ct)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock = s; self.buf = b""

    def close(self):
        if self.sock:
            try: self.sock.close()
            except OSError: pass
        self.sock = None; self.buf = b""

    def send(self, data):
        while True:
            try:
                if self.sock is None: self._connect()
                self.sock.settimeout(None); self.sock.sendall(data); return
            except OSError as e:
                print(f"[WARN] TCP send error: {e}; reconnecting in {self.rd}s", file=sys.stderr)
                self.close(); time.sleep(self.rd)

    def drain(self):
        """Не копить непрочитанные ответы, когда ответы не ждём."""
        if not self.sock: return
        try:
            self.sock.setblocking(False)
            while self.sock.recv(4096): pass
        except (BlockingIOError, OSError):
            pass

    def recv_response(self, timeout):
        """Прочитать один ответ Modbus TCP. Вернуть PDU или None."""
        if not self.sock: return None
        deadline = time.monotonic() + timeout
        try:
            while True:
                if len(self.buf) >= 7:
                    ln = struct.unpack(">H", self.buf[4:6])[0]
                    if len(self.buf) >= 6 + ln:
                        frame, self.buf = self.buf[:6 + ln], self.buf[6 + ln:]
                        return frame[7:]
                rem = deadline - time.monotonic()
                if rem <= 0: return None
                self.sock.settimeout(rem)
                try: chunk = self.sock.recv(4096)
                except socket.timeout: return None
                if not chunk: self.close(); return None
                self.buf += chunk
        except OSError:
            self.close(); return None


def main(argv=None):
    p = argparse.ArgumentParser(description="Modbus TCP эмулятор источника для стенда «Синоникс».",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--mode", choices=["tcp"], default="tcp", help="только TCP (Modbus TCP)")
    p.add_argument("--host", required=True); p.add_argument("--port", type=int, default=502)
    p.add_argument("--unit", type=int, default=1, help="Modbus unit id")
    p.add_argument("--rate", type=float, default=10.0, help="сообщений в секунду; 0 = быстро")
    p.add_argument("--count", type=int, default=0, help="сколько отправить; 0 = бесконечно")
    p.add_argument("--bidirectional", action="store_true", help="ждать ответ сервера (transport)")
    p.add_argument("--response-timeout", type=float, default=1.0)
    p.add_argument("--connect-timeout", type=float, default=5.0)
    p.add_argument("--reconnect-delay", type=float, default=1.0)
    p.add_argument("--stats-interval", type=float, default=5.0)
    p.add_argument("--session-id", type=lambda x: int(x, 16), default=None, help="sid, hex")
    p.add_argument("--dry-run", action="store_true", help="печатать кадры hex, не отправлять")
    a = p.parse_args(argv)

    sid = a.session_id if a.session_id is not None else random.getrandbits(32)
    sid_s = f"{sid:08x}"
    stop = {"v": False}
    for sg in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sg, lambda *_: stop.update(v=True))
    cl = Client(a.host, a.port, a.connect_timeout, a.reconnect_delay)
    interval = 1.0 / a.rate if a.rate > 0 else 0.0
    sent = acks = tmo = 0; seq = 0
    t0 = time.monotonic(); nxt = t0
    nstat = t0 + a.stats_interval if a.stats_interval > 0 else float("inf")
    print(f"[INFO] modbus emulator started: sid={sid_s} target={a.host}:{a.port} unit={a.unit} "
          f"rate={a.rate} msg/s {'bidirectional' if a.bidirectional else 'unidirectional'}", file=sys.stderr)

    def stats(final=False):
        el = max(1e-9, time.monotonic() - t0)
        s = f"[{'FINAL' if final else 'STATS'}] sent={sent} elapsed={el:.1f}s rate={sent/el:.1f} msg/s sid={sid_s}"
        if a.bidirectional: s += f" acks={acks} timeouts={tmo}"
        print(s, file=sys.stderr)

    while not stop["v"]:
        if interval > 0:
            w = nxt - time.monotonic()
            if w > 0: time.sleep(min(w, 0.05)); continue
        seq += 1
        frame = build_frame(seq, a.unit, build_regs(seq, time.time(), sid))
        if a.dry_run: print(frame.hex())
        else: cl.send(frame)
        sent += 1
        if a.bidirectional and not a.dry_run:
            r = cl.recv_response(a.response_timeout)
            if r and r[0] == 0x10: acks += 1
            else: tmo += 1
        elif not a.dry_run:
            cl.drain()
        if a.count and sent >= a.count: break
        if interval > 0:
            nxt += interval
            if nxt < time.monotonic(): nxt = time.monotonic()
        if time.monotonic() >= nstat: stats(); nstat += a.stats_interval
    stats(True); cl.close(); return 0


if __name__ == "__main__":
    sys.exit(main())
