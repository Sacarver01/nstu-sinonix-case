#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Прогон испытаний телеметрии: обёртка над collector.py и telemetry_emulator.py.
Логи называются по номеру пункта ПМИ (--id).

На стенде коллектор и эмулятор работают на разных ВМ, поэтому три шага:

  1) на коллекторе (корпоративный сегмент):
       python3 run_test.py collector --id 1_1_forward --mode udp --port 5001
     остановить Ctrl+C ПОСЛЕ завершения эмулятора
  2) на эмуляторе (технологический сегмент):
       python3 run_test.py emulator --id 1_1_forward --mode udp \
           --host <адрес> --port 5001 --rate 100 --count 6000
  3) скопировать оба лога в одну папку и посчитать:
       python3 run_test.py report --id 1_1_forward --max-loss 1.0

Для Modbus добавьте --proto modbus (порт, например, 5020; режим только TCP):
       python3 run_test.py local --id selftest_mb --proto modbus --port 5020

Проверка без стенда (всё на localhost):
       python3 run_test.py local --id selftest --mode udp --count 300 --rate 100

Потери считаются как «отправлено (эмулятор) минус получено (коллектор)»:
так видны и потери в хвосте потока, которые собственная сводка коллектора не замечает.
"""
import argparse, csv, json, os, re, signal, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
LOGS = "logs"


def log_path(test_id, kind, ext="txt"):
    os.makedirs(LOGS, exist_ok=True)
    return os.path.join(LOGS, f"{test_id}_{kind}.{ext}")


def run_tee(cmd, out_file, on_interrupt=signal.SIGINT):
    """Запустить процесс, дублировать его stderr на экран и в файл."""
    p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL,
                         text=True, bufsize=1)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("# " + " ".join(cmd) + "\n")
        try:
            for line in p.stderr:
                sys.stderr.write(line); f.write(line)
        except KeyboardInterrupt:
            p.send_signal(on_interrupt)
            for line in p.stderr:
                sys.stderr.write(line); f.write(line)
    p.wait()
    return p.returncode


def script(a, kind):
    if getattr(a, "proto", "json") == "modbus":
        return os.path.join(HERE, f"modbus_{kind}.py")
    return os.path.join(HERE, "collector.py" if kind == "collector" else "telemetry_emulator.py")


def collector_cmd(a):
    c = [sys.executable, script(a, "collector"), "--mode", a.mode,
         "--port", str(a.port), "--csv", log_path(a.id, "collector", "csv")]
    if a.bidirectional:
        c.append("--bidirectional")
    return c


def emulator_cmd(a):
    c = [sys.executable, script(a, "emulator"), "--mode", a.mode,
         "--host", a.host, "--port", str(a.port), "--rate", str(a.rate),
         "--count", str(a.count), "--stats-interval", "0"]
    if a.bidirectional:
        c.append("--bidirectional")
    return c


def cmd_collector(a):
    print(f"[run_test] коллектор, лог: {log_path(a.id, 'collector')}", file=sys.stderr)
    return run_tee(collector_cmd(a), log_path(a.id, "collector"))


def cmd_emulator(a):
    print(f"[run_test] эмулятор, лог: {log_path(a.id, 'emulator')}", file=sys.stderr)
    return run_tee(emulator_cmd(a), log_path(a.id, "emulator"))


def parse_emulator(path):
    txt = open(path, encoding="utf-8").read()
    m = re.search(r"\[FINAL\] sent=(\d+).*?sid=(\S+)(?: acks=(\d+) timeouts=(\d+))?", txt)
    if not m:
        sys.exit(f"В {path} нет строки [FINAL]: эмулятор не завершился штатно.")
    return {"sent": int(m[1]), "sid": m[2],
            "acks": int(m[3]) if m[3] else None, "timeouts": int(m[4]) if m[4] else None}


def parse_collector(path, sid):
    best = None
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line.startswith("{") and '"sid"' in line:
            d = json.loads(line)
            if d["sid"] == sid:
                return d
            best = d
    return None


def cmd_report(a):
    em = parse_emulator(log_path(a.id, "emulator"))
    co = parse_collector(log_path(a.id, "collector"), em["sid"])
    if co is None:
        print("[!] В логе коллектора нет сводки: остановите коллектор по Ctrl+C и запустите report снова.",
              file=sys.stderr)
    received = co["received"] if co else 0
    lost = em["sent"] - received
    loss_pct = round(100.0 * lost / em["sent"], 3) if em["sent"] else 0.0
    ok = loss_pct <= a.max_loss
    res = {"test_id": a.id, "sid": em["sid"], "sent": em["sent"], "received": received,
           "lost": lost, "loss_pct": loss_pct, "max_loss_pct": a.max_loss,
           "verdict": "соответствует" if ok else "не соответствует",
           "latency_avg_ms": co["latency_avg_ms"] if co else None,
           "latency_max_ms": co["latency_max_ms"] if co else None,
           "latency_p95_ms": co["latency_p95_ms"] if co else None,
           "out_of_order": co["out_of_order"] if co else None,
           "acks": em["acks"], "ack_timeouts": em["timeouts"]}
    json.dump(res, open(log_path(a.id, "result", "json"), "w"), ensure_ascii=False, indent=2)
    with open(log_path(a.id, "result", "csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(res.keys()); w.writerow(res.values())
    print(f"\n=== Результат {a.id} ===")
    print(f"Отправлено (эмулятор):  {res['sent']}")
    print(f"Получено (коллектор):   {res['received']}")
    print(f"Потери:                 {lost} ({loss_pct} %), допустимо {a.max_loss} %")
    print(f"Задержка, мс:           ср. {res['latency_avg_ms']}, макс. {res['latency_max_ms']}, p95 {res['latency_p95_ms']}")
    print("  (задержка осмыслена только при синхронизированных часах узлов)")
    if em["acks"] is not None:
        print(f"Ответы (ack):           получено {em['acks']}, таймаутов {em['timeouts']}")
        if em["acks"] == 0 and em["timeouts"]:
            print("Обратный канал:         ответы НЕ прошли (подтвердить дампами tcpdump/Wireshark)")
        elif em["acks"]:
            print("Обратный канал:         ответы прошли, обратный канал работает")
    print(f"Вывод:                  {res['verdict']}")
    print(f"Файлы: {log_path(a.id, 'result', 'json')}, {log_path(a.id, 'result', 'csv')}")
    return 0


def cmd_local(a):
    a.host = "127.0.0.1"
    col = subprocess.Popen(collector_cmd(a), stderr=open(log_path(a.id, "collector"), "w"),
                           stdout=subprocess.DEVNULL)
    time.sleep(1)
    run_tee(emulator_cmd(a), log_path(a.id, "emulator"))
    time.sleep(0.5)
    col.send_signal(signal.SIGTERM); col.wait()
    return cmd_report(a)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    def common(s, host=False):
        s.add_argument("--id", required=True, help="номер пункта ПМИ, например 1_1_forward")
        if s.prog.split()[-1] != "report":
            s.add_argument("--proto", choices=["json", "modbus"], default="json",
                           help="json: collector.py/telemetry_emulator.py; modbus: modbus_*.py (только TCP)")
            s.add_argument("--mode", choices=["tcp", "udp"], default="tcp")
            s.add_argument("--port", type=int, required=True)
            s.add_argument("--bidirectional", action="store_true")
        if host:
            s.add_argument("--host", required=True)
            s.add_argument("--rate", type=float, default=10.0)
            s.add_argument("--count", type=int, required=True)
    s1 = sub.add_parser("collector"); common(s1); s1.set_defaults(f=cmd_collector)
    s2 = sub.add_parser("emulator"); common(s2, True); s2.set_defaults(f=cmd_emulator)
    s3 = sub.add_parser("report"); common(s3)
    s3.add_argument("--max-loss", type=float, default=1.0, help="допустимые потери, %% (допущение, уточнить в ПМИ)")
    s3.set_defaults(f=cmd_report)
    s4 = sub.add_parser("local"); common(s4)
    s4.add_argument("--rate", type=float, default=100.0); s4.add_argument("--count", type=int, default=300)
    s4.add_argument("--max-loss", type=float, default=1.0); s4.set_defaults(f=cmd_local)
    a = p.parse_args()
    return a.f(a)


if __name__ == "__main__":
    sys.exit(main())
