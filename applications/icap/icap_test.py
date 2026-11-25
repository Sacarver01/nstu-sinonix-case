#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тестовый ICAP-клиент: проверяет и заглушку icap_stub.py, и настоящий c-icap.
Только стандартная библиотека.

  python3 icap_test.py make-testfiles                # создать файлы в testfiles/
  python3 icap_test.py options --host 10.0.0.4       # доступность и методы
  python3 icap_test.py scan --host 10.0.0.4 testfiles/clean.txt testfiles/eicar.txt
  python3 icap_test.py suite --host 10.0.0.4 --csv logs/icap_suite.csv   # весь набор

Сервис по умолчанию /avscan (c-icap). Вердикт по ответу сервера:
  204, либо 200 без HTTP 403  -> clean
  200 с X-Infection-Found / HTTP 403 -> blocked
"""
import argparse, csv, os, re, socket, sys, time

EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def recv_all(s, timeout):
    s.settimeout(timeout); data = b""
    try:
        while True:
            c = s.recv(65536)
            if not c: break
            data += c
            if data.startswith(b"ICAP/1.0 204") and b"\r\n\r\n" in data: break
            if b"\r\n\r\n" in data and data.rstrip().endswith(b"0") and b"\r\n0\r\n\r\n" in data: break
            if data.startswith(b"ICAP/1.0 200") and b"null-body=0" in data.split(b"\r\n\r\n")[0] and b"\r\n\r\n" in data: break
    except socket.timeout:
        pass
    return data


def icap(host, port, request, timeout=10):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(request); return recv_all(s, timeout)


def options(a):
    req = f"OPTIONS icap://{a.host}:{a.port}{a.service} ICAP/1.0\r\nHost: {a.host}\r\n\r\n".encode()
    r = icap(a.host, a.port, req).decode("latin1")
    print(r.split("\r\n\r\n")[0] or "(нет ответа)"); return 0 if r.startswith("ICAP/1.0 200") else 1


def scan_file(a, path):
    body = open(path, "rb").read(); name = os.path.basename(path)
    http = (f"PUT /{name} HTTP/1.1\r\nHost: stand\r\nContent-Length: {len(body)}\r\n\r\n").encode()
    chunk = b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
    req = (f"REQMOD icap://{a.host}:{a.port}{a.service} ICAP/1.0\r\nHost: {a.host}\r\nAllow: 204\r\n"
           f"Encapsulated: req-hdr=0, req-body={len(http)}\r\n\r\n").encode() + http + chunk
    t0 = time.time(); r = icap(a.host, a.port, req); ms = round(1000 * (time.time() - t0), 1)
    head = r.split(b"\r\n\r\n")[0].decode("latin1")
    st = (head.split("\r\n")[0] or "нет ответа")
    threat = re.search(r"X-(?:Virus-ID|Infection-Found):\s*(.+)", head)
    if not r: verdict = "ошибка"
    elif st.startswith("ICAP/1.0 204"): verdict = "clean"
    elif threat or b"403 Forbidden" in r: verdict = "blocked"
    elif st.startswith("ICAP/1.0 200"): verdict = "clean"
    else: verdict = "ошибка"
    return {"file": name, "size": len(body), "status": st.replace("ICAP/1.0 ", ""), "verdict": verdict,
            "threat": threat[1].strip() if threat else "", "ms": ms}


def show(rows):
    print(f"{'файл':<22}{'размер':>9}  {'ответ':<16}{'вердикт':<10}{'ms':>7}  угроза")
    for r in rows:
        print(f"{r['file']:<22}{r['size']:>9}  {r['status']:<16}{r['verdict']:<10}{r['ms']:>7}  {r['threat']}")


def make_files(a):
    os.makedirs("testfiles", exist_ok=True)
    files = {"clean.txt": b"telemetry update 1.0\n" * 50, "eicar.txt": EICAR,
             "update.exe": b"MZ not a real program\n", "big.bin": os.urandom(a.big_kb * 1024)}
    for n, d in files.items(): open(os.path.join("testfiles", n), "wb").write(d)
    print("Создано в testfiles/:", ", ".join(f"{n} ({len(d)} Б)" for n, d in files.items()))
    return 0


# ожидания набора: (файл, ожидаемый вердикт, зачем)
SUITE = [("clean.txt", "clean", "чистый файл доставляется"),
         ("eicar.txt", "blocked", "EICAR отклоняется"),
         ("update.exe", "blocked", "запрещённое расширение (если настроено)"),
         ("big.bin", "blocked", "превышен размер (если настроено)")]


def suite(a):
    rows = []; bad = 0
    for f, exp, why in SUITE:
        p = os.path.join("testfiles", f)
        if not os.path.exists(p): sys.exit("Сначала: icap_test.py make-testfiles")
        r = scan_file(a, p); r["expected"] = exp; r["why"] = why
        r["result"] = "OK" if r["verdict"] == exp else "РАСХОЖДЕНИЕ"; bad += r["result"] != "OK"; rows.append(r)
    show(rows); print()
    for r in rows: print(f"{r['file']:<14} ожидалось {r['expected']:<8} факт {r['verdict']:<8} {r['result']}  ({r['why']})")
    if a.csv:
        os.makedirs(os.path.dirname(a.csv) or ".", exist_ok=True)
        with open(a.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
        print("CSV:", a.csv)
    print("\nРасхождения для update.exe и big.bin означают лишь, что сервер не настроен на эти правила;"
          " в антивирусе c-icap такие правила чаще задаёт комплекс.")
    return 1 if any(r["file"] in ("clean.txt", "eicar.txt") and r["result"] != "OK" for r in rows) else 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for n in ("options", "scan", "suite"):
        s = sub.add_parser(n); s.add_argument("--host", default="127.0.0.1")
        s.add_argument("--port", type=int, default=1344); s.add_argument("--service", default="/avscan")
        if n == "scan": s.add_argument("files", nargs="+")
        if n == "suite": s.add_argument("--csv")
    m = sub.add_parser("make-testfiles"); m.add_argument("--big-kb", type=int, default=2048)
    a = p.parse_args()
    if a.cmd == "options": return options(a)
    if a.cmd == "make-testfiles": return make_files(a)
    if a.cmd == "scan": show([scan_file(a, f) for f in a.files]); return 0
    return suite(a)


if __name__ == "__main__":
    sys.exit(main())
