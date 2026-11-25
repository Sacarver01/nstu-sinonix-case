# Телеметрия

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