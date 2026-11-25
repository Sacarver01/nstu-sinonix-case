# ICAP-сервер стенда (c-icap + ClamAV)

Запуск на ВМ 10.0.0.4:
    docker compose up --build -d
    docker compose logs -f

Проверка (с любой машины корпоративного сегмента):
    python3 ../icap/icap_test.py make-testfiles
    python3 ../icap/icap_test.py options --host 10.0.0.4
    python3 ../icap/icap_test.py suite --host 10.0.0.4 --csv logs/icap_suite.csv

Ожидаемо: clean.txt -> 204 (clean), eicar.txt -> blocked.
Если сервис называется иначе, укажите --service (по умолчанию /avscan).

Нужно сверить с документацией комплекса: какой метод ICAP он использует (REQMOD или RESPMOD),
имя сервиса, порт и как он трактует 204 / 403.
