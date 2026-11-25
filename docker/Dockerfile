# ICAP-сервер для стенда: c-icap + ClamAV на Debian 12.
# НЕ ПРОВЕРЕНО в песочнице (там нет Docker): первая сборка может потребовать правок.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      c-icap libc-icap-mod-virus-scan clamav-daemon clamav-freshclam ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Подпись EICAR по MD5: ClamAV находит тестовый файл и без интернета и без загрузки баз
COPY eicar.hdb /var/lib/clamav/eicar.hdb
COPY virus_scan.conf /etc/c-icap/virus_scan.conf
COPY clamd_mod.conf /etc/c-icap/clamd_mod.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 1344
ENTRYPOINT ["/entrypoint.sh"]
