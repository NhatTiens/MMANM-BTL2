FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends suricata iproute2 procps python3 python3-yaml && rm -rf /var/lib/apt/lists/*
COPY srcs/member3_ids/start.sh /start.sh
COPY srcs/member3_ids/sensor_config.py /sensor_config.py
ENTRYPOINT ["sh", "/start.sh"]
