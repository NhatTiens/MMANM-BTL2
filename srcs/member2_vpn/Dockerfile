FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 wireguard-tools curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir 'cryptography>=41,<49'
COPY srcs/member2_vpn/ /lab/
WORKDIR /lab
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["sh", "/lab/start.sh"]
