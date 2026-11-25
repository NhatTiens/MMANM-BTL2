FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables wireguard-tools python3 curl ca-certificates iputils-ping && rm -rf /var/lib/apt/lists/*
COPY srcs/member1_firewall/ /lab/firewall/
COPY srcs/member2_vpn/wireguard/ /lab/vpn/
CMD ["sh", "/lab/firewall/start.sh"]
