# One image for every lab role: the diagnostic client, the routers and the broken servers.
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      dnsutils iputils-ping traceroute mtr-tiny nmap openssl curl tcpdump \
      iproute2 iptables ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app
RUN printf '#!/bin/sh\nexec python -m nettriage "$@"\n' > /usr/local/bin/nettriage && chmod +x /usr/local/bin/nettriage
WORKDIR /lab
