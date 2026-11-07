# Ajar in a container. It must see your real network, so run it with host networking:
#
#   docker build -t ajar .
#   docker run --rm -it --net=host -v ajar-data:/data ajar --set-password      # once: choose the password
#   docker run -d --name ajar --restart unless-stopped --net=host \
#       --cap-add=NET_RAW --cap-add=NET_ADMIN -v ajar-data:/data ajar
#
# Then open https://localhost:8080 (Linux only: host networking isn't available on Docker Desktop
# for Mac or Windows, where the container would only see its own virtual network).
FROM python:3.12-slim

# nmap does the scanning; the rest are the small tools Ajar calls (see the README requirements).
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap openssl iproute2 iputils-ping net-tools snmp iw \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ajar.py ./
COPY aj ./aj
COPY web ./web

# Settings, the database, the password hashes and the HTTPS certificate all live here.
ENV AJAR_DATA=/data
VOLUME /data

EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
  CMD python3 -c "import socket; socket.create_connection(('127.0.0.1', 8080), 4).close()" || exit 1

ENTRYPOINT ["python3", "ajar.py"]
