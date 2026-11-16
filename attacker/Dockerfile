FROM alpine:latest
RUN apk add --no-cache gcc musl-dev iptables bpftrace iproute2 procps
WORKDIR /poc
COPY noisytcp.c /poc/
COPY *.bt /poc/
RUN gcc -O2 -pthread -Wall -Wextra -o noisytcp noisytcp.c
ENTRYPOINT ["/bin/sh"]
CMD ["-c", "tail -f /dev/null"]
