# Build:  docker build -t recon .
# Run:    docker run --rm --network host recon 192.168.1.10 -pCT
# SYN scan (needs NET_RAW and root inside the container):
#         docker run --rm --network host --user root --cap-add NET_RAW recon 192.168.1.10 -sS -pCT
# NOTE: "localhost" inside a container is the container itself; use --network host or real addresses.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DRECON_BUILD_TESTS=OFF \
    && cmake --build build -j"$(nproc)" \
    && cmake --install build --prefix /opt/recon

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 recon
COPY --from=build /opt/recon/bin/recon /usr/local/bin/recon
USER recon
ENTRYPOINT ["recon"]
CMD ["--help"]
