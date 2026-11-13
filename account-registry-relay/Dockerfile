# Build from the repository root: docker build -f account-registry-relay/Dockerfile .
FROM rust:1.98.1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p account-registry-relay

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/account-relay /usr/local/bin/account-relay
RUN useradd --system --uid 10001 --home-dir /state relay \
    && mkdir /state && chown relay /state
USER relay
VOLUME /state
ENV ACCOUNT_RELAY_STATE=/state
EXPOSE 8650 9010
ENTRYPOINT ["account-relay"]
