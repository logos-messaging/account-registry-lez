# Build from the repository root: docker build -f account-registry-relay/Dockerfile .
FROM rust:1.98.1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p account-registry-relay --bin account-relay \
    && cp target/release/account-relay /usr/local/bin/account-relay

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="account-relay" \
      org.opencontainers.image.description="Publishes new Logos accounts' signed logs to the LEZ account registry, paying the fee" \
      org.opencontainers.image.source="https://github.com/logos-messaging/account-registry-lez"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/account-relay /usr/local/bin/account-relay
RUN useradd --system --uid 10001 --home-dir /state relay \
    && mkdir /state && chown relay /state
USER relay
VOLUME /state
ENV ACCOUNT_RELAY_STATE=/state \
    ACCOUNT_RELAY_P2P=/ip4/0.0.0.0/tcp/9010 \
    ACCOUNT_RELAY_METRICS=0.0.0.0:9464
EXPOSE 9010/tcp 9464/tcp
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s \
    CMD curl -fsS http://127.0.0.1:9464/metrics > /dev/null || exit 1
ENTRYPOINT ["tini", "--", "account-relay"]
