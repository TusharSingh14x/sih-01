FROM rust:1.88-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY compiler ./compiler
COPY stdlib ./stdlib
COPY agent ./agent
RUN cargo build --release -p jocky-agent

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/jocky-agent /usr/local/bin/jocky-agent
CMD ["jocky-agent"]
