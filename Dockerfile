# Build a static (musl) opseclint binary, then ship it in a scratch image.
# opseclint makes no network calls of its own — it only reads the files it
# analyzes — so no shell or CA certificates are needed in the final image.

FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY . .
RUN cargo build --release --locked

FROM scratch
COPY --from=builder /build/target/release/opseclint /opseclint
ENTRYPOINT ["/opseclint"]
