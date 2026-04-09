# Stage 1: build the custom collector binary
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git curl

# Install ocb (OTel Collector Builder)
RUN curl -Lo /usr/local/bin/ocb \
    https://github.com/open-telemetry/opentelemetry-collector/releases/download/cmd%2Fbuilder%2Fv0.104.0/ocb_0.104.0_linux_amd64 \
    && chmod +x /usr/local/bin/ocb

WORKDIR /build

# Copy processor source
COPY fingerprintprocessor/ ./fingerprintprocessor/

# Copy builder manifest
COPY collector-builder/manifest.yaml ./manifest.yaml

# Build
RUN ocb --config=manifest.yaml

# Stage 2: minimal runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /build/build/otelcol-fingerprint /otelcol-fingerprint

# Baseline files will be mounted at /baseline/
RUN mkdir /baseline

EXPOSE 4317 4318 55679

ENTRYPOINT ["/otelcol-fingerprint"]
CMD ["--config", "/etc/otelcol/config.yaml"]
