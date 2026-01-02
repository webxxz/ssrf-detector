# Multi-stage build for minimal image size
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN make build

# Final stage
FROM alpine:latest

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 scanner && \
    adduser -D -u 1000 -G scanner scanner

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/build/ssrfdetect /app/ssrfdetect

# Copy config examples
COPY configs/docker-config.yaml /app/config.yaml

# Set ownership
RUN chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Expose OOB server port
EXPOSE 8080

ENTRYPOINT ["/app/ssrfdetect"]
CMD ["--help"]