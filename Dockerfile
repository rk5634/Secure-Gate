# Stage 1 - Build
FROM golang:1.24 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -v -ldflags="-s -w" -o server ./cmd/server

# Stage 2 - Production image
FROM debian:bookworm-slim

WORKDIR /app

# Install CA certs
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -u 10001 -m appuser

# Copy only necessary files
COPY --from=builder /app/server .
# COPY --from=builder /app/private.key private.key
# COPY --from=builder /app/public.key public.key

USER appuser

EXPOSE 8080
ENTRYPOINT ["./server"]
