# syntax=docker/dockerfile:1

# Stage 1 - Build the Go binary
FROM golang:1.24 AS builder
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the app
RUN go build -o server ./cmd/server

# Stage 2 - Use updated Debian with newer GLIBC (2.36)
FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /app/server .
COPY --from=builder /app/.env .env

# Expose port
EXPOSE 8080

# Run the binary
ENTRYPOINT ["./server"]
