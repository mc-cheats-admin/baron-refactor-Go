# Multi-stage build for Go
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install dependencies
COPY go.mod ./
COPY go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Build the application
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o baron-server cmd/server/main.go

# Final stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    mono-devel \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/baron-server .
# Copy templates
COPY --from=builder /app/templates ./templates

# Create builds directory
RUN mkdir builds

# Expose port
EXPOSE 8080

# Command to run
CMD ["./baron-server"]
