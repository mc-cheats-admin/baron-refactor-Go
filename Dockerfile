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
    wget \
    && wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y dotnet-sdk-8.0 \
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
