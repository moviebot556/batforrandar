# Build stage
FROM golang:alpine AS builder

WORKDIR /app

# Copy all project files
COPY . .

# Ensure dependencies are tidied and resolved
RUN go mod tidy

# Compile statically linked single binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o btcscanner main.go

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install CA certificates for Telegram HTTPS alerts
RUN apk --no-cache add ca-certificates tzdata

# Copy binary and address list
COPY --from=builder /app/btcscanner /app/btcscanner
COPY --from=builder /app/addresses.txt /app/addresses.txt

ENV PORT=8080 \
    WORKERS=2 \
    MAX_VCPU=1.9 \
    PUZZLE_BITS=66 \
    ADDRESSES_FILE=addresses.txt \
    TELEGRAM_BOT_TOKEN=8112140789:AAFs2PiS3b0rfNfVwkBnDth3ikrN2Uacq48 \
    TELEGRAM_CHAT_ID=769770980

EXPOSE 8080

CMD ["/app/btcscanner"]