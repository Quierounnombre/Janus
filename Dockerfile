FROM golang:1.26 AS builder

WORKDIR /build
COPY go.mod go.sum ./
COPY . ./
RUN go mod download
RUN ls -la templates/

RUN CGO_ENABLED=1 GOOS=linux go build -o /build/auth -ldflags="-s -w"

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y ca-certificates

WORKDIR /app
COPY --from=builder /build/auth ./
COPY --from=builder /build/config.yaml ./
CMD ["./auth"]
