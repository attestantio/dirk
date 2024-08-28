FROM golang:1.22-bookworm as builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build

FROM debian:bookworm-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt install -y ca-certificates && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/dirk /app

ENTRYPOINT ["/app/dirk"]
