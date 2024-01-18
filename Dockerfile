FROM golang:1.20-bookworm as builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/dirk /app

ENTRYPOINT ["/app/dirk"]
