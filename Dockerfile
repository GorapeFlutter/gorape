FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /gorape ./cmd/server

FROM alpine:3.21
RUN addgroup -S gorape && adduser -S -G gorape gorape
WORKDIR /app
COPY --from=builder /gorape /usr/local/bin/gorape
USER gorape
EXPOSE 8000
ENTRYPOINT ["gorape"]
CMD ["-config", "/app/etc/server.yaml"]
