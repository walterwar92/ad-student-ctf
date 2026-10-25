FROM golang:1.23-bookworm AS builder
WORKDIR /source
COPY go.mod ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /server ./cmd/vnekontakta

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && mkdir -p /app/uploads && chown -R 65534:65534 /app/uploads
WORKDIR /app
COPY --from=builder /server /app/server
COPY web /app/web
COPY migrations /app/migrations
ENV PORT=8080 UPLOAD_DIR=/app/uploads WEB_DIR=/app/web PHOTO_WORKER_PATH=/usr/local/bin/photo-worker
EXPOSE 8080
USER 65534:65534
CMD ["/app/server"]
