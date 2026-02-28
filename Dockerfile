FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o trivy-pdf main.go

FROM alpine:latest
COPY --from=builder /app/trivy-pdf /usr/local/bin/trivy-pdf
ENTRYPOINT ["trivy-pdf"]
