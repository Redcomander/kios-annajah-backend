FROM golang:1.25-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o kasir-backend .

FROM alpine:3.20
WORKDIR /app

RUN adduser -D -u 10001 appuser
USER appuser

COPY --from=builder /app/kasir-backend /app/kasir-backend

EXPOSE 3000
CMD ["/app/kasir-backend"]
