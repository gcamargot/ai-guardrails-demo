# syntax=docker/dockerfile:1

FROM golang:1.25.7-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/coffee-station ./cmd/coffee-station
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/smoke ./cmd/smoke
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/calendar ./cmd/calendar
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/telegram-adapter ./cmd/telegram-adapter
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/qwen-simulator ./cmd/qwen-simulator
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/approval-authority ./cmd/approval-authority
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/outlook ./cmd/outlook
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/smart-lock ./cmd/smart-lock
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/audit ./cmd/audit
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/development-repository ./cmd/development-repository
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/oauth-facade ./cmd/oauth-facade

FROM alpine:3.22
RUN addgroup -g 10001 -S app && adduser -u 10001 -S -G app app
COPY --from=build /out /app
USER app
