FROM golang:1.26.1 AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go generate ./cmd/security
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/audit-exec ./cmd/security

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/audit-exec /audit-exec
EXPOSE 2112
ENTRYPOINT ["/audit-exec"]