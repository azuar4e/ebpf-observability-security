FROM golang:1.26.1 AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go generate ./cmd/metrics
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/metrics-agent ./cmd/metrics

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/metrics-agent /metrics-agent
EXPOSE 2112
ENTRYPOINT ["/metrics-agent"]