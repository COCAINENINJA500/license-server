# 多阶段构建: 静态编译 → distroless 运行镜像(非 root,无 shell)
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo docker)" \
    -o /out/license-server ./cmd/license-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/license-server /license-server
WORKDIR /data
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/license-server"]
CMD ["--db", "/data/licenses.db", "--addr", ":8080"]
