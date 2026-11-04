BINARY  := license-server
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet lint run clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/license-server

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

run:
	go run ./cmd/license-server

clean:
	rm -f $(BINARY) licenses.db licenses.db-shm licenses.db-wal
