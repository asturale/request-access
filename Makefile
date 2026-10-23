VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build dist test e2e

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/request-access ./cmd/request-access

dist:
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/request-access-linux-$$arch ./cmd/request-access; \
	done
	cd dist && sha256sum request-access-linux-* > SHA256SUMS

test:
	go vet ./...
	go test ./...

# Worker unit tests + end-to-end tests of the binary against the Worker
# in Miniflare (needs Node 20+; Miniflare does not run on musl/Alpine).
e2e:
	CGO_ENABLED=0 go build -o worker/test/bin/request-access ./cmd/request-access
	cd worker && npm ci && npm test
