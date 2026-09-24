GO ?= go
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
export GOOS GOARCH

DIST_DIR ?= dist
LDFLAGS ?= -s -w
BUILD_FLAGS := -trimpath -ldflags="$(LDFLAGS)"
BINARY = $(DIST_DIR)/sshfw$(if $(filter windows,$(GOOS)),.exe,)
ARCHIVE = $(DIST_DIR)/sshfw-$(GOOS)-$(GOARCH).tar.gz

.PHONY: all build install test test-race vet check fmt build-windows build-linux build-darwin build-all clean

all: build

build:
	@mkdir -p $(DIST_DIR)
	$(GO) build $(BUILD_FLAGS) -o $(BINARY) .

install:
	$(GO) install $(BUILD_FLAGS) .

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

check: test vet

fmt:
	$(GO) fmt ./...

build-windows: GOOS=windows
build-windows: GOARCH=amd64
build-windows:
	@mkdir -p $(DIST_DIR)
	$(GO) build $(BUILD_FLAGS) -o $(BINARY) .
	tar -czf $(ARCHIVE) -C $(DIST_DIR) $(notdir $(BINARY))

build-linux: GOOS=linux
build-linux: GOARCH=amd64
build-linux:
	@mkdir -p $(DIST_DIR)
	$(GO) build $(BUILD_FLAGS) -o $(BINARY) .
	tar -czf $(ARCHIVE) -C $(DIST_DIR) $(notdir $(BINARY))

build-darwin: GOOS=darwin
build-darwin: GOARCH=amd64
build-darwin:
	@mkdir -p $(DIST_DIR)
	$(GO) build $(BUILD_FLAGS) -o $(BINARY) .
	tar -czf $(ARCHIVE) -C $(DIST_DIR) $(notdir $(BINARY))

build-all: build-windows build-linux build-darwin

clean:
	$(RM) -r $(DIST_DIR)
