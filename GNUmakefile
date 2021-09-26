SRCS = $(shell git ls-files '*.go')
PKGS = $(shell go list ./...)
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)
LDFLAGS := -X 'github.com/MaineK00n/vtgen/config.Version=$(VERSION)' \
	-X 'github.com/MaineK00n/vtgen/config.Revision=$(REVISION)'
GO := GO111MODULE=on go
GO_OFF := GO111MODULE=off go

.PHONY: build
build: 
	$(GO) build -ldflags "$(LDFLAGS)" ./cmd/vtgen

.PHONY: install
install: 
	$(GO) install -ldflags "$(LDFLAGS)" ./cmd/vtgen

lint:
	$(GO_OFF) get -u golang.org/x/lint/golint
	golint $(PKGS)

vet:
	echo $(PKGS) | xargs env $(GO) vet || exit;

fmt:
	gofmt -s -w $(SRCS)

pretest: lint vet fmtcheck

test: 
	$(GO) test -cover -v ./... || exit;

cov:
	@ go get -v github.com/axw/gocov/gocov
	@ go get golang.org/x/tools/cmd/cover
	gocov test | gocov report
	
clean:
	$(foreach pkg,$(PKGS),go clean $(pkg) || exit;)

fetch:
	go-cve-dictionary fetch nvd
	go-cve-dictionary fetch jvn
	goval-dictionary fetch debian 8 9 10 11
	goval-dictionary fetch ubuntu 16 18 20
	goval-dictionary fetch redhat 6 7 8
	goval-dictionary fetch oracle
	goval-dictionary fetch amazon
	goval-dictionary fetch alpine 3.2 3.3 3.4 3.5 3.6 3.7 3.8 3.9 3.10 3.11 3.12 3.13 3.14
	gost fetch debian
	gost fetch ubuntu
	gost fetch redhat