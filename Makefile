LOGIN_PROXY_GRPC_HOSTNAME ?= blimp-login-grpc.kelda.io
CLUSTER_MANAGER_HOST ?= blimp-manager.kelda.io:443
VERSION?=latest
MANAGER_CERT_PATH = "./certs/cluster-manager.crt.pem"
LD_FLAGS = "-X github.com/kelda/blimp/pkg/version.Version=${VERSION} \
	   -X github.com/kelda/blimp/cli/manager.ClusterManagerCertBase64=$(shell base64 ${MANAGER_CERT_PATH} | tr -d "\n") \
	   -X github.com/kelda/blimp/cli/login.LoginProxyGRPCHost=${LOGIN_PROXY_GRPC_HOSTNAME} \
	   -X github.com/kelda/blimp/cli/manager.DefaultManagerHost=${CLUSTER_MANAGER_HOST} \
	   -s -w"
SYNCTHING_VERSION=1.4.0
DOCKER_REPO ?= gcr.io/kelda-blimp
DOCKER_IMAGE = ${DOCKER_REPO}/blimp:latest

# Include override variables. The production Makefile takes precendence if it exists.
-include local.mk
-include prod.mk

# Default target for local development.  Just builds binaries for now assumes
# OSX
install: certs build-cli-osx
	mv blimp-osx $(shell go env GOPATH)/bin/cli
	CGO_ENABLED=0 go install -ldflags $(LD_FLAGS) ./...

syncthing-macos:
	curl -L -O https://github.com/syncthing/syncthing/releases/download/v$(SYNCTHING_VERSION)/syncthing-macos-amd64-v$(SYNCTHING_VERSION).tar.gz
	tar -xf syncthing-macos-amd64-v$(SYNCTHING_VERSION).tar.gz
	mv syncthing-macos-amd64-v$(SYNCTHING_VERSION)/syncthing syncthing-macos
	rm -rf syncthing-macos-amd64*

syncthing-linux:
	curl -L -O https://github.com/syncthing/syncthing/releases/download/v$(SYNCTHING_VERSION)/syncthing-linux-amd64-v$(SYNCTHING_VERSION).tar.gz
	tar -xf syncthing-linux-amd64-v$(SYNCTHING_VERSION).tar.gz
	mv syncthing-linux-amd64-v$(SYNCTHING_VERSION)/syncthing syncthing-linux
	rm -rf syncthing-linux-amd64*

syncthing-windows.exe:
	curl -L -O https://github.com/syncthing/syncthing/releases/download/v$(SYNCTHING_VERSION)/syncthing-windows-amd64-v$(SYNCTHING_VERSION).zip
	unzip syncthing-windows-amd64-v$(SYNCTHING_VERSION).zip
	mv syncthing-windows-amd64-v$(SYNCTHING_VERSION)/syncthing.exe syncthing-windows.exe
	rm -rf syncthing-windows-amd64*

go-get:
	go get -u github.com/GeertJohan/go.rice
	go get -u github.com/GeertJohan/go.rice/rice

generate:
	protoc -I _proto _proto/blimp/node/v0/controller.proto --go_out=plugins=grpc:$(shell go env GOPATH)/src
	protoc -I _proto _proto/blimp/cluster/v0/manager.proto --go_out=plugins=grpc:$(shell go env GOPATH)/src
	protoc -I _proto _proto/blimp/login/v0/login.proto --go_out=plugins=grpc:$(shell go env GOPATH)/src
	protoc _proto/blimp/errors/v0/errors.proto --go_out=plugins=grpc:$(shell go env GOPATH)/src

certs:
	./scripts/setup-manager-cert.sh ${MANAGER_CERT_PATH}

build-cli-osx: syncthing-macos certs
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags $(LD_FLAGS) -o blimp-osx ./cli
	cp syncthing-macos ./pkg/syncthing/stbin
	rice append -i ./pkg/syncthing --exec blimp-osx
	rm ./pkg/syncthing/stbin

build-cli-linux: syncthing-linux certs
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags $(LD_FLAGS) -o blimp-linux ./cli
	cp syncthing-linux ./pkg/syncthing/stbin
	rice append -i ./pkg/syncthing --exec blimp-linux
	rm ./pkg/syncthing/stbin

build-cli-windows: syncthing-windows.exe certs
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags $(LD_FLAGS) -o blimp-windows.exe ./cli
	cp syncthing-windows.exe ./pkg/syncthing/stbin
	rice append -i ./pkg/syncthing --exec blimp-windows.exe
	rm ./pkg/syncthing/stbin

build-docker: build-cli-linux
	docker build -t "${DOCKER_IMAGE}" .

push-docker: build-docker
	docker push "${DOCKER_IMAGE}"

lint:
	golangci-lint run

lint-fix:
	golangci-lint run --fix
