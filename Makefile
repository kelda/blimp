LOGIN_PROXY_HOSTNAME ?= blimp-login.kelda.io
CLUSTER_MANAGER_HOST ?= blimp-manager.kelda.io:443
VERSION?=latest
MANAGER_CERT_PATH = "./certs/cluster-manager.crt.pem"
LD_FLAGS = "-X github.com/kelda/blimp/pkg/version.Version=${VERSION} \
	   -X github.com/kelda/blimp/cli/manager.ClusterManagerCertBase64=$(shell base64 ${MANAGER_CERT_PATH} | tr -d "\n") \
	   -X github.com/kelda/blimp/cli/login.LoginProxyHost=${LOGIN_PROXY_HOSTNAME} \
	   -X github.com/kelda/blimp/cli/manager.DefaultManagerHost=${CLUSTER_MANAGER_HOST} \
	   -s -w"

# Include override variables. The production Makefile takes precendence if it exists.
-include local.mk
-include prod.mk

# Default target for local development.  Just builds binaries for now assumes
# OSX
install: certs build-cli-osx
	mv blimp-osx $(GOPATH)/bin/cli
	CGO_ENABLED=0 go install -ldflags $(LD_FLAGS) ./...

syncthing-macos:
	curl -L -O https://github.com/syncthing/syncthing/releases/download/v1.4.0/syncthing-macos-amd64-v1.4.0.tar.gz
	tar -xf syncthing*.tar.gz
	mv syncthing-macos-amd64-v1.4.0/syncthing syncthing-macos
	rm -rf syncthing-macos-amd64*

syncthing-linux:
	curl -L -O https://github.com/syncthing/syncthing/releases/download/v1.4.0/syncthing-linux-amd64-v1.4.0.tar.gz
	tar -xf syncthing*.tar.gz
	mv syncthing-linux-amd64-v1.4.0/syncthing syncthing-linux
	rm -rf syncthing-linux-amd64*

go-get:
	go get -u github.com/GeertJohan/go.rice
	go get -u github.com/GeertJohan/go.rice/rice

generate:
	protoc -I _proto _proto/blimp/node/v0/controller.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc -I _proto _proto/blimp/cluster/v0/manager.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc -I _proto _proto/blimp/login/v0/login.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc _proto/blimp/errors/v0/errors.proto --go_out=plugins=grpc:$$GOPATH/src

certs:
	./scripts/setup-manager-cert.sh ${MANAGER_CERT_PATH}

build-cli-linux: syncthing-linux certs
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags $(LD_FLAGS) -o blimp-linux ./cli
	cp syncthing-linux ./pkg/syncthing/stbin
	rice append -i ./pkg/syncthing --exec blimp-linux
	rm ./pkg/syncthing/stbin

build-cli-osx: syncthing-macos certs
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags $(LD_FLAGS) -o blimp-osx ./cli
	cp syncthing-macos ./pkg/syncthing/stbin
	rice append -i ./pkg/syncthing --exec blimp-osx
	rm ./pkg/syncthing/stbin

lint:
	golangci-lint run

lint-fix:
	golangci-lint run --fix
