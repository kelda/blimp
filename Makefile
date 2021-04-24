CLUSTER_MANAGER_HOST ?= blimp-manager.kelda.io:443
SYNCTHING_VERSION=1.10.0
DOCKER_REPO ?= keldaio
REGISTRY_HOSTNAME ?= blimp-registry.kelda.io
LINK_PROXY_BASE_HOSTNAME ?= blimp.dev
# Only needs to be set during local development if the manager is being
# deployed to a remote cluster.
CLUSTER_MANAGER_IP ?= 8.8.8.8
CLUSTER_MANAGER_HTTP_API_IP ?= 35.247.75.232
CLUSTER_MANAGER_HTTP_API_HOSTNAME ?= blimp-manager-api.kelda.io
REGISTRY_IP ?= 8.8.8.8
REGISTRY_STORAGE ?= "5Gi"
VERSION?=latest
MANAGER_KEY_PATH = "./certs/cluster-manager.key.pem"
MANAGER_CERT_PATH = "./certs/cluster-manager.crt.pem"

# Note that main.LinkProxyBaseHostname refers to a variable in
# cluster-controller/main.go and link-proxy/main.go.
LD_FLAGS = "-X github.com/kelda/blimp/pkg/version.Version=${VERSION} \
	   -X github.com/kelda/blimp/pkg/version.CLIImage=${CLI_IMAGE} \
	   -X github.com/kelda/blimp/pkg/version.DNSImage=${DNS_IMAGE} \
	   -X github.com/kelda/blimp/pkg/version.InitImage=${INIT_IMAGE} \
	   -X github.com/kelda/blimp/pkg/version.NodeControllerImage=${NODE_CONTROLLER_IMAGE} \
	   -X github.com/kelda/blimp/pkg/version.ReservationImage=${RESERVATION_IMAGE} \
	   -X github.com/kelda/blimp/pkg/version.SyncthingImage=${SYNCTHING_IMAGE} \
	   -X main.RegistryHostname=${REGISTRY_HOSTNAME} \
	   -X main.LinkProxyBaseHostname=${LINK_PROXY_BASE_HOSTNAME} \
	   -s -w"

# Include override variables. The production Makefile takes precendence if it exists.
-include local.mk
-include prod.mk

# Default target for local development.  Just builds binaries for now assumes
# OSX
install: certs build-cli-osx
	mv blimp-osx $(shell go env GOPATH)/bin/cli
	CGO_ENABLED=0 go install -ldflags $(LD_FLAGS) ./...

syncthing-macos:
	curl -L -O https://github.com/syncthing/syncthing/releases/download/v$(SYNCTHING_VERSION)/syncthing-macos-amd64-v$(SYNCTHING_VERSION).zip
	unzip syncthing-macos-amd64-v$(SYNCTHING_VERSION).zip
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
	protoc _proto/blimp/auth/v0/auth.proto --go_out=plugins=grpc:$(shell go env GOPATH)/src
	protoc _proto/blimp/errors/v0/errors.proto --go_out=plugins=grpc:$(shell go env GOPATH)/src
	protoc -I _proto _proto/blimp/wait/v0/wait.proto  --go_out=plugins=grpc:$(shell go env GOPATH)/src

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

certs:
	./scripts/make-manager-cert.sh ${MANAGER_CERT_PATH} ${MANAGER_KEY_PATH} ${CLUSTER_MANAGER_IP}

run-cluster-controller: certs
	go run -ldflags $(LD_FLAGS) ./cluster-controller -tls-cert ${MANAGER_CERT_PATH} -tls-key ${MANAGER_KEY_PATH}

build-circle-image:
	docker build -f .circleci/Dockerfile . -t keldaio/circleci-blimp

test:
	go test ./...

# The CLI and cluster controller images aren't kept in sync, so we just deploy
# `latest`.
CLI_IMAGE = ${DOCKER_REPO}/blimp:latest
CLUSTER_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-cluster-controller:${VERSION}
DNS_IMAGE = ${DOCKER_REPO}/blimp-dns:${VERSION}
DOCKER_AUTH_IMAGE = ${DOCKER_REPO}/blimp-docker-auth:${VERSION}
INIT_IMAGE = ${DOCKER_REPO}/blimp-init:${VERSION}
LINK_PROXY_IMAGE = ${DOCKER_REPO}/link-proxy:${VERSION}
NODE_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-node-controller:${VERSION}
RESERVATION_IMAGE = ${DOCKER_REPO}/sandbox-reservation:${VERSION}
SYNCTHING_IMAGE = ${DOCKER_REPO}/sandbox-syncthing:${VERSION}

build-docker: certs
	# Exit if the base container fails to build.
	docker build -t blimp-go-build --build-arg COMPILE_FLAGS=${LD_FLAGS} .

	docker build -t sandbox-syncthing -t ${SYNCTHING_IMAGE} -f ./sandbox/syncthing/Dockerfile . & \
	docker build -t blimp-cluster-controller -t ${CLUSTER_CONTROLLER_IMAGE} - < ./cluster-controller/Dockerfile & \
	docker build -t blimp-node-controller -t ${NODE_CONTROLLER_IMAGE} - < ./node/Dockerfile & \
	docker build -t blimp-dns -t ${DNS_IMAGE} - < ./sandbox/dns/Dockerfile & \
	docker build -t blimp-init -t ${INIT_IMAGE} - < ./sandbox/init/Dockerfile & \
	docker build -t blimp-docker-auth -t ${DOCKER_AUTH_IMAGE} - < ./registry/Dockerfile & \
	docker build -t sandbox-reservation -t ${RESERVATION_IMAGE} - < ./sandbox/reservation/Dockerfile & \
	docker build -t link-proxy -t ${LINK_PROXY_IMAGE} - < ./link-proxy/Dockerfile & \
	wait # Wait for all background jobs to exit before continuing so that we can guarantee the images are built.

push-docker: build-docker
	docker push ${NODE_CONTROLLER_IMAGE} ;
	docker push ${CLUSTER_CONTROLLER_IMAGE} & \
	docker push ${DNS_IMAGE} & \
	docker push ${SYNCTHING_IMAGE} & \
	docker push ${INIT_IMAGE} & \
	docker push ${DOCKER_AUTH_IMAGE} & \
	docker push ${RESERVATION_IMAGE} & \
	docker push ${LINK_PROXY_IMAGE} & \
	wait # Wait for all background jobs to exit before continuing so that we can guarantee the images are pushed.

lint:
	golangci-lint run

lint-fix:
	golangci-lint run --fix
