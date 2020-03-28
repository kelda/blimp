DOCKER_REPO = ${BLIMP_DOCKER_REPO}
REGISTRY_HOSTNAME ?= blimp-registry.kelda.io
REGISTRY_IP ?= 8.8.8.8
#VERSION?=$(shell ./scripts/dev_version.sh)
VERSION?=latest
MANAGER_KEY_PATH = "./certs/cluster-manager.key.pem"
MANAGER_CERT_PATH = "./certs/cluster-manager.crt.pem"
LD_FLAGS = "-X github.com/kelda-inc/blimp/pkg/version.Version=${VERSION} \
	   -X github.com/kelda-inc/blimp/pkg/version.SandboxControllerImage=${SANDBOX_CONTROLLER_IMAGE} \
	   -X github.com/kelda-inc/blimp/pkg/version.BootWaiterImage=${BOOT_WAITER_IMAGE} \
	   -X github.com/kelda-inc/blimp/pkg/version.SyncthingImage=${SYNCTHING_IMAGE} \
	   -X github.com/kelda-inc/blimp/pkg/auth.ClusterManagerCertBase64=$(shell base64 ${MANAGER_CERT_PATH}) \
	   -X main.RegistryHostname=${REGISTRY_HOSTNAME}"

# Include all .mk files so you can have your own local configurations
include $(wildcard *.mk)

# Default target for local development.  Just builds binaries for now assumes
# OSX
install: certs build-cli-osx
	mv blimp-osx $(GOPATH)/bin/cli
	CGO_ENABLED=0 go install -ldflags $(LD_FLAGS) \
		    ./cluster-controller \
		    ./sandbox-controller \
		    ./registry \
		    ./boot-waiter \
		    ./sandbox-syncthing

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
	protoc -I _proto _proto/blimp/sandbox/v0/controller.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc -I _proto _proto/blimp/sandbox/v0/waiter.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc -I _proto _proto/blimp/cluster/v0/manager.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc _proto/blimp/errors/v0/errors.proto --go_out=plugins=grpc:$$GOPATH/src

certs:
	mkdir certs
	openssl req \
		-x509 \
		-newkey rsa:4096 \
		-keyout ${MANAGER_KEY_PATH} \
		-out ${MANAGER_CERT_PATH} \
		-days 365 \
		-nodes \
		-subj "/C=US/ST=California/L=Berkeley/O=Kelda Inc/OU=Kelda Blimp Manager/CN=localhost"

build-cli-linux: syncthing-linux
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags $(LD_FLAGS) -o blimp-linux ./cli
	cp syncthing-linux ./pkg/syncthing/stbin
	rice append -i ./pkg/syncthing --exec blimp-linux
	rm ./pkg/syncthing/stbin

build-cli-osx: syncthing-macos
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags $(LD_FLAGS) -o blimp-osx ./cli
	cp syncthing-macos ./pkg/syncthing/stbin
	rice append -i ./pkg/syncthing --exec blimp-osx
	rm ./pkg/syncthing/stbin

run-cluster-controller: certs
	go run -ldflags $(LD_FLAGS) ./cluster-controller -tls-cert ${MANAGER_CERT_PATH} -tls-key ${MANAGER_KEY_PATH}

build-circle-image:
	docker build -f .circleci/Dockerfile . -t keldaio/circleci-blimp

SANDBOX_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-sandbox-controller:${VERSION}
CLUSTER_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-cluster-controller:${VERSION}
BOOT_WAITER_IMAGE = ${DOCKER_REPO}/blimp-boot-waiter:${VERSION}
SYNCTHING_IMAGE = ${DOCKER_REPO}/sandbox-syncthing:${VERSION}
DOCKER_AUTH_IMAGE = ${DOCKER_REPO}/blimp-docker-auth:${VERSION}

build-docker:
	docker build -t blimp-go-build --build-arg COMPILE_FLAGS=${LD_FLAGS} .
	docker build -t blimp-cluster-controller -t ${CLUSTER_CONTROLLER_IMAGE} -f ./cluster-controller/Dockerfile .
	docker build -t blimp-sandbox-controller -t ${SANDBOX_CONTROLLER_IMAGE} -f ./sandbox-controller/Dockerfile .
	docker build -t sandbox-syncthing -t ${SYNCTHING_IMAGE} -f ./sandbox-syncthing/Dockerfile ./sandbox-syncthing
	docker build -t boot-waiter -t ${BOOT_WAITER_IMAGE} -f ./boot-waiter/Dockerfile ./boot-waiter
	docker build -t blimp-docker-auth -t ${DOCKER_AUTH_IMAGE} -f ./registry/Dockerfile .

push-docker: build-docker
	docker push ${SANDBOX_CONTROLLER_IMAGE}
	docker push ${CLUSTER_CONTROLLER_IMAGE}
	docker push ${SYNCTHING_IMAGE}
	docker push ${BOOT_WAITER_IMAGE}
	docker push ${DOCKER_AUTH_IMAGE}

deploy-registry: push-docker
	sed -i '' 's|<DOCKER_AUTH_IMAGE>|${DOCKER_AUTH_IMAGE}|' ./registry/kube/registry-deployment.yaml
	sed -i '' 's|<REGISTRY_HOSTNAME>|${REGISTRY_HOSTNAME}|' ./registry/kube/registry-deployment.yaml
	sed -i '' 's|<REGISTRY_IP>|${REGISTRY_IP}|' ./registry/kube/registry-service.yaml
	sed -i '' 's|storage: 500Gi|storage: 5Gi|' ./registry/kube/registry-pvc.yaml
	kubectl apply -f ./registry/kube
