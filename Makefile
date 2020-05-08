DOCKER_REPO = ${BLIMP_DOCKER_REPO}
REGISTRY_HOSTNAME ?= blimp-registry.kelda.io
REGISTRY_IP ?= 8.8.8.8
REGISTRY_SIZE ?= "5Gi"
#VERSION?=$(shell ./scripts/dev_version.sh)
VERSION?=latest
MANAGER_KEY_PATH = "./certs/cluster-manager.key.pem"
MANAGER_CERT_PATH = "./certs/cluster-manager.crt.pem"
LD_FLAGS = "-X github.com/kelda-inc/blimp/pkg/version.Version=${VERSION} \
	   -X github.com/kelda-inc/blimp/pkg/version.SandboxControllerImage=${SANDBOX_CONTROLLER_IMAGE} \
	   -X github.com/kelda-inc/blimp/pkg/version.InitImage=${INIT_IMAGE} \
	   -X github.com/kelda-inc/blimp/pkg/version.SyncthingImage=${SYNCTHING_IMAGE} \
	   -X github.com/kelda-inc/blimp/pkg/auth.ClusterManagerCertBase64=$(shell base64 ${MANAGER_CERT_PATH} | tr -d "\n") \
	   -X main.RegistryHostname=${REGISTRY_HOSTNAME}"

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
	protoc -I _proto _proto/blimp/sandbox/v0/controller.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc -I _proto _proto/blimp/sandbox/v0/waiter.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc -I _proto _proto/blimp/cluster/v0/manager.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc -I _proto _proto/blimp/login/v0/login.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc _proto/blimp/errors/v0/errors.proto --go_out=plugins=grpc:$$GOPATH/src

certs:
	./scripts/make-manager-cert.sh ${MANAGER_CERT_PATH} ${MANAGER_KEY_PATH}

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

run-cluster-controller: certs
	go run -ldflags $(LD_FLAGS) ./cluster-controller -tls-cert ${MANAGER_CERT_PATH} -tls-key ${MANAGER_KEY_PATH}

build-circle-image:
	docker build -f .circleci/Dockerfile . -t keldaio/circleci-blimp

SANDBOX_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-sandbox-controller:${VERSION}
CLUSTER_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-cluster-controller:${VERSION}
INIT_IMAGE = ${DOCKER_REPO}/blimp-init:${VERSION}
SYNCTHING_IMAGE = ${DOCKER_REPO}/sandbox-syncthing:${VERSION}
DOCKER_AUTH_IMAGE = ${DOCKER_REPO}/blimp-docker-auth:${VERSION}
LOGIN_PROXY_IMAGE = ${DOCKER_REPO}/login-proxy:${VERSION}

build-docker: certs
	docker build -t blimp-go-build --build-arg COMPILE_FLAGS=${LD_FLAGS} . && \
	docker build -t sandbox-syncthing -t ${SYNCTHING_IMAGE} -f ./sandbox/syncthing/Dockerfile . & \
	docker build -t blimp-cluster-controller -t ${CLUSTER_CONTROLLER_IMAGE} - < ./cluster-controller/Dockerfile & \
	docker build -t blimp-sandbox-controller -t ${SANDBOX_CONTROLLER_IMAGE} - < ./sandbox/sbctl/Dockerfile & \
	docker build -t blimp-init -t ${INIT_IMAGE} - < ./sandbox/init/Dockerfile & \
	docker build -t blimp-docker-auth -t ${DOCKER_AUTH_IMAGE} - < ./registry/Dockerfile & \
	docker build -t login-proxy -t ${LOGIN_PROXY_IMAGE} - < ./login-proxy/Dockerfile & \
	wait # Wait for all background jobs to exit before continuing so that we can guarantee the images are built.

push-docker: build-docker
	docker push ${SANDBOX_CONTROLLER_IMAGE} && \
	docker push ${CLUSTER_CONTROLLER_IMAGE} & \
	docker push ${SYNCTHING_IMAGE} & \
	docker push ${INIT_IMAGE} & \
	docker push ${DOCKER_AUTH_IMAGE} & \
	docker push ${LOGIN_PROXY_IMAGE} & \
	wait # Wait for all background jobs to exit before continuing so that we can guarantee the images are pushed.

deploy-registry:
	sed -i '' 's|<DOCKER_AUTH_IMAGE>|${DOCKER_AUTH_IMAGE}|' ./registry/kube/registry-deployment.yaml
	sed -i '' 's|<REGISTRY_HOSTNAME>|${REGISTRY_HOSTNAME}|' ./registry/kube/registry-deployment.yaml
	sed -i '' 's|<REGISTRY_IP>|${REGISTRY_IP}|' ./registry/kube/registry-service.yaml
	sed -i '' 's|<REGISTRY_STORAGE>|${REGISTRY_STORAGE}|' ./registry/kube/registry-pvc.yaml
	kubectl apply -f ./registry/kube

deploy-manager:
	sed -i '' 's|<CLUSTER_MANAGER_IMAGE>|${CLUSTER_CONTROLLER_IMAGE}|' ./cluster-controller/kube/manager-deployment.yaml
	kubectl apply -f ./cluster-controller/kube

deploy-login-proxy:
	sed -i '' 's|<LOGIN_PROXY_IMAGE>|${LOGIN_PROXY_IMAGE}|' ./login-proxy/kube/login-deployment.yaml
	sed -i '' 's|<LOGIN_PROXY_HOSTNAME>|${LOGIN_PROXY_HOSTNAME}|' ./login-proxy/kube/login-deployment.yaml
	sed -i '' 's|<LOGIN_PROXY_IP>|${LOGIN_PROXY_IP}|' ./login-proxy/kube/login-service.yaml
	kubectl apply -f ./login-proxy/kube
