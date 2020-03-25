DOCKER_REPO = ${BLIMP_DOCKER_REPO}
REGISTRY_HOSTNAME ?= blimp-registry.kelda.io
REGISTRY_IP ?= 8.8.8.8
#VERSION?=$(shell ./scripts/dev_version.sh)
VERSION?=latest
MANAGER_KEY_PATH = "./certs/cluster-manager.key.pem"
MANAGER_CERT_PATH = "./certs/cluster-manager.crt.pem"
LD_FLAGS = "-X github.com/kelda-inc/blimp/pkg/version.Version=${VERSION} \
	   -X github.com/kelda-inc/blimp/pkg/version.SandboxControllerImage=${SANDBOX_CONTROLLER_IMAGE} \
	   -X github.com/kelda-inc/blimp/pkg/version.DependsOnImage=${DEPENDS_ON_IMAGE} \
	   -X github.com/kelda-inc/blimp/pkg/version.SyncthingImage=${SYNCTHING_IMAGE} \
	   -X github.com/kelda-inc/blimp/pkg/auth.ClusterManagerCertBase64=$(shell base64 ${MANAGER_CERT_PATH}) \
	   -X main.RegistryHostname=${REGISTRY_HOSTNAME}"

# Include all .mk files so you can have your own local configurations
include $(wildcard *.mk)

# Default target for local development.  Just builds binaries
install: certs
	CGO_ENABLED=0 go install -ldflags $(LD_FLAGS) ./cli ./cluster-controller ./sandbox-controller ./registry

generate:
	protoc -I _proto _proto/blimp/sandbox/v0/controller.proto --go_out=plugins=grpc:$$GOPATH/src
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

build-cli-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags $(LD_FLAGS) -o blimp-linux ./cli

build-cli-osx:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags $(LD_FLAGS) -o blimp-osx ./cli

run-cluster-controller: certs
	go run -ldflags $(LD_FLAGS) ./cluster-controller -tls-cert ${MANAGER_CERT_PATH} -tls-key ${MANAGER_KEY_PATH}

build-circle-image:
	docker build -f .circleci/Dockerfile . -t keldaio/circleci-blimp

SANDBOX_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-sandbox-controller:${VERSION}
CLUSTER_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-cluster-controller:${VERSION}
DEPENDS_ON_IMAGE = ${DOCKER_REPO}/blimp-depends-on-waiter:${VERSION}
SYNCTHING_IMAGE = ${DOCKER_REPO}/blimp-syncthing:${VERSION}
DOCKER_AUTH_IMAGE = ${DOCKER_REPO}/blimp-docker-auth:${VERSION}

build-docker:
	docker build -t blimp-go-build --build-arg COMPILE_FLAGS=${LD_FLAGS} .
	docker build -t ${CLUSTER_CONTROLLER_IMAGE} -f ./cluster-controller/Dockerfile .
	docker build -t ${SANDBOX_CONTROLLER_IMAGE} -f ./sandbox-controller/Dockerfile .
	docker build -t ${SYNCTHING_IMAGE} -f ./syncthing/Dockerfile ./syncthing
	docker build -t ${DEPENDS_ON_IMAGE} -f ./depends-on-waiter/Dockerfile ./depends-on-waiter
	docker build -t ${DOCKER_AUTH_IMAGE} -f ./registry/Dockerfile .

push-docker: build-docker
	docker push ${SANDBOX_CONTROLLER_IMAGE}
	docker push ${CLUSTER_CONTROLLER_IMAGE}
	docker push ${SYNCTHING_IMAGE}
	docker push ${DEPENDS_ON_IMAGE}
	docker push ${DOCKER_AUTH_IMAGE}

deploy-registry: push-docker
	sed -i '' 's|<DOCKER_AUTH_IMAGE>|${DOCKER_AUTH_IMAGE}|' ./registry/kube/registry-deployment.yaml
	sed -i '' 's|<REGISTRY_HOSTNAME>|${REGISTRY_HOSTNAME}|' ./registry/kube/registry-deployment.yaml
	sed -i '' 's|<REGISTRY_IP>|${REGISTRY_IP}|' ./registry/kube/registry-service.yaml
	sed -i '' 's|storage: 500Gi|storage: 5Gi|' ./registry/kube/registry-pvc.yaml
	kubectl apply -f ./registry/kube
