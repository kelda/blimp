DOCKER_REPO = ${BLIMP_DOCKER_REPO}
#VERSION?=$(shell ./scripts/dev_version.sh)
VERSION?=latest
SANDBOX_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-sandbox-controller:${VERSION}
CLUSTER_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-cluster-controller:${VERSION}
LD_FLAGS = "-X github.com/kelda-inc/blimp/pkg/version.Version=${VERSION} -X github.com/kelda-inc/blimp/pkg/version.SandboxControllerImage=${SANDBOX_CONTROLLER_IMAGE}"

# Default target for local development.  Just builds binaries
install:
	go install ./cli ./cluster-controller ./sandbox-controller

generate:
	protoc -I _proto _proto/blimp/sandbox/v0/controller.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc -I _proto _proto/blimp/cluster/v0/manager.proto --go_out=plugins=grpc:$$GOPATH/src
	protoc _proto/blimp/errors/v0/errors.proto --go_out=plugins=grpc:$$GOPATH/src

build-cli-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags $(LD_FLAGS) -o blimp-linux ./cli

build-cli-osx:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags $(LD_FLAGS) -o blimp-osx ./cli

build-sandbox-controller:
	docker build -t ${SANDBOX_CONTROLLER_IMAGE} -f ./sandbox-controller/Dockerfile --build-arg COMPILE_FLAGS=${LD_FLAGS} .

push-sandbox-controller: build-sandbox-controller
	docker push ${SANDBOX_CONTROLLER_IMAGE}

build-cluster-controller:
	docker build -t ${CLUSTER_CONTROLLER_IMAGE} -f ./cluster-controller/Dockerfile --build-arg COMPILE_FLAGS=${LD_FLAGS} .

push-cluster-controller: build-cluster-controller
	docker push ${CLUSTER_CONTROLLER_IMAGE}

run-cluster-controller:
	go run -ldflags $(LD_FLAGS) ./cluster-controller

build-all: build-sandbox-controller build-cluster-controller

push-all: push-sandbox-controller push-cluster-controller

build-circle-image:
	docker build -f .circleci/Dockerfile . -t keldaio/circleci-blimp
