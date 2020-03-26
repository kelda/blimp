DOCKER_REPO = ${BLIMP_DOCKER_REPO}
#VERSION?=$(shell ./scripts/dev_version.sh)
VERSION?=latest
LD_FLAGS = "-X github.com/kelda-inc/blimp/pkg/version.Version=${VERSION} \
	   -X github.com/kelda-inc/blimp/pkg/version.SandboxControllerImage=${SANDBOX_CONTROLLER_IMAGE} \
	   -X github.com/kelda-inc/blimp/pkg/version.DependsOnImage=${DEPENDS_ON_IMAGE} \
	   -X github.com/kelda-inc/blimp/pkg/version.SyncthingImage=${SYNCTHING_IMAGE}"

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

run-cluster-controller:
	go run -ldflags $(LD_FLAGS) ./cluster-controller

build-circle-image:
	docker build -f .circleci/Dockerfile . -t keldaio/circleci-blimp

SANDBOX_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-sandbox-controller:${VERSION}
CLUSTER_CONTROLLER_IMAGE = ${DOCKER_REPO}/blimp-cluster-controller:${VERSION}
DEPENDS_ON_IMAGE = ${DOCKER_REPO}/blimp-depends-on-waiter:${VERSION}
SYNCTHING_IMAGE = ${DOCKER_REPO}/blimp-syncthing:${VERSION}

build-docker:
	docker build -t blimp-go-build .
	docker build -t ${CLUSTER_CONTROLLER_IMAGE} -f ./cluster-controller/Dockerfile --build-arg COMPILE_FLAGS=${LD_FLAGS} .
	docker build -t ${SANDBOX_CONTROLLER_IMAGE} -f ./sandbox-controller/Dockerfile --build-arg COMPILE_FLAGS=${LD_FLAGS} .
	docker build -t ${SYNCTHING_IMAGE} -f ./syncthing/Dockerfile --build-arg COMPILE_FLAGS=${LD_FLAGS} ./syncthing
	docker build -t ${DEPENDS_ON_IMAGE} -f ./depends-on-waiter/Dockerfile ./depends-on-waiter

push-docker: build-docker
	docker push ${SANDBOX_CONTROLLER_IMAGE}
	docker push ${CLUSTER_CONTROLLER_IMAGE}
	docker push ${SYNCTHING_IMAGE}
	docker push ${DEPENDS_ON_IMAGE}
