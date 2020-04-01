FROM golang:1.13-alpine as builder

RUN apk add busybox-static

WORKDIR /go/src/github.com/kelda-inc/blimp

ADD ./go.mod ./go.mod
ADD ./go.sum ./go.sum
ADD ./pkg ./pkg
ADD ./vendor ./vendor
ADD ./cli ./cli

ARG COMPILE_FLAGS

# Pre-build the CLI as a hack to download modules and hopefully compile some of
# our deps
RUN CGO_ENABLED=0 go install -mod=vendor -ldflags "${COMPILE_FLAGS}" ./cli/...

ADD . .

RUN CGO_ENABLED=0 go install -mod=vendor -ldflags "${COMPILE_FLAGS}" ./...

RUN mkdir /gobin
RUN cp /go/bin/cluster-controller /gobin/blimp-cluster-controller
RUN cp /go/bin/syncthing /gobin/blimp-syncthing
RUN cp /go/bin/init /gobin/blimp-init
RUN cp /go/bin/sbctl /gobin/blimp-sbctl
RUN cp /go/bin/registry /gobin/blimp-auth
RUN cp /go/bin/vcp /gobin/blimp-vcp

FROM alpine

COPY --from=builder /bin/busybox.static /bin/busybox.static
COPY --from=builder /gobin/* /bin/
