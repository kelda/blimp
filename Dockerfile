FROM golang:1.13-alpine as builder

RUN apk add busybox-static

WORKDIR /go/src/github.com/kelda-inc/blimp

ADD ./go.mod ./go.mod
ADD ./go.sum ./go.sum
ADD ./pkg ./pkg

ARG COMPILE_FLAGS

# Build incrementally for better caching.
RUN CGO_ENABLED=0 go install -i -ldflags "${COMPILE_FLAGS}" ./pkg/...

ADD ./login-proxy ./login-proxy
RUN CGO_ENABLED=0 go install -i -ldflags "${COMPILE_FLAGS}" ./login-proxy/...

ADD ./registry ./registry
RUN CGO_ENABLED=0 go install -i -ldflags "${COMPILE_FLAGS}" ./registry/...

ADD ./node ./node
RUN CGO_ENABLED=0 go install -i -ldflags "${COMPILE_FLAGS}" ./node/...

ADD ./sandbox ./sandbox
RUN CGO_ENABLED=0 go install -i -ldflags "${COMPILE_FLAGS}" ./sandbox/...

ADD ./cluster-controller ./cluster-controller
RUN CGO_ENABLED=0 go install -i -ldflags "${COMPILE_FLAGS}" ./cluster-controller/...

ADD ./link-proxy ./link-proxy
RUN CGO_ENABLED=0 go install -i -ldflags "${COMPILE_FLAGS}" ./link-proxy/...

RUN mkdir /gobin
RUN cp /go/bin/cluster-controller /gobin/blimp-cluster-controller
RUN cp /go/bin/syncthing /gobin/blimp-syncthing
RUN cp /go/bin/init /gobin/blimp-init
RUN cp /go/bin/node /gobin/blimp-node-controller
RUN cp /go/bin/registry /gobin/blimp-auth
RUN cp /go/bin/vcp /gobin/blimp-vcp
RUN cp /go/bin/login-proxy /gobin/login-proxy
RUN cp /go/bin/dns /gobin/blimp-dns
RUN cp /go/bin/link-proxy /gobin/link-proxy

FROM alpine

COPY --from=builder /bin/busybox.static /bin/busybox.static
COPY --from=builder /gobin/* /bin/
