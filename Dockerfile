FROM golang:1.13-alpine as builder

WORKDIR /go/src/github.com/kelda-inc/blimp

ADD . .
ARG COMPILE_FLAGS

RUN CGO_ENABLED=0 go install -mod=vendor -ldflags "${COMPILE_FLAGS}" ./...

FROM alpine

COPY --from=builder /go/bin/cluster-controller /bin/blimp-cluster-controller
COPY --from=builder /go/bin/syncthing /bin/blimp-syncthing
COPY --from=builder /go/bin/init /bin/blimp-init
COPY --from=builder /go/bin/sbctl /bin/blimp-sbctl
COPY --from=builder /go/bin/registry /blimp-auth
