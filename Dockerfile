FROM golang:1.13-alpine as builder

WORKDIR /go/src/github.com/kelda-inc/blimp

ADD . .
ARG COMPILE_FLAGS

RUN CGO_ENABLED=0 go install -mod=vendor -ldflags "${COMPILE_FLAGS}" ./...
