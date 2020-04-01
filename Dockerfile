FROM golang:1.13-alpine as builder

WORKDIR /go/src/github.com/kelda-inc/blimp
COPY go.mod go.sum ./
RUN go mod download

ADD . .
ARG COMPILE_FLAGS

RUN CGO_ENABLED=0 go install -ldflags "${COMPILE_FLAGS}" \
    ./cluster-controller \
    ./registry \
    ./sandbox/* \
