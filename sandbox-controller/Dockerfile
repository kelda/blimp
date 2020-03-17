FROM golang:1.13 as builder

WORKDIR /go/src/github.com/kelda-inc/blimp

COPY go.mod go.sum ./
RUN go mod download

ADD . .
ARG COMPILE_FLAGS
RUN go build -ldflags "${COMPILE_FLAGS}" -o blimp-sandbox-controller ./sandbox-controller

FROM ubuntu:18.04

COPY --from=builder /go/src/github.com/kelda-inc/blimp/blimp-sandbox-controller /bin/blimp-sandbox-controller
CMD ["blimp-sandbox-controller"]
