FROM blimp-go-build as builder
FROM syncthing/syncthing:1.4.0 as upstream
FROM ubuntu:18.04

COPY --from=builder /go/bin/sandbox-syncthing /bin/sandbox-syncthing
COPY --from=upstream /bin/syncthing /bin/syncthing
COPY *.pem /var/syncthing/config/

ENTRYPOINT ["/bin/sandbox-syncthing"]
