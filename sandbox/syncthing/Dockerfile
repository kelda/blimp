FROM blimp-go-build as builder
FROM syncthing/syncthing:1.4.0 as upstream
FROM ubuntu:18.04

COPY --from=builder /bin/blimp-syncthing /bin/blimp-syncthing
COPY --from=upstream /bin/syncthing /bin/syncthing
COPY ./sandbox/syncthing/*.pem /var/syncthing/config/

ENTRYPOINT ["/bin/blimp-syncthing"]
