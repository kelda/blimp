FROM syncthing/syncthing:1.4.0 as upstream
FROM ubuntu:18.04

COPY --from=upstream /bin/syncthing /bin/syncthing
COPY config.xml /var/syncthing/config/config.xml
COPY cert.pem /var/syncthing/config/cert.pem
COPY key.pem /var/syncthing/config/key.pem

ENV HOME=/var/syncthing
ENTRYPOINT ["/bin/syncthing", "-home", "/var/syncthing/config"]
