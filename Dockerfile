FROM ubuntu:18.04
RUN apt update
RUN apt install -y git
COPY ./blimp-linux /usr/local/bin/blimp
COPY docker-entrypoint.sh /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["blimp"]
