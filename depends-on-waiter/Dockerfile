FROM ubuntu:18.04
RUN apt-get update && \
    apt-get install -y iputils-ping && \
    rm -rf /var/lib/apt/lists/*
COPY wait.sh /wait.sh
ENTRYPOINT ["/wait.sh"]
