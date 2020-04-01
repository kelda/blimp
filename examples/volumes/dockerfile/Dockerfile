FROM ubuntu:18.04

RUN mkdir data
RUN echo hi > /data/hi

VOLUME ["/data"]


CMD ["tail", "-f", "/dev/null"]
