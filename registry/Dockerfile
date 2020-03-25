FROM blimp-go-build as builder

FROM cesanta/docker_auth:1

COPY --from=builder /go/bin/registry /blimp-auth
