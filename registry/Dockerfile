FROM blimp-go-build as builder

FROM cesanta/docker_auth:1

COPY --from=builder /bin/blimp-auth /blimp-auth
