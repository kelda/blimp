FROM blimp-go-build as builder

FROM alpine

COPY --from=builder /go/bin/init /bin/blimp-init
CMD ["blimp-init"]
