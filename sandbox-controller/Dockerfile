FROM blimp-go-build as builder

FROM alpine

COPY --from=builder /go/bin/sandbox-controller /bin/blimp-sandbox-controller
CMD ["blimp-sandbox-controller"]
