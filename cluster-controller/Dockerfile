FROM blimp-go-build as builder

FROM alpine

COPY --from=builder /go/bin/cluster-controller /bin/blimp-cluster-controller
CMD ["blimp-cluster-controller"]
