FROM blimp-go-build as builder

FROM alpine

COPY --from=builder /go/bin/sbctl /bin/blimp-sbctl
CMD ["blimp-sbctl"]
