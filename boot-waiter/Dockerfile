FROM blimp-go-build as builder

FROM alpine

COPY --from=builder /go/bin/boot-waiter /bin/boot-waiter
CMD ["boot-waiter"]
