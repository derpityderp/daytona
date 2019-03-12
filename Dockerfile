FROM golang:1.11.5 AS builder
ENV GOFLAGS -mod=vendor
WORKDIR /go/src/app
ADD . .
RUN go test
RUN CGO_ENABLED=0 go build -a -o daytona .

FROM scratch
COPY --from=builder /go/src/app/daytona /
ADD https://curl.haxx.se/ca/cacert.pem /etc/ssl/certs/ca-certificates.crt
CMD ["/daytona"]
