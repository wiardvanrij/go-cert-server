FROM golang:1.12 AS builder
RUN mkdir /build 
ADD . /build/
WORKDIR /build 
RUN CGO_ENABLED=0 GODEBUG=http2client=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o main .
FROM golang:alpine
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/main /app/
WORKDIR /app
CMD ["./main"]