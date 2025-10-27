#compile the binary
FROM golang:1.24-alpine AS builder

WORKDIR /build
COPY go.mod ./
COPY go.sum* ./
RUN go mod download
COPY . .
RUN go build -o kosmo .

#run the binary
FROM golang:1.24-alpine
RUN apk add --no-cache ca-certificates git curl netcat-openbsd
WORKDIR /app
COPY --from=builder /build/kosmo /usr/local/bin/kosmo

#ENTRYPOINT ["/usr/local/bin/kosmo"]
#CMD ["start"]