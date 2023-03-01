FROM ghcr.io/inspektor-gadget/ig-builder:latest

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/integration/local-gadget/k8s

RUN go test -c -o local-gadget-integration.test ./...
