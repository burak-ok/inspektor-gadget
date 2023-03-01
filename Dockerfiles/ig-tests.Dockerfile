FROM ghcr.io/burak-ok/ig-builder:latest

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/integration/ig/k8s

RUN go test -c -o ig-integration.test ./...
