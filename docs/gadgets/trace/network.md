---
title: 'The "network" gadget'
weight: 10
---

The network gadget monitors the network activity in the specified pods
and records the list of TCP connections and UDP streams.

### On Kubernetes

* Start the gadget:
```bash
$ kubectl gadget trace network -n demo
```

* Generate some network traffic:
```bash
$ kubectl run -ti -n demo --image=busybox --restart=Never shell -- wget 1.1.1.1.nip.io
```

* Observe the results:
```
NODE             NAMESPACE        POD                            TYPE      PROTO  PORT    REMOTE
minikube         demo             shell                          OUTGOING  udp    53      svc kube-system/kube-dns
minikube         demo             shell                          OUTGOING  tcp    80      endpoint 1.1.1.1
```

### With IG

Let's start the gadget in a terminal:

```bash
$ sudo ig trace network -c test-container
CONTAINER                       TYPE      PROTO PORT  REMOTE
```

Run a container that generates TCP and UDP network traffic:

```bash
$ docker run --name test-container -ti --rm busybox /bin/sh -c "wget http://1.1.1.1.nip.io/"
```

The tools will show the network activity:

```bash
$ sudo ig trace network -c test-container
CONTAINER                       TYPE      PROTO PORT  REMOTE
demo                            OUTGOING  udp   53    192.168.67.1
demo                            OUTGOING  tcp   80    1.1.1.1
```
