// Copyright 2019-2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	tracednsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceDns(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-dns")

	t.Parallel()

	// TODO: Handle it once we support getting container image name from docker
	errIsDocker, isDockerRuntime := IsDockerRuntime()
	if errIsDocker != nil {
		t.Fatalf("checking if docker is current runtime: %v", errIsDocker)
	}

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("dnstester", *dnsTesterImage, ns, "", ""),
		WaitUntilPodReadyCommand(ns, "dnstester"),
	}

	RunTestSteps(commandsPreTest, t)
	dnsServer, err := GetTestPodIP(ns, "dnstester")
	if err != nil {
		t.Fatalf("failed to get dnsserver pod ip: %v", err)
	}

	nslookupCmds := []string{
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=a fake.test.com. %s", dnsServer),
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=aaaa fake.test.com. %s", dnsServer),
	}

	// Start the busybox pod so that we can get the IP address of the pod.
	commands := []*Command{
		BusyboxPodRepeatCommand(ns, strings.Join(nslookupCmds, " ; ")),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commands, t)
	busyBoxIP, err := GetTestPodIP(ns, "test-pod")
	if err != nil {
		t.Fatalf("failed to get busybox pod ip: %v", err)
	}

	traceDNSCmd := &Command{
		Name:         "StartTraceDnsGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace dns -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*tracednsTypes.Event{
				{
					Event:      BuildBaseEvent(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Uid:        1000,
					Gid:        1111,
					Protocol:   "udp",
					DstPort:    53,
					SrcIP:      busyBoxIP,
				},
				{
					Event:      BuildBaseEvent(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeResponse,
					Nameserver: dnsServer,
					PktType:    "HOST",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Rcode:      "NoError",
					Latency:    1,
					NumAnswers: 1,
					Addresses:  []string{"127.0.0.1"},
					Uid:        1000,
					Gid:        1111,
					Protocol:   "udp",
					SrcPort:    53,
					DstIP:      busyBoxIP,
				},
				{
					Event:      BuildBaseEvent(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Uid:        1000,
					Gid:        1111,
					Protocol:   "udp",
					DstPort:    53,
					SrcIP:      busyBoxIP,
				},
				{
					Event:      BuildBaseEvent(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeResponse,
					Nameserver: dnsServer,
					PktType:    "HOST",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Rcode:      "NoError",
					Latency:    1,
					NumAnswers: 1,
					Addresses:  []string{"::1"},
					Uid:        1000,
					Gid:        1111,
					Protocol:   "udp",
					SrcPort:    53,
					DstIP:      busyBoxIP,
				},
			}

			normalize := func(e *tracednsTypes.Event) {
				e.Timestamp = 0
				e.ID = ""
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0

				// Latency should be > 0 only for DNS responses.
				if e.Latency > 0 {
					e.Latency = 1
				}

				e.K8s.Node = ""
				// TODO: Verify container runtime and container name
				e.Runtime.RuntimeName = ""
				e.Runtime.ContainerName = ""
				e.Runtime.ContainerID = ""
			}

			compFn := func(a, b any) bool {
				x := a.(*tracednsTypes.Event)
				y := b.(*tracednsTypes.Event)
				return x.Comm == y.Comm &&
					x.Qr == y.Qr &&
					x.Nameserver == y.Nameserver &&
					x.PktType == y.PktType &&
					x.DNSName == y.DNSName &&
					x.QType == y.QType &&
					x.Rcode == y.Rcode &&
					x.Latency == y.Latency &&
					x.NumAnswers == y.NumAnswers &&
					reflect.DeepEqual(x.Addresses, y.Addresses) &&
					x.Uid == y.Uid &&
					x.Gid == y.Gid &&
					x.Protocol == y.Protocol &&
					((x.Qr == tracednsTypes.DNSPktTypeQuery &&
						x.DstPort == y.DstPort && x.SrcIP == y.SrcIP) ||
						(x.Qr == tracednsTypes.DNSPktTypeResponse &&
							x.SrcPort == y.SrcPort &&
							x.DstIP == y.DstIP))
			}

			return ExpectedEntriesToMatchCustom(output, normalize, compFn, expectedEntries...)
		},
	}

	// Start the trace gadget and verify the output.
	commands = []*Command{
		CreateTestNamespaceCommand(ns),
		traceDNSCmd,
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
