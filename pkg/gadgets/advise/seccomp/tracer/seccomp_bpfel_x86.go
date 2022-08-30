// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64
// +build 386 amd64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadSeccomp returns the embedded CollectionSpec for seccomp.
func loadSeccomp() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SeccompBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load seccomp: %w", err)
	}

	return spec, err
}

// loadSeccompObjects loads seccomp and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *seccompObjects
//     *seccompPrograms
//     *seccompMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSeccompObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSeccomp()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// seccompSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type seccompSpecs struct {
	seccompProgramSpecs
	seccompMapSpecs
}

// seccompSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type seccompProgramSpecs struct {
	IgSeccompE *ebpf.ProgramSpec `ebpf:"ig_seccomp_e"`
}

// seccompMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type seccompMapSpecs struct {
	SyscallsPerMntns *ebpf.MapSpec `ebpf:"syscalls_per_mntns"`
}

// seccompObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSeccompObjects or ebpf.CollectionSpec.LoadAndAssign.
type seccompObjects struct {
	seccompPrograms
	seccompMaps
}

func (o *seccompObjects) Close() error {
	return _SeccompClose(
		&o.seccompPrograms,
		&o.seccompMaps,
	)
}

// seccompMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSeccompObjects or ebpf.CollectionSpec.LoadAndAssign.
type seccompMaps struct {
	SyscallsPerMntns *ebpf.Map `ebpf:"syscalls_per_mntns"`
}

func (m *seccompMaps) Close() error {
	return _SeccompClose(
		m.SyscallsPerMntns,
	)
}

// seccompPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSeccompObjects or ebpf.CollectionSpec.LoadAndAssign.
type seccompPrograms struct {
	IgSeccompE *ebpf.Program `ebpf:"ig_seccomp_e"`
}

func (p *seccompPrograms) Close() error {
	return _SeccompClose(
		p.IgSeccompE,
	)
}

func _SeccompClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed seccomp_bpfel_x86.o
var _SeccompBytes []byte
