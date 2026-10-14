package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bane ../../bpf/sec.bpf.c -- -I/usr/include/bpf

func main() {

}
