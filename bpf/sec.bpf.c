#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


SEC("xdp")
int nombre() {


    return ;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

