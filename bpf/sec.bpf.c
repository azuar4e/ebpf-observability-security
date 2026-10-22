#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1 

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u8 comm[16];
    __u8 path[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u8[64]); //binary path
    __type(value, __u8);
} blocked_paths SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64); //cgroupid
    __type(value, __u8);
} watched_cgroups SEC(".maps");

struct {
    __uint (type, BPF_MAP_TYPE_RINGBUF);
    __uint (max_entries, 1 << 24);
} events SEC (".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(audit_exec, struct linux_binprm *bprm) {

    // const char* filename = bprm->filename;
    // bpf_printk("exec %s", filename);

    __u64 cgi = bpf_get_current_cgroup_id();

    if (!bpf_map_lookup_elem(&watched_cgroups, &cgi))
        return 0;

    __u8 key[64] = {};
    bpf_probe_read_kernel_str(key, sizeof(key), bprm->filename);

    if (!bpf_map_lookup_elem(&blocked_paths, &key))
        return 0;

    
    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);

    if (ev) {
        ev->timestamp_ns = bpf_ktime_get_ns();
        ev->pid = bpf_get_current_pid_tgid() >> 32;
        ev->cgroup_id = cgi;
        __builtin_memcpy(ev->path, key, sizeof(key));
        bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
        bpf_ringbuf_submit(ev, 0);
    }

    return -EPERM;
}

