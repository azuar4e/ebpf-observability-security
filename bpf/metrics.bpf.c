#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define AF_INET 2

// lru map for timestamps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64); //socket mem addr
    __type(value, __u64); //timestamp
} connections SEC(".maps");

// ringbuffer to send info for logs
struct tcp_event {
    __u64 latency_ns;

    __u8 saddr[4];
    __u8 daddr[4];

    __u16 src_port;
    __u16 dst_port;
};

struct {
    __uint (type, BPF_MAP_TYPE_RINGBUF);
    __uint (max_entries, 1 << 24);
} events SEC (".maps");

// percpu array for lost connections
enum {
    MISSING_TIMESTAMP = 0,
    RINGBUF_FULL = 1,
    TCP_FAILED = 2,
    //size max entries
    ERRORS_COUNT = 3
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ERRORS_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} lost_events SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_tcp_state(struct trace_event_raw_inet_sock_set_state *ctx) {

    if (ctx->protocol != IPPROTO_TCP || ctx->family != AF_INET)
        return 0;

    __u64 skaddr = (__u64)ctx->skaddr;
    __u32 key;
    __u64 *val;

    if (ctx->newstate == TCP_SYN_SENT) {
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&connections, &skaddr, &ts, BPF_ANY);

    } else if (ctx->newstate == TCP_ESTABLISHED && ctx->oldstate == TCP_SYN_SENT) {
        __u64 *ts = bpf_map_lookup_elem(&connections, &skaddr);

        if (!ts) {
            bpf_map_delete_elem(&connections, &skaddr);

            key = MISSING_TIMESTAMP;
            val = bpf_map_lookup_elem(&lost_events, &key);
            if (val)
                (*val)++;

            return 0;
        }

        struct tcp_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);

        if (!ev) {
            bpf_map_delete_elem(&connections, &skaddr);
            
            key = RINGBUF_FULL;
            val = bpf_map_lookup_elem(&lost_events, &key);
            if (val)
                (*val)++;

            return 0;
        }
        
        ev->latency_ns = bpf_ktime_get_ns() - (*ts);
        bpf_map_delete_elem(&connections, &skaddr);
        ev->src_port   = ctx->sport;
        ev->dst_port   = ctx->dport;
        __builtin_memcpy(ev->saddr, ctx->saddr, 4);
        __builtin_memcpy(ev->daddr, ctx->daddr, 4);
        bpf_ringbuf_submit(ev, 0);

    } else if (ctx->newstate == TCP_CLOSE && ctx->oldstate == TCP_SYN_SENT) {
        bpf_map_delete_elem(&connections, &skaddr);

        key = TCP_FAILED;
        val = bpf_map_lookup_elem(&lost_events, &key);

        if (val)
            (*val)++;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
