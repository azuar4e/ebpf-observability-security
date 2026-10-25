# eBPF Observability & Security

![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-1.34-326CE5?logo=kubernetes&logoColor=white)
![Cilium](https://img.shields.io/badge/Cilium-1.20-F8C517?logo=cilium&logoColor=black)
![eBPF](https://img.shields.io/badge/eBPF-CO--RE-orange)

Source code for two eBPF agents written in C (kernel space) and Go (user space) with [`cilium/ebpf`](https://github.com/cilium/ebpf):

- **Metrics agent (observability):** measures the latency of TCP connection establishment (`SYN_SENT` → `ESTABLISHED`) and counts the events it could not record or the connections that failed. In user space it reads the ring buffer, logs every connection, feeds a Prometheus histogram and exposes the counters of the per-CPU array through a custom collector. Metrics are served at `/metrics` on port `2112`.
- **Security agent (enforcement):** uses a BPF LSM hook to decide whether a command can be executed from a watched cgroup. It denies the execution when the binary is in the block list. In user space it reads the denial events from the ring buffer and exposes a Prometheus counter of blocked executions, also at `/metrics` on port `2112`.

This repository is the companion of a full article about observability and security in a Kubernetes cluster using Cilium as CNI and service mesh. You can read it [here](https://azuar4e.github.io/en/posts/cilium/).

> [!WARNING]
> This is a **demo for test environments**. An LSM program runs for **every** process on the host (not only for pods) and the DaemonSets run as `privileged: true`. The security agent filters narrowly watched cgroup and blocked path.

## Overview

### Metrics agent

It attaches to the `sock:inet_sock_set_state` tracepoint, which fires on every TCP state transition. It uses three data structures:

- **LRU hash:** stores the timestamp of each connection when it enters `SYN_SENT`. If it fills up it evicts the least recently used entries.
- **Per-CPU array:** one copy of the counters per CPU core, so incrementing needs no locks. It holds one counter per reason:
    - `MISSING_TIMESTAMP`: the connection was established but its timestamp was not found (internal).
    - `RINGBUF_FULL`: there was no room in the ring buffer (internal).
    - `TCP_FAILED`: the socket went from `SYN_SENT` to `CLOSE`, so the connection attempt failed.
- **Ring buffer:** sends the details of each established connection to user space.

In user space, a goroutine reads the ring buffer, logs every connection and records its latency in a Prometheus histogram, whose buckets are tuned to the latencies observed. A custom collector reads the per-CPU array and exposes the total of each reason (the sum of the counter on every core). Both are served at `/metrics` on port `2112`.

### Security agent

It attaches to the `bprm_check_security` LSM hook, which runs during `execve`, right before the new binary is executed. The program returns `0` to allow it or `-EPERM` to deny it. It uses three data structures:

- **`blocked_paths`:** hash map with the paths of the binaries to block.
- **`watched_cgroups`:** hash map with the ids of the cgroups to enforce on.
- **Ring buffer:** sends user space one event per denied execution, with the timestamp, the pid, the cgroup id, the name of the process that tried to run the command (`comm`) and the path of the blocked binary.

The program only denies when the process belongs to a watched cgroup **and** the binary is in `blocked_paths`. In every other case it returns `0`.

In user space the Kubernetes client lists the pods labelled `ebpf-sec=enforce`, takes the ID of each container, looks for its cgroup under `/sys/fs/cgroup` and inserts the inode (which is the cgroup id the kernel sees) in `watched_cgroups`. It repeats this every 10 seconds, since pods come and go. Another goroutine reads the ring buffer and increments a Prometheus counter with the number of blocked executions, exposed at `/metrics` on port `2112`.

### Manifests

- **Metrics agent:** mounts `/sys/kernel/tracing`, where the tracepoints live.
- **Security agent:** mounts `/sys/fs/cgroup` so it can find the cgroup of each container. Each node of a kind cluster is a container, so each agent only sees the cgroups of its own node and logs `cgroup not found` for pods running elsewhere.
- **RBAC:** the security agent lists pods, so it needs a `ServiceAccount`, a `ClusterRole` that allows reading pods and a `ClusterRoleBinding` joining them. Otherwise it would use the `default` service account and the API server would deny the request.
- **`PodMonitor`:** tells the Prometheus Operator where to scrape the metrics of both agents.

## Requirements

- **Kernel** with BTF (`CONFIG_DEBUG_INFO_BTF=y`) and, for the security agent, BPF LSM (`CONFIG_BPF_LSM=y`) with `bpf` in the active LSM list. Check it with `cat /sys/kernel/security/lsm`, which should end in `bpf` (you may need to mount `securityfs`).
- A Kubernetes cluster (tested with kind and Kubernetes 1.34). Nodes of a kind cluster share the host kernel, so the requirements above apply to your host.
- Docker, to build the images.
- The Prometheus Operator (for example `kube-prometheus-stack`) if you want to use the `PodMonitor`.
- To build from source: Go, clang/llvm and libbpf headers (`libbpf-dev`). Not needed if you build with the provided Dockerfiles, which do it inside the container.

<details>
<summary>Enabling BPF LSM on WSL2</summary>

The WSL2 kernel ships with `CONFIG_BPF_LSM`, but `bpf` is not in the active list. Add this to `%UserProfile%\.wslconfig`:

```ini
[wsl2]
kernelCommandLine = lsm=landlock,yama,safesetid,selinux,bpf
```

Then run `wsl --shutdown` from PowerShell and start WSL again.
</details>

## Usage

### Build and deploy

Each agent has its own Dockerfile. The build context is the root of the repository:

```bash
docker build -f cmd/metrics/Dockerfile -t azuar4e/ebpf-metrics:v1 .
docker build -f cmd/security/Dockerfile -t azuar4e/ebpf-sec:v1 .
kind load docker-image azuar4e/ebpf-sec:v1 azuar4e/ebpf-metrics:v1 --name kind
```

> This builds both images and loads them into the kind cluster.

Then deploy the manifests:

```bash
kubectl apply -f ./manifests
```

### Choosing what to block

- **Which pods:** add the label `ebpf-sec: enforce` to `spec.template.metadata.labels` of the Deployments you want to watch.
- **Which commands:** the paths are defined in the `paths` variable of `cmd/security/main.go`. They are compared as **plain text**, so `/bin/cat` and `/usr/bin/cat` are different entries. You can see the path of the command using the `type <cmd>` command.

### Checking that it works

```bash
# Metrics agent
kubectl port-forward pod/<ebpf-metrics-pod> 2112:2112
curl -s localhost:2112/metrics | grep ebpf_tcp

# Security agent: run a blocked command in a watched pod
kubectl exec -it <watched-pod> -- cat /etc/hostname   # Operation not permitted
kubectl port-forward pod/<ebpf-sec-pod> 2112:2112
curl -s localhost:2112/metrics | grep ebpf_blocked
```

### Running locally (without Kubernetes)

```bash
go generate ./cmd/metrics && go build -o metrics-agent ./cmd/metrics && sudo ./metrics-agent
```

For the security agent, comment out the Kubernetes code in `main` and pass a test cgroup with the `-cgroup` flag. The article explains the whole process step by step.

## Metrics

| Metric | Type | Agent |
| --- | --- | --- |
| `ebpf_tcp_connection_duration` | Histogram (seconds) | metrics |
| `tcp_lost_events_total` | Counter, per reason | metrics |
| `ebpf_blocked_execs_total` | Counter | security |

## Limitations

- Blocking is by **path string**. Running the same binary under another path, or copying it with another name, bypasses the block.
- Only IPv4 is measured by the metrics agent.
- The blocked executions counter is fed by the ring buffer, so if the buffer fills up the command is still denied, but it is not counted.
- A new pod is not watched until the next sync (10 seconds), and the cgroups of deleted pods are not removed from the map.

## Project structure

```text
.
├── bpf/            # vmlinux.h, metrics.bpf.c, sec.bpf.c
├── cmd/
│   ├── metrics/    # gen.go, main.go, Dockerfile
│   └── security/   # gen.go, main.go, Dockerfile
└── manifests/      # DaemonSets, RBAC, PodMonitor
```
