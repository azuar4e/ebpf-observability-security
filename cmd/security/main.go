package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bane ../../bpf/sec.bpf.c -- -I/usr/include/bpf

type metrics struct {
	execsCounter prometheus.Counter
}

type event struct {
	TimestampNs uint64
	CgroupId    uint64
	Pid         uint32
	Comm        [16]uint8
	Path        [64]uint8
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		execsCounter: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "ebpf_blocked_execs_total",
			Help: "Total number of command executions blocked by the BPF LSM program.",
		}),
	}
	return m
}

func syncCgroups(ctx context.Context, cs kubernetes.Interface, m *ebpf.Map) error {
	pods, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "ebpf-sec=enforce",
	})
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		for _, c := range pod.Status.ContainerStatuses {
			_, id, ok := strings.Cut(c.ContainerID, "://")
			if !ok || id == "" {
				continue
			}
			cgID, err := findCgroupID(id)
			if err != nil {
				log.Printf("%s/%s: %v", pod.Namespace, pod.Name, err)
				continue
			}
			if err := m.Put(cgID, uint8(1)); err != nil {
				return err
			}
			log.Printf("vigilando %s/%s cgroup=%d", pod.Namespace, pod.Name, cgID)
		}
	}
	return nil
}

func findCgroupID(containerID string) (uint64, error) {
	root := "/sys/fs/cgroup"

	var cgroupID uint64
	found := false

	err := filepath.WalkDir(root,
		func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() || !strings.Contains(path, containerID) {
				return nil
			}

			var stat unix.Stat_t

			if err := unix.Stat(path, &stat); err != nil {
				return nil
			}

			cgroupID = stat.Ino
			found = true
			return filepath.SkipAll
		})

	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("cgroup not found for container %s", containerID)
	}

	return cgroupID, nil
}

var bootTime time.Time

func init() {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	bootTime = time.Now().Add(-time.Duration(ts.Nano()))
}

func main() {
	ctx := context.Background()
	cfg, _ := rest.InClusterConfig()
	cs, _ := kubernetes.NewForConfig(cfg)

	objs := bpfObjects{}

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	defer objs.Close()

	//insert into the map the paths of the commands we want to block
	var paths = []string{"/bin/curl", "/bin/cat"}

	for _, p := range paths {
		var key [64]byte
		copy(key[:], p)
		if err := objs.BlockedPaths.Put(&key, uint8(1)); err != nil {
			log.Fatalf("copying command to blocked_paths ebpf map: %v", err)
		}
	}

	// cgroupPath := flag.String("cgroup", "", "ruta de un cgroup a vigilar (pruebas)")
	// flag.Parse()

	// if *cgroupPath != "" {
	// 	var st unix.Stat_t
	// 	if err := unix.Stat(*cgroupPath, &st); err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	if err := objs.WatchedCgroups.Put(uint64(st.Ino), uint8(1)); err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	log.Printf("vigilando cgroup %d (%s)", st.Ino, *cgroupPath)
	// }

	if err := syncCgroups(ctx, cs, objs.WatchedCgroups); err != nil {
		log.Println(err)
	}

	lsm, err := link.AttachLSM(link.LSMOptions{
		Program: objs.AuditExec,
	})

	if err != nil {
		log.Fatalf("opening lsm hook: %s", err)
	}

	defer lsm.Close()

	go func() {
		for {
			time.Sleep(10 * time.Second)
			if err := syncCgroups(ctx, cs, objs.WatchedCgroups); err != nil {
				log.Println(err)
			}
		}
	}()

	reg := prometheus.NewRegistry()
	m := newMetrics(reg)

	//read the ringbuf
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	//go routine for ring buffer
	go func() {
		var event event

		for {
			record, err := rd.Read()

			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}

			t := bootTime.Add(time.Duration(event.TimestampNs))

			log.Printf("BLOCKED exec: path=%s comm=%s pid=%d cgroup=%d time=%s",
				unix.ByteSliceToString(event.Path[:]),
				unix.ByteSliceToString(event.Comm[:]),
				event.Pid,
				event.CgroupId,
				t.Format(time.RFC3339Nano),
			)

			m.execsCounter.Inc()
		}
	}()

	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	http.ListenAndServe(":2112", nil)
}
