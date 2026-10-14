package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/http"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bane ../../bpf/metrics.bpf.c -- -I/usr/include/bpf
type metrics struct {
	latencyHistogram prometheus.Histogram
}

type lostEventsCollector struct {
	m    *ebpf.Map
	desc *prometheus.Desc
}

type TCPEvent struct {
	LatencyNs uint64
	Saddr     [4]byte
	Daddr     [4]byte
	SrcPort   uint16
	DstPort   uint16
}

var lostReasons = []string{"missing_timestamp", "ringbuf_full", "tcp_failed"}

func newMetrics(reg prometheus.Registerer, lost *ebpf.Map) *metrics {
	m := &metrics{
		latencyHistogram: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name: "ebpf_tcp_connection_duration",
			Help: "The latency of TCP connection establishment.",
			Buckets: []float64{
				0.00002, 0.00004, 0.00008, 0.00016, 0.00032, 0.00064, // donde está tu loopback
				0.0015, 0.005, 0.025, // entre nodos, a ojo
				0.25, 1, 3, // anomalías y reintentos de SYN

			},
		}),
	}
	reg.MustRegister(newLostEventsCollector(lost))
	return m
}

func newLostEventsCollector(m *ebpf.Map) *lostEventsCollector {
	return &lostEventsCollector{
		m: m,
		desc: prometheus.NewDesc(
			"tcp_lost_events_total",
			"Lost events by reason.",
			[]string{"reason"}, nil,
		),
	}
}

func (lec *lostEventsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- lec.desc
}

func (lec *lostEventsCollector) Collect(ch chan<- prometheus.Metric) {
	for i, reason := range lostReasons {
		var perCPU []uint64
		if err := lec.m.Lookup(uint32(i), &perCPU); err != nil {
			log.Printf("reading %s counter: %v", reason, err)
			continue
		}

		var total uint64
		for _, v := range perCPU {
			total += v
		}

		ch <- prometheus.MustNewConstMetric(
			lec.desc, prometheus.CounterValue, float64(total), reason,
		)
	}
}

func main() {
	objs := bpfObjects{}

	if err := loadBpfObjects(&objs, nil); err != nil {

		log.Fatalf("loading objects: %v", err)

	}

	defer objs.Close()

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleTcpState, nil)

	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}

	defer tp.Close()

	reg := prometheus.NewRegistry()
	m := newMetrics(reg, objs.LostEvents)

	//para leer el ringbuf
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	//go routine for ring buffer
	go func() {
		var event TCPEvent

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

			srcIP := net.IP(event.Saddr[:])
			dstIP := net.IP(event.Daddr[:])

			log.Printf(
				"TCP %s:%d -> %s:%d | latency=%d ns",
				srcIP,
				event.SrcPort,
				dstIP,
				event.DstPort,
				event.LatencyNs,
			)

			m.latencyHistogram.Observe(float64(event.LatencyNs) / 1e9)
		}
	}()

	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	http.ListenAndServe(":2112", nil)
}
