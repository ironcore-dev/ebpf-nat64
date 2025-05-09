// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	UPDATE_INTERVAL = 1 // sec
)

var (
	mapElemCountGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_map_elem_count",
			Help: "Current number of elements in eBPF maps, labeled by map ID and name",
		},
		[]string{"id", "name"},
	)

	mapPressureGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_map_pressure",
			Help: "Current pressure of eBPF maps (currElements / maxElements), labeled by map ID and name",
		},
		[]string{"id", "name"},
	)
	
	exporterStatsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_exporter_stats",
			Help: "Current value of exposed NAT64 kernel module stats, labeled by map ID and stats name",
		},
		[]string{"id", "name"},
	)

)

func main() {
	reg := prometheus.NewRegistry()
	reg.MustRegister(mapElemCountGauge)
	reg.MustRegister(mapPressureGauge)
	reg.MustRegister(exporterStatsGauge) 

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}


	objs := exporterObjects{}
	if err := loadExporterObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf", // Specify the pin path
		},
	}); err != nil {
		log.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	// Attach the first program to the Iterator hook.
	iterLinkStatsMapElement, err := link.AttachIter(link.IterOptions{
		Map: objs.exporterMaps.Nat64StatsMap,
		Program: objs.exporterPrograms.DumpExporterStatsMap,
	})
	if err != nil {
		log.Fatalf("Failed to attach StatsMapElement eBPF program: %v", err)
	}
	defer iterLinkStatsMapElement.Close()
	log.Println("StatsMapElement eBPF program attached successfully.")

	// Attach the second program to the Iterator hook.
	iterLinkMapFullness, err := link.AttachIter(link.IterOptions{
		Program: objs.exporterPrograms.DumpNat64MapFullness, // Replace with your second program
	})
	if err != nil {
		log.Fatalf("Failed to attach MapFullness eBPF program: %v", err)
	}
	defer iterLinkMapFullness.Close()
	log.Println("MapFullness eBPF program attached successfully.")

	// Start HTTP server for Prometheus metrics
	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	http.Handle("/metrics", handler)
	go func() {
		log.Fatal(http.ListenAndServe(":2112", nil))
	}()
	log.Println("Prometheus HTTP server started on :2112")

	// Keep the program running.
	for {
		time.Sleep(UPDATE_INTERVAL * time.Second)

		// Open readers for both iterators
		readerStatsMapElement, err := iterLinkStatsMapElement.Open()
		if err != nil {
			log.Fatalf("Failed to open StatsMapElement BPF iterator: %v", err)
		}
		defer readerStatsMapElement.Close()

		readerMapFullness, err := iterLinkMapFullness.Open()
		if err != nil {
			log.Fatalf("Failed to open MapFullness BPF iterator: %v", err)
		}
		defer readerMapFullness.Close()

		// Process the output from the first iterator
		scannerStatsMapElement := bufio.NewScanner(readerStatsMapElement)
		for scannerStatsMapElement.Scan() {
			line := scannerStatsMapElement.Text()
				// Variables to store the parsed values
				var id int
				var name string
				var dropPkts int64
				var dropFlows int64
				var acceptedFlows int64

				// // Parse the line
				length, err := fmt.Sscanf(line, "map_id=%4d map_name=%s drop_pkts=%10d drop_flows=%10d accepted_flows=%10d", &id, &name, &dropPkts, &dropFlows, &acceptedFlows)
				if err != nil || length != 5 {
					log.Fatal(err)
				}

				// Update the metrics
				idStr := fmt.Sprintf("%d", id)
				exporterStatsGauge.WithLabelValues(idStr, "drop_pkts").Set(float64(dropPkts))
				exporterStatsGauge.WithLabelValues(idStr, "drop_flows").Set(float64(dropFlows))
				exporterStatsGauge.WithLabelValues(idStr, "accepted_flows").Set(float64(acceptedFlows))
		}

		if err := scannerStatsMapElement.Err(); err != nil {
			log.Fatal(err)
		}

		// Process the output from the second iterator
		scannerMapFullness := bufio.NewScanner(readerMapFullness)
		for scannerMapFullness.Scan() {
			line := scannerMapFullness.Text()
				// Variables to store the parsed values
			var id int
			var mapName string
			var maxElements int
			var currElements int64

			// Parse the line
			length, err := fmt.Sscanf(line, "map_id=%4d map_name=%s max_entries=%10d curr_elements=%10d", &id, &mapName, &maxElements, &currElements)
			if err != nil || length != 4 {
				log.Fatal(err)
			}

			// Update the metrics
			idStr := fmt.Sprintf("%d", id)
			mapElemCountGauge.WithLabelValues(idStr, mapName).Set(float64(currElements))
			mapPressureGauge.WithLabelValues(idStr, mapName).Set(float64(currElements) / float64(maxElements))
			
		}

		if err := scannerMapFullness.Err(); err != nil {
			log.Fatal(err)
		}
	}
}
