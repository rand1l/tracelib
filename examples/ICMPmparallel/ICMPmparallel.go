package main

import (
	"fmt"
	"strings"
	"time"

	"tracelib"
)

func main() {
	// Create a DNS/AS lookup cache
	cache := tracelib.NewLookupCache()

	// Run parallel traceroute for multiple hosts using ICMP
	rawMHops, err := tracelib.RunMPTrace(
		[]string{"google.com", "yandex.ru", "skorochod.cz"}, // Target hosts
		"0.0.0.0",  // Source IPv4 address (auto-selected if empty)
		"::",       // Source IPv6 address (auto-selected if empty)
		time.Second, // Maximum RTT
		32,         // Maximum TTL
		cache,      // DNS/AS cache (can be nil)
		10,         // Number of rounds per TTL
		100,        // Initial ICMP identifier (startID)
		time.Millisecond, // Delay between sending packets
		tracelib.ProtoICMP, // Selected protocol (ICMP)
		80,         // Destination port (used for TCP, ignored for ICMP)
	)
	if err != nil {
		fmt.Println("Traceroute error:", err)
		return
	}

	// Iterate over results for each host
	for host, rawHops := range rawMHops {
		fmt.Println("Trace to", host)

		// Aggregate results across multiple rounds
		hops := tracelib.AggregateMulti(*rawHops)

		// Print the results for each hop
		for i, hop := range hops {
			isd := fmt.Sprintf("%d. ", i+1)
			isp := strings.Repeat(" ", len(isd))
			for j, h := range hop {
				prefix := isd
				if j > 0 {
					prefix = isp
				}
				if h.Addr != nil {
					fmt.Printf("%s%v (%s)/AS%d RTT(avg:%v, min:%v, max:%v) (final:%v, lost %d of %d, down %d of %d)\n",
						prefix, h.Host, h.Addr, h.AS, h.AvgRTT, h.MinRTT, h.MaxRTT, h.Final, h.Lost, h.Total, h.Down, h.Total)
				} else {
					fmt.Printf("%s Lost: %d\n", prefix, h.Lost)
				}
			}
		}
	}
}
