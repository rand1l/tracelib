package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/rand1l/tracelib"
)

func main() {
	// Initialize DNS/AS lookup cache
	cache := tracelib.NewLookupCache()

	// Run parallel traceroute using UDP
	rawHops, err := tracelib.RunPTrace(
		"google.com",      // Target host
		"0.0.0.0",         // Source IPv4 address (auto-selected if empty)
		"::",              // Source IPv6 address (auto-selected if empty)
		time.Second,       // Maximum RTT
		32,                // Maximum TTL
		cache,             // DNS/AS cache (can be nil)
		10,                // Number of attempts per TTL
		tracelib.ProtoICMP, // Selected protocol (ICMP, UDP, or TCP)
		100,               // ICMP identifier
		0,             // Destination port for UDP (default for traceroute)
		time.Millisecond,   // Delay between sending packets
	)
	if err != nil {
		fmt.Println("Traceroute error:", err)
		return
	}

	// Aggregate results from multiple rounds
	hops := tracelib.AggregateMulti(rawHops)

	// Print aggregated results for each TTL
	for i, ttlHops := range hops {
		prefix := fmt.Sprintf("%d. ", i+1)
		for j, hop := range ttlHops {
			pfx := prefix
			if j > 0 {
				pfx = strings.Repeat(" ", len(prefix))
			}
			if hop.Addr != nil {
				// Print hop details including RTT and packet loss stats
				fmt.Printf("%s%v (%s)/AS%d RTT(avg:%v, min:%v, max:%v) (final:%v, lost %d of %d, down %d of %d)\n",
					pfx, hop.Host, hop.Addr, hop.AS, hop.AvgRTT, hop.MinRTT, hop.MaxRTT, hop.Final, hop.Lost, hop.Total, hop.Down, hop.Total)
			} else {
				fmt.Printf("%s Lost: %d\n", pfx, hop.Lost)
			}
		}
	}
}

