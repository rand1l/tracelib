package main

import (
	"fmt"
	"time"

	"github.com/rand1l/tracelib"
)

func main() {
	// Initialize DNS/AS lookup cache
	cache := tracelib.NewLookupCache()

	// Run multiple-round traceroute using ICMP
	rawHops, err := tracelib.RunMultiTrace(
		"google.com",  // Target host
		"0.0.0.0",        // Source IPv4 address (auto-selected if empty)
		"::",             // Source IPv6 address (auto-selected if empty)
		time.Second,      // Maximum RTT
		64,               // Maximum TTL
		cache,            // DNS/AS cache (can be nil)
		10,               // Number of attempts per TTL
		nil,              // Callback function (not used in this example)
		tracelib.ProtoUDP, // Selected protocol (ICMP, UDP, or TCP)
		33434,                // Destination port (not used for ICMP)
	)
	if err != nil {
		fmt.Println("Traceroute error:", err)
		return
	}

	// Aggregate results across multiple rounds
	hops := tracelib.AggregateMulti(rawHops)

	// Iterate through aggregated results for each TTL
	for i, ttlHops := range hops {
		prefix := fmt.Sprintf("%d. ", i+1)
		for _, h := range ttlHops {
			if h.Addr != nil {
				// Print aggregated data including host, IP, AS, RTT, and final status
				fmt.Printf("%s%v (%s)/AS%d RTT:%v (final:%v) [min:%v, max:%v, lost %d of %d, down %d of %d]\n",
					prefix, h.Host, h.Addr, h.AS, h.AvgRTT, h.Final, h.MinRTT, h.MaxRTT, h.Lost, h.Total, h.Down, h.Total)
			} else {
				fmt.Printf("%s Lost\n", prefix)
			}
		}
	}
}
