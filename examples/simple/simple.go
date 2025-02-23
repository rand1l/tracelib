package main

import (
	"fmt"
	"time"

	"tracelib"
)

func main() {
	// Callback function to print each hop's result
	cb := func(hop tracelib.Hop, ttl, round int) {
		if hop.Timeout {
			fmt.Printf("%2d. * * * (timeout)\n", ttl)
		} else if hop.Error != nil {
			fmt.Printf("%2d. Error: %v\n", ttl, hop.Error)
		} else {
			fmt.Printf("%2d. %v (%v) rtt=%v final=%v\n",
				ttl, hop.Host, hop.Addr, hop.RTT, hop.Final)
		}
	}

	cache := tracelib.NewLookupCache()
	// Run single-round traceroute using TCP
	hops, err := tracelib.RunTrace(
		"google.com",            // target host
		"0.0.0.0",               // source IPv4 address (auto-selected if empty)
		"::",                    // source IPv6 address (auto-selected if empty)
		5*time.Second,           // maximum RTT
		30,                      // maximum TTL
		cache,                     // LookupCache (nil for now)
		cb,                      // callback function
		tracelib.ProtoTCP,       // Selected protocol (TCP)
		80,                      // destination port
	)
	if err != nil {
		fmt.Println("Trace error:", err)
		return
	}

	fmt.Println("\n--- Final TCP Trace Results ---")
	for i, hop := range hops {
		fmt.Printf("%2d: %+v\n", i+1, hop)
	}
}
