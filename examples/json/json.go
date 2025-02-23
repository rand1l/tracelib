package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/rand1l/tracelib"
)

type mtrhHost struct {
	IP   string `json:"ip"`
	Host string `json:"host"`
	AS   int64  `json:"as"`
	Min  string `json:"min"`
	Avg  string `json:"avg"`
	Max  string `json:"max"`
	Rcvd int    `json:"received"`
}

func doTrace(host string) ([]byte, error) {
	// Create a cache for lookups
	cache := tracelib.NewLookupCache()

	// Run the trace with the specified parameters
	rawHops, err := tracelib.RunMultiTrace(
		host,
		"0.0.0.0",  // IPv4 source address
		"::",        // IPv6 source address
		time.Second, // Max RTT
		64,          // Max TTL
		cache,       // Cache for lookups
		10,          // Number of rounds
		nil,         // No callback
		tracelib.ProtoTCP, // Use TCP protocol
		80,          // Target port (for TCP)
	)
	if err != nil {
		return nil, err
	}

	// Aggregate the raw trace data
	hops := tracelib.AggregateMulti(rawHops)

	// Prepare the final result in a suitable format for JSON output
	result := make([][]mtrhHost, 0, len(hops))
	for _, hop := range hops {
		nextSlice := make([]mtrhHost, 0, len(hop))
		for _, h := range hop {
			// Skip if no address was returned for this hop
			if h.Addr == nil {
				continue
			}
			// Prepare hop data for output
			next := mtrhHost{
				AS:   h.AS,
				IP:   h.Addr.String(),
				Host: h.Host,
				Avg:  fmt.Sprintf("%.2f", float64(h.AvgRTT)/float64(time.Millisecond)),
				Max:  fmt.Sprintf("%.2f", float64(h.MaxRTT)/float64(time.Millisecond)),
				Min:  fmt.Sprintf("%.2f", float64(h.MinRTT)/float64(time.Millisecond)),
			}
			// Calculate received packet percentage
			if h.Total == 0 {
				next.Rcvd = 0
			} else {
				next.Rcvd = (100 * h.Total) / 10
			}
			nextSlice = append(nextSlice, next)
		}
		result = append(result, nextSlice)
	}

	// Marshal result into JSON
	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}
	return out, nil
}

func main() {
	// Perform the trace and get the JSON result
	j, err := doTrace("google.com")
	if err != nil {
		log.Fatalln("Error:", err)
	}
	// Print the formatted JSON output
	fmt.Println(string(j))
}
