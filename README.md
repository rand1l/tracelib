# tracelib
Traceroute implementation in Go supporting multi round trace (return min/max/avg/lost) and AS number detection for both IPv4 and IPv6. Supports multiple protocols (ICMP, UDP, and TCP) for probing. An experimental parallel traceroute implementation is included, which sends all packets with all possible Tls at once so that the total traceroute time is always equal to MaxRTT. See examples/parallel for more info.  
Note: The ptrace functionality is currently implemented only for ICMP and may require further improvements. See examples

Usage example of regular traceroute
```go
	cache := tracelib.NewLookupCache()
	hops, err := tracelib.RunTrace("google.com", "0.0.0.0", "::", 5*time.Second, 30, nil, nil, tracelib.ProtoTCP, 80)

	if err != nil {
		fmt.Println("Trace error:", err)
		return
	}

	fmt.Println("\n--- TCP Trace Results ---")
	for i, hop := range hops {
		fmt.Printf("%2d: %+v\n", i+1, hop)
	}
```
