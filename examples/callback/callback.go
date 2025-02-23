package main

import (
	"fmt"
	"time"

	"tracelib"
)

// printStep formats and prints trace results for each hop.
func printStep(hop tracelib.Hop, num int, round int) {
	fmt.Printf("%d.(%d) %v(%s)/AS%d %v (final:%v timeout:%v error:%v down:%v)\n",
		num, round, hop.Host, hop.Addr, hop.AS, hop.RTT, hop.Final, hop.Timeout, hop.Error, hop.Down)
}

func main() {
	// Create a DNS/AS lookup cache
	cache := tracelib.NewLookupCache()

	fmt.Println("Single round trace (ICMP)")
	_, err := tracelib.RunTrace(
		"google.com",
		"0.0.0.0",  // IPv4 source address
		"::",        // IPv6 source address
		time.Second, // Max RTT
		64,          // Max TTL
		cache,       // Lookup cache
		printStep,   // Callback function for printing each hop
		tracelib.ProtoICMP, // Use ICMP protocol
		0,          // No port needed for ICMP
	)
	if err != nil {
		fmt.Println("Traceroute error:", err)
		return
	}

	fmt.Println("Multi round trace (udp)")
	_, err = tracelib.RunMultiTrace(
		"google.com",
		"0.0.0.0",  // IPv4 source address
		"::",        // IPv6 source address
		time.Second, // Max RTT
		64,          // Max TTL
		cache,       // Lookup cache
		3,           // Number of rounds per TTL
		printStep,   // Callback function for printing each hop
		tracelib.ProtoUDP, // Use ICMP protocol
		33434,          // No port needed for ICMP
	)
	if err != nil {
		fmt.Println("Traceroute error:", err)
		return
	}
}
