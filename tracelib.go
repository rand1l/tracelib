package tracelib

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Protocol int

const (
	ProtoICMP Protocol = iota // iota identifier is used in const declarations to simplify definitions of incrementing numbers. // 0
	ProtoUDP				  																									// 1
	ProtoTCP				  																									// 2
)

const (
	ProtocolICMP  = 1
	ProtocolICMP6 = 58
)

// MaxTimeouts sets number of hops without replay before trace termination
const MaxTimeouts = 3

// trace stores the trace state
type trace struct {
	conn     net.PacketConn // main connection for sending and receiving packets (socket)

	// Wrappers that add extra features, like setting TTL or control messages
	ipv4conn *ipv4.PacketConn
	ipv6conn *ipv6.PacketConn

	// for ICMP
	msg    icmp.Message // default ICMP message for sending
	netmsg []byte       // Serialized ICMP message as a byte slice


	id     int           // Random ID to match outgoing requests with incoming responses. Used fot Identifier field in packet (used in ICMP Echo, in tcp and udp - ports)
	maxrtt time.Duration // Max round-trip time
	maxttl int
	dest   net.Addr

	proto      Protocol // ProtoICMP, ProtoTCP, ProtoUDP
	destPort   int
	sourcePort int
	rawConn    net.PacketConn // used for UDP/TCP (raw socket)
	isIPv6     bool

	// default and goal IP (for formation of packet headers)
	srcIP net.IP
	dstIP net.IP
}

// Hop represents each hop of the trace
type Hop struct {
	Addr    net.Addr       // hop IP
	Host    string         // Optional - resolved from DNS cache
	AS      int64          // Autonomous system number if using LookupCache
	RTT     time.Duration  // Round-trip time for this hop
	Final   bool
	Timeout bool
	Down    bool           // true if hop is unreachable (e.g. Destination Unreachable)
	Error   error
}

// Callback function called after every hop is received
type Callback func(info Hop, hopnum int, round int)

// RunTrace starts a traceroute to the specified host using the chosen protocol.
// source4/source6 – source addresses (if empty, selected automatically).
// destPort is used for UDP and TCP.
func RunTrace(
	host string,
	source4 string,        // source IPv4 (e.g. "0.0.0.0")
	source6 string,        // source IPv6 (e.g. "::")
	maxrtt time.Duration,  // maximum round-trip time
	maxttl int,            // maximum TTL value
	DNScache *LookupCache, // may be nil; defined in tools.go
	cb Callback,
	proto Protocol, 		// ProtoICMP, ProtoUDP, ProtoTCP
	destPort int,   		// destination port (for UDP/TCP)
) ([]Hop, error) {
	var tr trace
	tr.proto = proto
	tr.destPort = destPort
	tr.maxrtt = maxrtt
	tr.maxttl = maxttl
	// Limit ID to 16 bits fot Identifier field in packet (used in ICMP Echo, in tcp and udp - ports)
	tr.id = rand.Int() & 0xffff

	// Determine target IP (try IPv4 first, then IPv6)
	dstIP, isV6, err := resolveIP(host)
	if err != nil {
		return nil, err
	}
	tr.isIPv6 = isV6
	tr.dstIP = dstIP

	// If source4/source6 is not provided, the default routing interface is defined by function findSrcAddrForDst.
	var srcIP net.IP
	if !tr.isIPv6 {
		if source4 != "" && source4 != "0.0.0.0" {
			// Converts it to IPv4 format (4-byte representation)
			srcIP = net.ParseIP(source4).To4()
		} else {
			srcIP, err = findSrcAddrForDst(dstIP)
			if err != nil {
				return nil, fmt.Errorf("cannot get local IPv4 for %v: %w", dstIP, err)
			}
		}
		if srcIP == nil {
			return nil, errors.New("invalid IPv4 source address")
		}
		tr.srcIP = srcIP.To4()
	} else {
		if source6 != "" && source6 != "::" {
			srcIP = net.ParseIP(source6).To16()
		} else {
			srcIP, err = findSrcAddrForDst(dstIP)
			if err != nil {
				return nil, fmt.Errorf("cannot get local IPv6 for %v: %w", dstIP, err)
			}
		}
		if srcIP == nil {
			return nil, errors.New("invalid IPv6 source address")
		}
		tr.srcIP = srcIP.To16()
	}

	// 	Get net.Addr for destination
	/* net.ResolveIPAddr is used to obtain the destination network address (tr.dest).
		It returns a net.IPAddr (net.IP + Zone for IPv6 link-local addresses).
		This is necessary because tr.dest is passed to net.PacketConn.WriteTo(), 
		which requires an address implementing net.Addr.*/
	if !tr.isIPv6 {
		tr.dest, err = net.ResolveIPAddr("ip4", tr.dstIP.String())
	} else {
		tr.dest, err = net.ResolveIPAddr("ip6", tr.dstIP.String())
	}
	if err != nil {
		return nil, err
	}

	// Create socket for receiving ICMP replies (e.g. Time Exceeded, Destination Unreachable)
	if !tr.isIPv6 {
		// Open raw connect for listening icmp packets
		tr.conn, err = net.ListenPacket("ip4:icmp", source4)
		if err != nil {
			return nil, fmt.Errorf("listen icmp4 error: %w", err)
		}
		// wraps net.PacketConn into a more convenient ipv4.PacketConn structure
		tr.ipv4conn = ipv4.NewPacketConn(tr.conn)
	} else {
		tr.conn, err = net.ListenPacket("ip6:58", source6)
		if err != nil {
			return nil, fmt.Errorf("listen icmp6 error: %w", err)
		}
		tr.ipv6conn = ipv6.NewPacketConn(tr.conn)
	}
	defer tr.conn.Close()
	if tr.ipv4conn != nil {
		defer tr.ipv4conn.Close()
	} else if tr.ipv6conn != nil {
		defer tr.ipv6conn.Close()
	}

	// If ICMP is used, the code generates an ICMP Echo Request to send to the target host.
	if tr.proto == ProtoICMP {
		if tr.isIPv6 {
			tr.msg = icmp.Message{
				Type: ipv6.ICMPTypeEchoRequest, Code: 0,
				Body: &icmp.Echo{ID: tr.id, Seq: 1}, // Seq is fixed because packet identification is done using TTL and ID, so its value is not relevant.
			}
		} else {
			tr.msg = icmp.Message{
				Type: ipv4.ICMPTypeEcho, Code: 0,
				Body: &icmp.Echo{ID: tr.id, Seq: 1}, // Seq is fixed because packet identification is done using TTL and ID, so its value is not relevant.
			}
		}
		tr.netmsg, err = tr.msg.Marshal(nil)		 // Transform tr.msg into a byte slice tr.netmsg, prepared for transmission.
		if err != nil {
			return nil, err
		}
	} else {
		var protoNum string

		/* Determine the protocol number for the raw socket based on the selected protocol (UDP/TCP)
		 and the IP version (IPv4/IPv6). This is necessary for creating a raw socket with net.ListenPacket(). 
		 Raw sockets require specifying the protocol explicitly to filter the correct packet types*/
		if tr.proto == ProtoUDP {
			if tr.isIPv6 {
				protoNum = "ip6:17" // - "ip4:17" -> UDP over IPv4 (protocol number 17 in the IP header)
			} else {
				protoNum = "ip4:17" // - "ip6:17" -> UDP over IPv6 (protocol number 17 in the IP header)
			}
		} else { // TCP
			if tr.isIPv6 {
				protoNum = "ip6:6" // - "ip4:6"  -> TCP over IPv4 (protocol number 6 in the IP header)
			} else {
				protoNum = "ip4:6" // - "ip6:6"  -> TCP over IPv6 (protocol number 6 in the IP header)
			}
		}
		tr.rawConn, err = net.ListenPacket(protoNum, "")	// Opens a raw socket for direct interaction with IP layer protocols.
		if err != nil {
			return nil, fmt.Errorf("cannot open raw socket (%s): %w", protoNum, err)
		}
		defer tr.rawConn.Close()

		// Set source port
		tr.sourcePort = 40000 + rand.Intn(2000)

		// For IPv4 raw sockets, set IP_HDRINCL option using setIPv4HeaderIncl for manual header creation.
		if !tr.isIPv6 {
			if err := setIPv4HeaderIncl(tr.rawConn); err != nil {
				return nil, fmt.Errorf("set IP_HDRINCL error: %w", err)
			}
		}
	}

	// For IPv6, control messages are used. Transmission of Hop Limit (equivalent to TTL), destination IP flag, source IP is enabled.
	if tr.ipv6conn != nil {
		tr.ipv6conn.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagDst|ipv6.FlagSrc, true)
	}

	// Main loop over TTL
	var hops []Hop						// Slice for all discovered hops
	hops = make([]Hop, 0, tr.maxttl)	// pre-allocates memory for hops with maximum capacity equal to tr.maxttl
	timeouts := 0						// if it reaches MaxTimeouts, break

	for i := 1; i <= tr.maxttl; i++ {
		hop := tr.step(i)
		if hop.Error != nil {
			hops = append(hops, hop)
			break
		}

		if hop.Addr != nil && DNScache != nil {
			addrString := hop.Addr.String()
			hop.Host = DNScache.LookupHost(addrString)
			hop.AS = DNScache.LookupAS(addrString)
		}

		if cb != nil {
			cb(hop, i, 1)
		}
		hops = append(hops, hop)	// add hop data

		if hop.Final {
			break
		}
		if hop.Timeout {
			timeouts++
		} else {
			timeouts = 0
		}
		if timeouts >= MaxTimeouts {
			break
		}
	}
	return hops, nil
}

// Step sends one packet with the given TTL and waits for a reply.
func (t *trace) step(ttl int) Hop {
	var hop Hop

	if err := t.conn.SetReadDeadline(time.Now().Add(t.maxrtt)); err != nil {	// max round-trip time set
		hop.Error = err
		return hop
	}

	sendTime := time.Now()														// fix current time for calc RTT

	// For ICMP (IPv4) use SetTTL.
	if t.ipv4conn != nil && t.proto == ProtoICMP {
		if err := t.ipv4conn.SetTTL(ttl); err != nil {							// time-to-live set
			hop.Error = err
			return hop
		}
	}

	// Send packet according to the selected protocol.
	var err error
	switch t.proto {
	case ProtoICMP:
		err = t.sendICMP(ttl)
	case ProtoUDP:
		err = t.sendUDP(ttl)
	case ProtoTCP:
		err = t.sendTCP(ttl)
	}
	if err != nil {
		hop.Error = err
		return hop
	}

	// Wait for an ICMP reply.
	buf := make([]byte, 1500)	// 1500 byte - default MTU
	for {
		n, addr, err2 := t.conn.ReadFrom(buf)
		if neterr, ok := err2.(net.Error); ok && neterr.Timeout() {
			// if ReadFrom timeout
			hop.Timeout = true
			return hop
		}
		if err2 != nil {
			// if successful response
			hop.Error = err2
			return hop
		}

		hop.RTT = time.Since(sendTime)
		hop.Addr = addr

		var im *icmp.Message
		if t.isIPv6 {
			im, err = icmp.ParseMessage(ProtocolICMP6, buf[:n])
		} else {
			im, err = icmp.ParseMessage(ProtocolICMP, buf[:n])
		}
		if err != nil {
			continue
		}

		switch im.Type {
		case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:						// The packet reached the router and the TTL expired.
			if t.isOurPacket(im.Body) {
				return hop
			}
		case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:	
			if t.isOurPacket(im.Body) {
				hop.Final = true
				hop.Down = true
				return hop
			}
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:							// final hop reply
			if t.proto == ProtoICMP && t.isOurPacket(im.Body) {
				hop.Final = true
				return hop
			}
		default:
			// Ignore other messages (e.g. Redirect, Source Quench)
		}
	}
}

func (t *trace) isOurPacket(body icmp.MessageBody) bool {
	switch b := body.(type) {
	case *icmp.TimeExceeded:															// If this is a Time Exceeded message, b.Data contains a copy of the original packet's header.
		return t.matchPacket(b.Data)
	case *icmp.DstUnreach:																// also for Destination Unreachable
		return t.matchPacket(b.Data)
	case *icmp.Echo:																	// if echoreply сompare with the unique ID.
		return b.ID == t.id
	}
	return false
}

// matchPacket extracts the embedded IP+L4 header and checks ports/ID.
func (t *trace) matchPacket(data []byte) bool {
	if len(data) < 28 {																	// min IPv4 header Length (20) + Protocol (8)
		return false
	}
	if !t.isIPv6 {
		protocol := data[9]																// 9 - byte shift for protocol field
		ihl := (data[0] & 0x0F) * 4														// header length in byte
		if int(ihl) < 20 || len(data) < int(ihl)+8 {
			return false
		}
		l4 := data[ihl:]																// L4 header
		switch t.proto {
		case ProtoICMP:																	// Check id
			if protocol == 1 && len(l4) >= 6 {
				id := binary.BigEndian.Uint16(l4[4:6])
				return id == uint16(t.id)
			}
		case ProtoUDP:
			if protocol == 17 && len(l4) >= 4 {											// Check the ports match
				sport := binary.BigEndian.Uint16(l4[0:2])
				dport := binary.BigEndian.Uint16(l4[2:4])
				return int(sport) == t.sourcePort && int(dport) == t.destPort
			}
		case ProtoTCP:
			if protocol == 6 && len(l4) >= 4 {											// Check the ports match
				sport := binary.BigEndian.Uint16(l4[0:2])
				dport := binary.BigEndian.Uint16(l4[2:4])
				return int(sport) == t.sourcePort && int(dport) == t.destPort
			}
		}
	} else {
		// For IPv6, IP header is 40 bytes.
		if (data[0] >> 4) != 6 {
			return false
		}
		nextHeader := data[6]
		ipHeaderLen := 40
		if len(data) < ipHeaderLen+8 {
			return false
		}
		l4 := data[ipHeaderLen:]
		switch t.proto {
		case ProtoICMP:
			if nextHeader == 58 && len(l4) >= 6 {
				id := binary.BigEndian.Uint16(l4[4:6])
				return id == uint16(t.id)
			}
		case ProtoUDP:
			if nextHeader == 17 && len(l4) >= 4 {
				sport := binary.BigEndian.Uint16(l4[0:2])
				dport := binary.BigEndian.Uint16(l4[2:4])
				return int(sport) == t.sourcePort && int(dport) == t.destPort
			}
		case ProtoTCP:
			if nextHeader == 6 && len(l4) >= 4 {
				sport := binary.BigEndian.Uint16(l4[0:2])
				dport := binary.BigEndian.Uint16(l4[2:4])
				return int(sport) == t.sourcePort && int(dport) == t.destPort
			}
		}
	}
	return false
}

//------------------ Packet Sending --------------------

// sendICMP sends an ICMP packet.
func (t *trace) sendICMP(ttl int) error {
	if t.isIPv6 {
		if t.ipv6conn == nil {
			return errors.New("ipv6conn is nil for ICMPv6")
		}
		cm := &ipv6.ControlMessage{HopLimit: ttl}
		_, err := t.ipv6conn.WriteTo(t.netmsg, cm, t.dest)
		return err
	} else {
		if t.ipv4conn == nil {
			return errors.New("ipv4conn is nil for ICMPv4")
		}
		_, err := t.conn.WriteTo(t.netmsg, t.dest)
		return err
	}
}

// sendUDP builds and sends a UDP packet.
func (t *trace) sendUDP(ttl int) error {
	payload := []byte("GoTraceroute")
	pkt, err := buildTransportPacket(
		t.isIPv6,
		ttl,
		t.srcIP,
		t.dstIP,
		uint16(t.sourcePort),
		uint16(t.destPort),
		payload,
		ProtoUDP,
	)
	if err != nil {
		return err
	}
	_, err = t.rawConn.WriteTo(pkt, t.dest)
	return err
}

// sendTCP builds and sends a TCP SYN packet (without payload).
func (t *trace) sendTCP(ttl int) error {
	payload := []byte{}
	pkt, err := buildTransportPacket(
		t.isIPv6,
		ttl,
		t.srcIP,
		t.dstIP,
		uint16(t.sourcePort),
		uint16(t.destPort),
		payload,
		ProtoTCP,
	)
	if err != nil {
		return err
	}
	_, err = t.rawConn.WriteTo(pkt, t.dest)
	return err
}

// buildTransportPacket constructs a complete packet (IP header + transport header) with proper checksums.
func buildTransportPacket(
	isIPv6 bool,
	ttl int,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	payload []byte,
	proto Protocol,
) ([]byte, error) {
	if !isIPv6 {
		return buildIPv4Packet(ttl, srcIP.To4(), dstIP.To4(), srcPort, dstPort, payload, proto)
	}
	return buildIPv6Packet(ttl, srcIP.To16(), dstIP.To16(), srcPort, dstPort, payload, proto)
}

//------------------- IPv4 Packet Building -------------------------

func buildIPv4Packet(
	ttl int,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	payload []byte,
	proto Protocol,
) ([]byte, error) {
	var l4Header []byte
	var err error

	switch proto {
	case ProtoUDP:
		l4Header, err = buildUDPHeaderIPv4(srcIP, dstIP, srcPort, dstPort, payload)
	case ProtoTCP:
		l4Header, err = buildTCPHeaderIPv4(srcIP, dstIP, srcPort, dstPort, payload)
	default:
		return nil, errors.New("unsupported proto for raw IPv4")
	}
	if err != nil {
		return nil, err
	}

	ipHeader, err := buildIPv4Header(srcIP, dstIP, ttl, byte(l4Proto(proto)), 20+len(l4Header))
	if err != nil {
		return nil, err
	}

	packet := append(ipHeader, l4Header...)
	return packet, nil
}

func buildIPv4Header(srcIP, dstIP net.IP, ttl int, nextProto byte, totalLength int) ([]byte, error) {
	ip := make([]byte, 20)									 // ipv4 header size
	ip[0] = 0x45 											 // Version = 4, IHL = 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLength)) // total size packet (ip header + data)
	ip[8] = byte(ttl)
	ip[9] = nextProto										 // protocol
	copy(ip[12:16], srcIP)									 
	copy(ip[16:20], dstIP)

	cs := checksum(ip)
	binary.BigEndian.PutUint16(ip[10:12], cs)				 // calc and write checksum 
	return ip, nil
}

func buildUDPHeaderIPv4(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	udpLen := 8 + len(payload)								 // protocol field size and payload
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)			 // write src ports
	binary.BigEndian.PutUint16(udp[2:4], dstPort)			 // write dst ports
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))	 // write packet length
	copy(udp[8:], payload)									 // copy payload

	cs := udpChecksumIPv4(srcIP, dstIP, udp)
	binary.BigEndian.PutUint16(udp[6:8], cs)
	return udp, nil
}

func buildTCPHeaderIPv4(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	baseLen := 20
	tcpLen := baseLen + len(payload)
	tcp := make([]byte, tcpLen)

	binary.BigEndian.PutUint16(tcp[0:2], srcPort)			 // write src ports
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)			 // write dst ports
	// Seq = 0, ACK = 0; DataOffset = 5 (20 bytes)
	tcp[12] = 0x50
	tcp[13] = 0x02 											 // SYN flag
	tcp[14] = 0x72 // window size
	tcp[15] = 0x10 // window size
	if len(payload) > 0 {
		copy(tcp[20:], payload)
	}

	cs := tcpChecksumIPv4(srcIP, dstIP, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], cs)
	return tcp, nil
}

//------------------- IPv6 Packet Building -------------------------

func buildIPv6Packet(
	ttl int,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	payload []byte,
	proto Protocol,
) ([]byte, error) {
	var l4Header []byte
	var err error
	switch proto {
	case ProtoUDP:
		l4Header, err = buildUDPHeaderIPv6(srcIP, dstIP, srcPort, dstPort, payload)
	case ProtoTCP:
		l4Header, err = buildTCPHeaderIPv6(srcIP, dstIP, srcPort, dstPort, payload)
	default:
		return nil, errors.New("unsupported proto for raw IPv6")
	}
	if err != nil {
		return nil, err
	}

	ip6 := make([]byte, 40)
	ip6[0] = 0x60 // Version = 6
	binary.BigEndian.PutUint16(ip6[4:6], uint16(len(l4Header))) // PayloadLength
	ip6[6] = l4Proto(proto)                                      // NextHeader
	ip6[7] = byte(ttl)                                           // HopLimit

	copy(ip6[8:24], srcIP)
	copy(ip6[24:40], dstIP)

	pkt := append(ip6, l4Header...)
	return pkt, nil
}

func buildUDPHeaderIPv6(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	udpLen := 8 + len(payload)									// header len (8) + payload
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)

	cs := udpChecksumIPv6(srcIP, dstIP, udp)
	if cs == 0 {												// If the sum is 0, replace it with 0xffff by the standard
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], cs)
	return udp, nil
}

func buildTCPHeaderIPv6(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	baseLen := 20
	tcpLen := baseLen + len(payload)							// header len (8) + payload
	tcp := make([]byte, tcpLen)

	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50
	tcp[13] = 0x02 // SYN
	tcp[14] = 0x72
	tcp[15] = 0x10
	if len(payload) > 0 {
		copy(tcp[20:], payload)
	}

	cs := tcpChecksumIPv6(srcIP, dstIP, tcp)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(tcp[16:18], cs)
	return tcp, nil
}

//------------------ Utility Functions ---------------------

func l4Proto(p Protocol) byte {									// L4 protocol number set
	switch p {
	case ProtoUDP:
		return 17
	case ProtoTCP:
		return 6
	default:
		return 1 // ICMP
	}
}

// checksum calculates the checksum for a given byte array.
/* 1. Splits the byte array into 16-bit words and sums them.
2. If the number of bytes is odd, the last byte is padded with zero.
3. If the sum exceeds 16 bits, the overflow (upper 16 bits) is added to the lower 16 bits (carry-around addition).
4. Inverts the result (^uint16(sum)) to produce the final checksum. */
func checksum(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(b)-1; i += 2 {			// Sum 16-bit words
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {							// If the byte count is odd, pad the last byte with zero
		sum += uint32(b[len(b)-1]) << 8
	}
	for (sum >> 16) != 0 {						// Perform carry-around addition
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)							// Invert the result
}

// Pseudo-headers are used in checksum calculations to include source/destination IPs, ensuring packet integrity.
// IPv4 pseudo-header for UDP
func udpChecksumIPv4(srcIP, dstIP net.IP, udp []byte) uint16 {
	ph := make([]byte, 12)
	copy(ph[0:4], srcIP)
	copy(ph[4:8], dstIP)
	ph[9] = 17
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(udp)))
	return transportChecksum(ph, udp)
}

// IPv4 pseudo-header for TCP
func tcpChecksumIPv4(srcIP, dstIP net.IP, tcp []byte) uint16 {
	ph := make([]byte, 12)
	copy(ph[0:4], srcIP)
	copy(ph[4:8], dstIP)
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(tcp)))
	return transportChecksum(ph, tcp)
}

// IPv6 pseudo-header for UDP
func udpChecksumIPv6(srcIP, dstIP net.IP, udp []byte) uint16 {
	ph := make([]byte, 40)
	copy(ph[0:16], srcIP)
	copy(ph[16:32], dstIP)
	binary.BigEndian.PutUint32(ph[32:36], uint32(len(udp)))
	ph[39] = 17
	return transportChecksum(ph, udp)
}

// IPv6 pseudo-header for TCP
func tcpChecksumIPv6(srcIP, dstIP net.IP, tcp []byte) uint16 {
	ph := make([]byte, 40)
	copy(ph[0:16], srcIP)
	copy(ph[16:32], dstIP)
	binary.BigEndian.PutUint32(ph[32:36], uint32(len(tcp)))
	ph[39] = 6
	return transportChecksum(ph, tcp)
}

func transportChecksum(ph, l4 []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(ph)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ph[i : i+2]))
	}
	if len(ph)%2 == 1 {
		sum += uint32(ph[len(ph)-1]) << 8
	}
	for i := 0; i < len(l4)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(l4[i : i+2]))
	}
	if len(l4)%2 == 1 {
		sum += uint32(l4[len(l4)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// resolveIP tries to find an IPv4 address first, then IPv6.
func resolveIP(host string) (net.IP, bool, error) {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return nil, false, err
	}
	var ipv4, ipv6 net.IP
	for _, a := range addrs {
		if v4 := a.To4(); v4 != nil {
			ipv4 = v4
			break
		}
	}
	if ipv4 != nil {
		return ipv4, false, nil
	}
	for _, a := range addrs {
		if v6 := a.To16(); v6 != nil && a.To4() == nil {
			ipv6 = v6
			break
		}
	}
	if ipv6 != nil {
		return ipv6, true, nil
	}
	return nil, false, fmt.Errorf("no suitable A/AAAA found for %s", host)
}

// findSrcAddrForDst determines the local IP for connecting to dstIP (using DialUDP)
func findSrcAddrForDst(dstIP net.IP) (net.IP, error) {
	var network string
	if dstIP.To4() != nil {
		network = "udp4"
	} else {
		network = "udp6"
	}
	conn, err := net.DialUDP(network, nil, &net.UDPAddr{IP: dstIP, Port: 12345})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

// setIPv4HeaderIncl sets the IP_HDRINCL option on an IPv4 raw socket.
func setIPv4HeaderIncl(conn net.PacketConn) error {
	type syscallConn interface {
		SyscallConn() (syscall.RawConn, error)
	}
	sc, ok := conn.(syscallConn)
	if !ok {
		return errors.New("failed to get syscall.RawConn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

// RunMultiTrace performs a traceroute to the specified host, sending multiple packets per TTL.
// For each TTL, it performs the specified number of rounds, aggregates the results into a 2D slice,
// and terminates if a final hop is reached or if consecutive timeouts exceed MaxTimeouts.
func RunMultiTrace(
	host string,
	source4 string,        // source IPv4 (e.g. "0.0.0.0")
	source6 string,        // source IPv6 (e.g. "::")
	maxrtt time.Duration,  // maximum RTT
	maxttl int,            // maximum TTL value
	DNScache *LookupCache, // may be nil
	rounds int,            // number of attempts per TTL
	cb Callback,
	proto Protocol, // ProtoICMP, ProtoUDP, ProtoTCP
	destPort int,   // destination port (for UDP/TCP)
) ([][]Hop, error) {
	var tr trace
	tr.proto = proto
	tr.destPort = destPort
	tr.maxrtt = maxrtt
	tr.maxttl = maxttl
	// Limit ID to 16 bits (used in ICMP Echo)
	tr.id = rand.Int() & 0xffff

	// 1. Determine target IP (try IPv4 first, then IPv6)
	dstIP, isV6, err := resolveIP(host)
	if err != nil {
		return nil, err
	}
	tr.isIPv6 = isV6
	tr.dstIP = dstIP

	// 2. Determine source IP
	var srcIP net.IP
	if !tr.isIPv6 {
		if source4 != "" && source4 != "0.0.0.0" {
			srcIP = net.ParseIP(source4).To4()
		} else {
			srcIP, err = findSrcAddrForDst(dstIP)
			if err != nil {
				return nil, fmt.Errorf("cannot get local IPv4 for %v: %w", dstIP, err)
			}
		}
		if srcIP == nil {
			return nil, errors.New("invalid IPv4 source address")
		}
		tr.srcIP = srcIP.To4()
	} else {
		if source6 != "" && source6 != "::" {
			srcIP = net.ParseIP(source6).To16()
		} else {
			srcIP, err = findSrcAddrForDst(dstIP)
			if err != nil {
				return nil, fmt.Errorf("cannot get local IPv6 for %v: %w", dstIP, err)
			}
		}
		if srcIP == nil {
			return nil, errors.New("invalid IPv6 source address")
		}
		tr.srcIP = srcIP.To16()
	}

	// 3. Get net.Addr for destination
	if !tr.isIPv6 {
		tr.dest, err = net.ResolveIPAddr("ip4", tr.dstIP.String())
	} else {
		tr.dest, err = net.ResolveIPAddr("ip6", tr.dstIP.String())
	}
	if err != nil {
		return nil, err
	}

	// 4. Create socket for receiving ICMP replies
	if !tr.isIPv6 {
		tr.conn, err = net.ListenPacket("ip4:icmp", source4)
		if err != nil {
			return nil, fmt.Errorf("listen icmp4 error: %w", err)
		}
		tr.ipv4conn = ipv4.NewPacketConn(tr.conn)
	} else {
		tr.conn, err = net.ListenPacket("ip6:58", source6)
		if err != nil {
			return nil, fmt.Errorf("listen icmp6 error: %w", err)
		}
		tr.ipv6conn = ipv6.NewPacketConn(tr.conn)
	}
	defer tr.conn.Close()
	if tr.ipv4conn != nil {
		defer tr.ipv4conn.Close()
	} else if tr.ipv6conn != nil {
		defer tr.ipv6conn.Close()
	}

	// 5. If using ICMP, prepare the message in advance.
	if tr.proto == ProtoICMP {
		if tr.isIPv6 {
			tr.msg = icmp.Message{
				Type: ipv6.ICMPTypeEchoRequest, Code: 0,
				Body: &icmp.Echo{ID: tr.id, Seq: 1}, // Seq is fixed because packet identification is done using TTL and ID, so its value is not relevant.
			}
		} else {
			tr.msg = icmp.Message{
				Type: ipv4.ICMPTypeEcho, Code: 0,
				Body: &icmp.Echo{ID: tr.id, Seq: 1}, // Seq is fixed because packet identification is done using TTL and ID, so its value is not relevant.
			}
		}
		tr.netmsg, err = tr.msg.Marshal(nil)		 // Transform tr.msg into a byte slice tr.netmsg, prepared for transmission.
		if err != nil {
			return nil, err
		}
	} else {
		// 6. For UDP/TCP – open a raw socket.
		var protoNum string

		/* Determine the protocol number for the raw socket based on the selected protocol (UDP/TCP)
		 and the IP version (IPv4/IPv6). This is necessary for creating a raw socket with net.ListenPacket(). 
		 Raw sockets require specifying the protocol explicitly to filter the correct packet types*/
		if tr.proto == ProtoUDP {
			if tr.isIPv6 {
				protoNum = "ip6:17" // - "ip4:17" -> UDP over IPv4 (protocol number 17 in the IP header)
			} else {
				protoNum = "ip4:17" // - "ip6:17" -> UDP over IPv6 (protocol number 17 in the IP header)
			}
		} else { // TCP
			if tr.isIPv6 {
				protoNum = "ip6:6" // - "ip4:6"  -> TCP over IPv4 (protocol number 6 in the IP header)
			} else {
				protoNum = "ip4:6" // - "ip6:6"  -> TCP over IPv6 (protocol number 6 in the IP header)
			}
		}
		tr.rawConn, err = net.ListenPacket(protoNum, "")
		if err != nil {
			return nil, fmt.Errorf("cannot open raw socket (%s): %w", protoNum, err)
		}
		defer tr.rawConn.Close()

		// Set source port
		tr.sourcePort = 40000 + rand.Intn(2000)

		// For IPv4 raw sockets, set IP_HDRINCL option using setIPv4HeaderIncl for manual header creation.
		if !tr.isIPv6 {
			if err := setIPv4HeaderIncl(tr.rawConn); err != nil {
				return nil, fmt.Errorf("set IP_HDRINCL error: %w", err)
			}
		}
	}

	// For IPv6, control messages are used. Transmission of Hop Limit (equivalent to TTL), destination IP flag, source IP is enabled.
	if tr.ipv6conn != nil {
		tr.ipv6conn.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagDst|ipv6.FlagSrc, true)
	}

	// Main loop over TTL with multiple rounds per hop.
	var hops [][]Hop
	hops = make([][]Hop, 0, tr.maxttl)
	timeouts := 0

	for i := 1; i <= tr.maxttl; i++ {
		thisHops := make([]Hop, 0, rounds)
		isFinal := false
		notimeout := true

		for j := 0; j < rounds; j++ {
			next := tr.step(i)
			// If an IP address is received, perform additional DNS resolution if a cache is provided.
			if next.Addr != nil && DNScache != nil {
				addrString := next.Addr.String()
				next.Host = DNScache.LookupHost(addrString)
				next.AS = DNScache.LookupAS(addrString)
			}
			if cb != nil {
				cb(next, i, j+1)
			}
			thisHops = append(thisHops, next)

			// If any round produces a final response, mark it.
			if next.Final {
				isFinal = true
			}
			// If any round did not timeout, then notimeout remains true.
			if next.Timeout {
				notimeout = false
			}
		}

		hops = append(hops, thisHops)
		if isFinal {
			break
		}
		if notimeout {
			timeouts = 0
		} else {
			timeouts++
		}
		if timeouts >= MaxTimeouts {
			break
		}
	}

	return hops, nil
}
