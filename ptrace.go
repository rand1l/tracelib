package tracelib

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func RunPTrace(
	host string,
	source string,
	source6 string,
	maxrtt time.Duration,
	maxttl int,
	DNScache *LookupCache,
	rounds int,
	proto Protocol,
	id int,
	destPort int,
	delay time.Duration,
) ([][]Hop, error) {

	hops := make([][]Hop, maxttl)
	sendOn := make([][]time.Time, maxttl)
	for i := 0; i < maxttl; i++ {
		hops[i] = make([]Hop, rounds)
		for r := 0; r < rounds; r++ {
			hops[i][r].Timeout = true
		}
		sendOn[i] = make([]time.Time, rounds)
	}

	var (
		conn     net.PacketConn
		ipv4conn *ipv4.PacketConn
		ipv6conn *ipv6.PacketConn
		dest     net.Addr
	)
	isIPv6 := false

	addrList, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrList {
		if addr.To4() != nil {
			switch proto {
			case ProtoICMP:
				dest, err = net.ResolveIPAddr("ip4:icmp", addr.String())
			case ProtoUDP, ProtoTCP:
				dest, err = net.ResolveIPAddr("ip4", addr.String())
			}
			if err == nil {
				break
			}
		}
	}
	if dest == nil {
		for _, addr := range addrList {
			if addr.To16() != nil && addr.To4() == nil {
				isIPv6 = true
				switch proto {
				case ProtoICMP:
					dest, err = net.ResolveIPAddr("ip6:58", addr.String())
				case ProtoUDP, ProtoTCP:
					dest, err = net.ResolveIPAddr("ip6", addr.String())
				}
				if err == nil {
					break
				}
			}
		}
	}
	if dest == nil {
		return nil, errors.New("unable to resolve destination host")
	}

	if !isIPv6 {
		conn, err = net.ListenPacket("ip4:icmp", source)
	} else {
		conn, err = net.ListenPacket("ip6:58", source6)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if isIPv6 {
		ipv6conn = ipv6.NewPacketConn(conn)
		defer ipv6conn.Close()
		if err := ipv6conn.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagSrc|ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
			return nil, err
		}
		var f ipv6.ICMPFilter
		f.SetAll(true)
		f.Accept(ipv6.ICMPTypeTimeExceeded)
		f.Accept(ipv6.ICMPTypeEchoReply)
		f.Accept(ipv6.ICMPTypeDestinationUnreachable)
		if err := ipv6conn.SetICMPFilter(&f); err != nil {
			return nil, err
		}
	} else {
		ipv4conn = ipv4.NewPacketConn(conn)
		defer ipv4conn.Close()
	}

	// For UDP/TCP, determine source IP and source port.
	var srcIP net.IP
	var srcPort int
	if proto != ProtoICMP {
		srcIP, err = findSrcAddrForDst(dest.(*net.IPAddr).IP)
		if err != nil {
			return nil, err
		}
		srcPort = 40000 + rand.Intn(2000)
	}

	// Launch a goroutine to send all packets at once.
	go func() {
		for i := 1; i <= maxttl; i++ {
			hop := i - 1
			var wcm ipv6.ControlMessage
			if !isIPv6 {
				if proto == ProtoICMP {
					_ = ipv4conn.SetTTL(i)
				}
			} else {
				wcm.HopLimit = i
			}
			for r := 0; r < rounds; r++ {
				var netmsg []byte
				var err error
				seq := hop + (maxttl * r)
				if proto == ProtoICMP {
					var msg icmp.Message
					if isIPv6 {
						msg = icmp.Message{
							Type: ipv6.ICMPTypeEchoRequest, Code: 0,
							Body: &icmp.Echo{ID: id, Seq: seq},
						}
					} else {
						msg = icmp.Message{
							Type: ipv4.ICMPTypeEcho, Code: 0,
							Body: &icmp.Echo{ID: id, Seq: seq},
						}
					}
					netmsg, err = msg.Marshal(nil)
				} else if proto == ProtoUDP {
					payload := []byte("GoTraceroute")
					netmsg, err = buildTransportPacket(isIPv6, i, srcIP, dest.(*net.IPAddr).IP, uint16(srcPort), uint16(destPort), payload, ProtoUDP)
				} else if proto == ProtoTCP {
					payload := []byte{}
					netmsg, err = buildTransportPacket(isIPv6, i, srcIP, dest.(*net.IPAddr).IP, uint16(srcPort), uint16(destPort), payload, ProtoTCP)
				}
				if err != nil {
					hops[hop][r].Error = err
					continue
				}
				sendOn[hop][r] = time.Now()
				if !isIPv6 {
					_, hops[hop][r].Error = conn.WriteTo(netmsg, dest)
				} else {
					_, hops[hop][r].Error = ipv6conn.WriteTo(netmsg, &wcm, dest)
				}
				if delay != 0 {
					time.Sleep(delay)
				}
			}
		}
	}()

	buf := make([]byte, 1500)
	maxSeq := rounds * maxttl - 1

	for now := time.Now().Add(maxrtt + (delay * time.Duration(maxSeq))); time.Now().Before(now); {
		conn.SetReadDeadline(now)
		readLen, addr, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		var result *icmp.Message
		if !isIPv6 {
			result, err = icmp.ParseMessage(ProtocolICMP, buf[:readLen])
		} else {
			result, err = icmp.ParseMessage(ProtocolICMP6, buf[:readLen])
		}
		if err != nil {
			continue
		}
		switch result.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			if rply, ok := result.Body.(*icmp.Echo); ok {
				if rply.ID != id || rply.Seq > maxSeq {
					continue
				}
				idx := rply.Seq % maxttl
				round := rply.Seq / maxttl
				hops[idx][round].Addr = addr
				hops[idx][round].RTT = time.Since(sendOn[idx][round])
				hops[idx][round].Final = true
				hops[idx][round].Timeout = false
			}
		case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
			if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
				if !isIPv6 {
					if len(rply.Data) > 26 {
						if uint16(id) != binary.BigEndian.Uint16(rply.Data[24:26]) {
							continue
						}
						seq := int(binary.BigEndian.Uint16(rply.Data[26:28]))
						if seq > maxSeq {
							continue
						}
						idx := seq % maxttl
						round := seq / maxttl
						hops[idx][round].Addr = addr
						hops[idx][round].RTT = time.Since(sendOn[idx][round])
						hops[idx][round].Timeout = false
					}
				} else {
					if len(rply.Data) > 46 {
						if uint16(id) != binary.BigEndian.Uint16(rply.Data[44:46]) {
							continue
						}
						seq := int(binary.BigEndian.Uint16(rply.Data[26:28]))
						if seq > maxSeq {
							continue
						}
						idx := seq % maxttl
						round := seq / maxttl
						hops[idx][round].Addr = addr
						hops[idx][round].RTT = time.Since(sendOn[idx][round])
						hops[idx][round].Timeout = false
					}
				}
			}	
			case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
				if rply, ok := result.Body.(*icmp.Echo); ok {
					if rply.ID != id || rply.Seq > maxSeq {
						continue
					}
					idx := rply.Seq % maxttl
					round := rply.Seq / maxttl
					hops[idx][round].Addr = addr
					hops[idx][round].RTT = time.Since(sendOn[idx][round])
					hops[idx][round].Down = true
					hops[idx][round].Timeout = false
				}
		}
	}

	// Determine the final hop index.
	finalHop := maxttl
	for hop := 0; hop < maxttl; hop++ {
		for r := 0; r < rounds; r++ {
			if hops[hop][r].Addr == nil {
				continue
			}
			if DNScache != nil {
				addrStr := hops[hop][r].Addr.String()
				hops[hop][r].Host = DNScache.LookupHost(addrStr)
				hops[hop][r].AS = DNScache.LookupAS(addrStr)
			}
			if finalHop == maxttl && hops[hop][r].Final {
				finalHop = hop + 1
			}
		}
	}

	return hops[:finalHop], nil
}

// RunMPTrace performs traceroute to multiple hosts by sending all packets at once using one or two raw sockets.
// It returns a map from hostname to a pointer to a 2D slice of Hop results.
func RunMPTrace(
	hosts []string,
	source string,
	source6 string,
	maxrtt time.Duration,
	maxttl int,
	DNScache *LookupCache,
	rounds int,
	startID int,
	delay time.Duration,
	proto Protocol,
	destPort int,
) (map[string]*[][]Hop, error) {

	hopsMap := make(map[string]*[][]Hop, len(hosts))
	sendOnMap := make(map[string]*[][]time.Time, len(hosts))
	isIPv6Map := make(map[string]bool, len(hosts))
	destMap := make(map[string]net.Addr, len(hosts))
	addrsb := make(map[string][]byte, len(hosts))

	for _, host := range hosts {
		_hops := make([][]Hop, maxttl)
		_sendOn := make([][]time.Time, maxttl)
		for i := 0; i < maxttl; i++ {
			_hops[i] = make([]Hop, rounds)
			for r := 0; r < rounds; r++ {
				_hops[i][r].Timeout = true
			}
			_sendOn[i] = make([]time.Time, rounds)
		}
		hopsMap[host] = &_hops
		sendOnMap[host] = &_sendOn
	}

	hasIPv4 := false
	hasIPv6 := false

	for _, host := range hosts {
		addrList, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}
		var resolved net.Addr
		for _, addr := range addrList {
			if addr.To4() != nil {
				switch proto {
				case ProtoICMP:
					resolved, err = net.ResolveIPAddr("ip4:icmp", addr.String())
				case ProtoUDP, ProtoTCP:
					resolved, err = net.ResolveIPAddr("ip4", addr.String())
				}
				if err == nil {
					hasIPv4 = true
					destMap[host] = resolved
					addrsb[host] = addr.To16()
					break
				}
			}
		}
		if destMap[host] == nil {
			for _, addr := range addrList {
				if addr.To16() != nil && addr.To4() == nil {
					isIPv6Map[host] = true
					switch proto {
					case ProtoICMP:
						resolved, err = net.ResolveIPAddr("ip6:58", addr.String())
					case ProtoUDP, ProtoTCP:
						resolved, err = net.ResolveIPAddr("ip6", addr.String())
					}
					if err == nil {
						hasIPv6 = true
						destMap[host] = resolved
						addrsb[host] = addr.To16()
						break
					}
				}
			}
		}
		if destMap[host] == nil {
			return nil, errors.New("unable to resolve destination host for " + host)
		}
	}

	var conn4, conn6 net.PacketConn
	var ipv4conn *ipv4.PacketConn
	var ipv6conn *ipv6.PacketConn
	var err error
	if hasIPv4 {
		conn4, err = net.ListenPacket("ip4:icmp", source)
		if err != nil {
			return nil, err
		}
		defer conn4.Close()
		ipv4conn = ipv4.NewPacketConn(conn4)
		defer ipv4conn.Close()
	}
	if hasIPv6 {
		conn6, err = net.ListenPacket("ip6:58", source6)
		if err != nil {
			return nil, err
		}
		defer conn6.Close()
		ipv6conn = ipv6.NewPacketConn(conn6)
		defer ipv6conn.Close()
		if err := ipv6conn.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagSrc|ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
			return nil, err
		}
		var f ipv6.ICMPFilter
		f.SetAll(true)
		f.Accept(ipv6.ICMPTypeTimeExceeded)
		f.Accept(ipv6.ICMPTypeEchoReply)
		f.Accept(ipv6.ICMPTypeDestinationUnreachable)
		if err := ipv6conn.SetICMPFilter(&f); err != nil {
			return nil, err
		}
	}

	var srcIP net.IP
	var sourcePort int
	if proto != ProtoICMP {
		for _, d := range destMap {
			srcIP, err = findSrcAddrForDst(d.(*net.IPAddr).IP)
			break
		}
		if err != nil {
			return nil, err
		}
		sourcePort = 40000 + rand.Intn(2000)
	}

	go func() {
		for i := 1; i <= maxttl; i++ {
			hopIdx := i - 1
			var wcm ipv6.ControlMessage
			if hasIPv4 {
				_ = ipv4conn.SetTTL(i)
			}
			if hasIPv6 {
				wcm.HopLimit = i
			}
			for r := 0; r < rounds; r++ {
				for hostID, host := range hosts {
					var netmsg []byte
					var err error
					seq := hopIdx + (maxttl * r)
					if proto == ProtoICMP {
						var msg icmp.Message
						if isIPv6Map[host] {
							msg = icmp.Message{
								Type: ipv6.ICMPTypeEchoRequest, Code: 0,
								Body: &icmp.Echo{ID: startID + hostID, Seq: seq, Data: addrsb[host]},
							}
						} else {
							msg = icmp.Message{
								Type: ipv4.ICMPTypeEcho, Code: 0,
								Body: &icmp.Echo{ID: startID + hostID, Seq: seq, Data: addrsb[host]},
							}
						}
						netmsg, err = msg.Marshal(nil)
					} else if proto == ProtoUDP {
						payload := []byte("GoTraceroute")
						if isIPv6Map[host] {
							netmsg, err = buildTransportPacket(true, i, srcIP, destMap[host].(*net.IPAddr).IP, uint16(sourcePort), uint16(destPort), payload, ProtoUDP)
						} else {
							netmsg, err = buildTransportPacket(false, i, srcIP, destMap[host].(*net.IPAddr).IP, uint16(sourcePort), uint16(destPort), payload, ProtoUDP)
						}
					} else if proto == ProtoTCP {
						payload := []byte{}
						if isIPv6Map[host] {
							netmsg, err = buildTransportPacket(true, i, srcIP, destMap[host].(*net.IPAddr).IP, uint16(sourcePort), uint16(destPort), payload, ProtoTCP)
						} else {
							netmsg, err = buildTransportPacket(false, i, srcIP, destMap[host].(*net.IPAddr).IP, uint16(sourcePort), uint16(destPort), payload, ProtoTCP)
						}
					}
					if err != nil {
						(*hopsMap[host])[hopIdx][r].Error = err
						continue
					}
					(*sendOnMap[host])[hopIdx][r] = time.Now()
					if isIPv6Map[host] {
						_, (*hopsMap[host])[hopIdx][r].Error = ipv6conn.WriteTo(netmsg, &wcm, destMap[host])
					} else {
						_, (*hopsMap[host])[hopIdx][r].Error = conn4.WriteTo(netmsg, destMap[host])
					}
					if delay != 0 {
						time.Sleep(delay)
					}
				}
			}
		}
	}()

	maxSeq := rounds * maxttl - 1
	var wg sync.WaitGroup

	maxID := startID + len(hosts) - 1

	if hasIPv4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1500)
			waitUntil := time.Now().Add(maxrtt + (delay * time.Duration(maxSeq)))
			for now := time.Now(); now.Before(waitUntil); now = time.Now() {
				conn4.SetReadDeadline(waitUntil)
				n, addr, err := conn4.ReadFrom(buf)
				if err != nil {
					break
				}
				result, err := icmp.ParseMessage(ProtocolICMP, buf[:n])
				if err != nil {
					continue
				}
				switch result.Type {
				case ipv4.ICMPTypeEchoReply:
					if rply, ok := result.Body.(*icmp.Echo); ok {
						if rply.ID < startID || rply.ID > maxID || rply.Seq > maxSeq {
							continue
						}
						host := hosts[rply.ID-startID]
						hopS := (*hopsMap[host])
						idx := rply.Seq % maxttl
						round := rply.Seq / maxttl
						hopS[idx][round].Addr = addr
						hopS[idx][round].RTT = time.Since((*sendOnMap[host])[idx][round])
						hopS[idx][round].Final = true
						hopS[idx][round].Timeout = false
					}
				case ipv4.ICMPTypeTimeExceeded:
					if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
						if len(rply.Data) > 26 {
							idVal := int(binary.BigEndian.Uint16(rply.Data[24:26]))
							if idVal < startID || idVal > maxID {
								continue
							}
							seq := int(binary.BigEndian.Uint16(rply.Data[26:28]))
							if seq > maxSeq {
								continue
							}
							host := hosts[idVal-startID]
							hopS := (*hopsMap[host])
							idx := seq % maxttl
							round := seq / maxttl
							hopS[idx][round].Addr = addr
							hopS[idx][round].RTT = time.Since((*sendOnMap[host])[idx][round])
							hopS[idx][round].Timeout = false
						}
					}
				case ipv4.ICMPTypeDestinationUnreachable:
					if rply, ok := result.Body.(*icmp.Echo); ok {
						if rply.ID < startID || rply.ID > maxID || rply.Seq > maxSeq {
							continue
						}
						host := hosts[rply.ID-startID]
						hopS := (*hopsMap[host])
						idx := rply.Seq % maxttl
						round := rply.Seq / maxttl
						hopS[idx][round].Addr = addr
						hopS[idx][round].RTT = time.Since((*sendOnMap[host])[idx][round])
						hopS[idx][round].Down = true
						hopS[idx][round].Timeout = false
					}
				}
			}
		}()
	}

	if hasIPv6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1500)
			waitUntil := time.Now().Add(maxrtt + (delay * time.Duration(maxSeq)))
			for now := time.Now(); now.Before(waitUntil); now = time.Now() {
				conn6.SetReadDeadline(waitUntil)
				n, addr, err := conn6.ReadFrom(buf)
				if err != nil {
					break
				}
				result, err := icmp.ParseMessage(ProtocolICMP6, buf[:n])
				if err != nil {
					continue
				}
				switch result.Type {
				case ipv6.ICMPTypeEchoReply:
					if rply, ok := result.Body.(*icmp.Echo); ok {
						if rply.ID < startID || rply.ID > maxID || rply.Seq > maxSeq {
							continue
						}
						host := hosts[rply.ID-startID]
						hopS := (*hopsMap[host])
						idx := rply.Seq % maxttl
						round := rply.Seq / maxttl
						hopS[idx][round].Addr = addr
						hopS[idx][round].RTT = time.Since((*sendOnMap[host])[idx][round])
						hopS[idx][round].Final = true
						hopS[idx][round].Timeout = false
					}
				case ipv6.ICMPTypeTimeExceeded:
					if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
						if len(rply.Data) > 46 {
							idVal := int(binary.BigEndian.Uint16(rply.Data[44:46]))
							seq := int(binary.BigEndian.Uint16(rply.Data[26:28]))
							if idVal < startID || idVal > maxID || seq > maxSeq {
								continue
							}
							host := hosts[idVal-startID]
							hopS := (*hopsMap[host])
							idx := seq % maxttl
							round := seq / maxttl
							hopS[idx][round].Addr = addr
							hopS[idx][round].RTT = time.Since((*sendOnMap[host])[idx][round])
							hopS[idx][round].Timeout = false
						}
					}
				case ipv6.ICMPTypeDestinationUnreachable:
					if rply, ok := result.Body.(*icmp.Echo); ok {
						if rply.ID < startID || rply.ID > maxID || rply.Seq > maxSeq {
							continue
						}
						host := hosts[rply.ID-startID]
						hopS := (*hopsMap[host])
						idx := rply.Seq % maxttl
						round := rply.Seq / maxttl
						hopS[idx][round].Addr = addr
						hopS[idx][round].RTT = time.Since((*sendOnMap[host])[idx][round])
						hopS[idx][round].Down = true
						hopS[idx][round].Timeout = false
					}
				}
			}
		}()
	}

	wg.Wait()

	for _, host := range hosts {
		hopS := (*hopsMap[host])
		finalHop := maxttl
		for i := 0; i < maxttl; i++ {
			for r := 0; r < rounds; r++ {
				if hopS[i][r].Addr == nil {
					continue
				}
				if DNScache != nil {
					addrStr := hopS[i][r].Addr.String()
					hopS[i][r].Host = DNScache.LookupHost(addrStr)
					hopS[i][r].AS = DNScache.LookupAS(addrStr)
				}
				if finalHop == maxttl && hopS[i][r].Final {
					finalHop = i + 1
				}
			}
		}
		hopS = hopS[:finalHop]
		hopsMap[host] = &hopS
	}

	return hopsMap, nil
}

