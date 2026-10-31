package netutils

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// checkDefragmenter fails the test if the memory accounting, the byAge list, or
// the fragment lists no longer match the tracked flows.
func checkDefragmenter(t *testing.T, d *IPDefragmenter) {
	t.Helper()
	if d.byAge.Len() != len(d.ipFlows) {
		t.Fatalf("byAge holds %d flows, map holds %d", d.byAge.Len(), len(d.ipFlows))
	}
	var size int
	for e := d.byAge.Front(); e != nil; e = e.Next() {
		fl := e.Value.(*fragments)
		if d.ipFlows[fl.key] != fl {
			t.Fatalf("byAge flow %v is not in the map", fl.key)
		}
		size += fl.size
		checkFragments(t, fl)
	}
	if size != d.size {
		t.Fatalf("flows hold %d bytes, defragmenter counts %d", size, d.size)
	}
	if d.size > d.memoryLimit {
		t.Fatalf("defragmenter holds %d bytes, limit is %d", d.size, d.memoryLimit)
	}
}

// checkFragments fails the test if the fragments of a flow are out of order or
// overlap, or if Current and Highest don't match them. build relies on this.
func checkFragments(t *testing.T, fl *fragments) {
	t.Helper()
	var end, sum uint16
	for e := fl.List.Front(); e != nil; e = e.Next() {
		offset, payload, _ := fragmentInfo(e.Value.(gopacket.Packet))
		if offset < end {
			t.Fatalf("flow %v: fragment at %d overlaps or precedes the one that ends at %d", fl.key, offset, end)
		}
		end = offset + uint16(len(payload))
		sum += uint16(len(payload))
	}
	if fl.Highest != end || fl.Current != sum {
		t.Fatalf("flow %v: Highest %d, Current %d, fragments end at %d and hold %d bytes", fl.key, fl.Highest, fl.Current, end, sum)
	}
}

// encodeFuzzPackets builds a fuzz input. For each packet it writes a 2-byte
// length, a signed 1-byte capture time step in seconds, and the IP packet,
// that is the bytes after the 14-byte Ethernet header.
func encodeFuzzPackets(steps []int8, pkts ...[]byte) []byte {
	var out []byte
	for i, p := range pkts {
		raw := p[14:]
		out = binary.BigEndian.AppendUint16(out, uint16(len(raw)))
		out = append(out, byte(steps[i]))
		out = append(out, raw...)
	}
	return out
}

// decodeFuzzPackets decodes a fuzz input with dec. It returns the fragments of
// the first layer type, the packets that DNS-collector sends to the
// defragmenter.
func decodeFuzzPackets(data []byte, first gopacket.LayerType, dec testDecoder) []gopacket.Packet {
	ethType := layers.EthernetTypeIPv4
	if first == layers.LayerTypeIPv6 {
		ethType = layers.EthernetTypeIPv6
	}
	var pkts []gopacket.Packet
	ts := time.Unix(1700000000, 0)
	for len(data) >= 3 {
		n := int(binary.BigEndian.Uint16(data))
		// The step can go back and forward, to cover clock steps.
		ts = ts.Add(time.Duration(int8(data[2])) * time.Second)
		data = data[3:]
		if n > len(data) {
			n = len(data)
		}
		frame := make([]byte, 14, 14+n)
		binary.BigEndian.PutUint16(frame[12:], uint16(ethType))
		pkt := dec.decodeFrame(append(frame, data[:n]...))
		data = data[n:]
		if pkt.NetworkLayer() == nil || pkt.NetworkLayer().LayerType() != first {
			continue
		}
		if first == layers.LayerTypeIPv4 {
			ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || (ip4.Flags&layers.IPv4MoreFragments == 0 && ip4.FragOffset == 0) {
				continue
			}
		} else if pkt.Layer(layers.LayerTypeIPv6) == nil || pkt.Layer(layers.LayerTypeIPv6Fragment) == nil {
			continue
		}
		pkt.Metadata().Timestamp = ts
		pkts = append(pkts, pkt)
	}
	return pkts
}

// fuzzDefragIP runs the input once per decoder in testDecoders.
func fuzzDefragIP(t *testing.T, data []byte, first gopacket.LayerType) {
	for _, dec := range testDecoders {
		d := NewIPDefragmenter()
		// A small limit, so that short inputs reach the eviction path.
		d.memoryLimit = 4 * fragmentOverhead
		for _, pkt := range decodeFuzzPackets(data, first, dec) {
			_, _ = d.DefragIP(pkt)
			checkDefragmenter(t, d)
		}
	}
}

// FuzzDefragIPv4 feeds a sequence of raw IPv4 packets to one defragmenter.
// DefragIP runs on every captured fragment, so it must never panic.
func FuzzDefragIPv4(f *testing.F) {
	frag1, frag2 := dnsQueryIPv4Fragments()
	f.Add(encodeFuzzPackets([]int8{1, 1}, frag1.Data(), frag2.Data()))

	// The inputs that made build panic before.
	src := net.IP{10, 0, 0, 1}
	nop := layers.IPv4Option{OptionType: 1, OptionLength: 1}
	f.Add(encodeFuzzPackets([]int8{0, 0, 0},
		newIPv4Fragment(f, src, 7, 0, true, make([]byte, 236), time.Time{}).Data(),
		newIPv4Fragment(f, src, 7, 55, true, make([]byte, 64), time.Time{}).Data(),
		newIPv4Fragment(f, src, 7, 4, false, make([]byte, 200), time.Time{}, nop, nop, nop, nop).Data()))
	truncated := newIPv4Fragment(f, src, 8, 1, false, make([]byte, 24), time.Time{}).Data()
	f.Add(encodeFuzzPackets([]int8{0, 0, 0},
		newIPv4Fragment(f, src, 8, 0, true, make([]byte, 16), time.Time{}).Data(),
		newIPv4Fragment(f, src, 8, 5, true, make([]byte, 8), time.Time{}).Data(),
		truncated[:len(truncated)-21]))

	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzDefragIP(t, data, layers.LayerTypeIPv4)
	})
}

// FuzzDefragIPv6 is FuzzDefragIPv4 for IPv6 packets.
func FuzzDefragIPv6(f *testing.F) {
	frag1, frag2 := dnsQueryIPv6Fragments()
	f.Add(encodeFuzzPackets([]int8{1, 1}, frag1.Data(), frag2.Data()))
	f.Add(encodeFuzzPackets([]int8{0, -100}, frag2.Data(), frag1.Data()))

	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzDefragIP(t, data, layers.LayerTypeIPv6)
	})
}

// FuzzIPDefragger sends the fuzz packets to the IPDefragger goroutine, then a
// DNS query in two fragments. No input may stop the goroutine or the
// reassembly of the query, because nothing restarts the goroutine.
func FuzzIPDefragger(f *testing.F) {
	frag1, frag2 := dnsQueryIPv4Fragments()
	f.Add(encodeFuzzPackets([]int8{1, 1}, frag1.Data(), frag2.Data()), false)
	frag1, frag2 = dnsQueryIPv6Fragments()
	f.Add(encodeFuzzPackets([]int8{1, 1}, frag1.Data(), frag2.Data()), true)
	tooBig := newIPv4Fragment(f, net.IP{10, 0, 0, 1}, 1, IPv4MaximumFragmentOffset+1, false, make([]byte, 8), time.Time{})
	f.Add(encodeFuzzPackets([]int8{0}, tooBig.Data()), false)

	f.Fuzz(func(t *testing.T, data []byte, ipv6 bool) {
		first, query := layers.LayerTypeIPv4, dnsQueryIPv4Fragments
		if ipv6 {
			first, query = layers.LayerTypeIPv6, dnsQueryIPv6Fragments
		}
		for _, dec := range testDecoders {
			frag1, frag2 := query()
			pkts := decodeFuzzPackets(data, first, dec)
			queryFlow := frag1.NetworkLayer().NetworkFlow()
			// A fuzz fragment in the flow of the query can drop it on purpose.
			sharesFlow := false
			for _, pkt := range pkts {
				sharesFlow = sharesFlow || pkt.NetworkLayer().NetworkFlow() == queryFlow
			}

			ipInput := make(chan gopacket.Packet)
			udpOutput := make(chan gopacket.Packet, len(pkts)+1)
			tcpOutput := make(chan gopacket.Packet, len(pkts)+1)
			done := make(chan struct{})
			go func() {
				IPDefragger(ipInput, udpOutput, tcpOutput, 53)
				close(done)
			}()
			// stop also runs if send fails, so that no goroutine leaks.
			stop := sync.OnceFunc(func() {
				close(ipInput)
				<-done
			})
			defer stop()
			send := func(p gopacket.Packet) {
				select {
				case ipInput <- p:
				case <-time.After(time.Second):
					t.Fatal("the defragger no longer reads its input")
				}
			}
			for _, pkt := range pkts {
				send(pkt)
			}
			send(dec.decode(frag1))
			send(dec.decode(frag2))
			stop()

			found := false
			for len(udpOutput) > 0 {
				pkt := <-udpOutput
				found = found || pkt.NetworkLayer().NetworkFlow() == queryFlow
			}
			if !found && !sharesFlow {
				t.Fatalf("%s: DNS query not reassembled after %d fuzz fragments", dec.name, len(pkts))
			}
		}
	})
}
