package netutils

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// checkDefragmenter fails the test if the memory accounting, the lru list, or
// the fragment lists no longer match the tracked flows.
func checkDefragmenter(t *testing.T, d *IPDefragmenter) {
	t.Helper()
	if d.lru.Len() != len(d.ipFlows) {
		t.Fatalf("lru holds %d flows, map holds %d", d.lru.Len(), len(d.ipFlows))
	}
	var size int
	for e := d.lru.Front(); e != nil; e = e.Next() {
		fl := e.Value.(*fragments)
		if d.ipFlows[fl.key] != fl {
			t.Fatalf("lru flow %v is not in the map", fl.key)
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

// fuzzDefragIP decodes each packet with the gopacket layers, as a pcap file
// reader does, and with NetDecoder, as the DNS-collector sniffer does.
func fuzzDefragIP(t *testing.T, data []byte, first gopacket.LayerType) {
	fuzzDefragIPWith(t, data, first, func(raw []byte) gopacket.Packet {
		return gopacket.NewPacket(raw, first, gopacket.Default)
	})
	ethType := layers.EthernetTypeIPv4
	if first == layers.LayerTypeIPv6 {
		ethType = layers.EthernetTypeIPv6
	}
	fuzzDefragIPWith(t, data, first, func(raw []byte) gopacket.Packet {
		eth := make([]byte, 14, 14+len(raw))
		binary.BigEndian.PutUint16(eth[12:], uint16(ethType))
		return gopacket.NewPacket(append(eth, raw...), &NetDecoder{}, gopacket.NoCopy)
	})
}

func fuzzDefragIPWith(t *testing.T, data []byte, first gopacket.LayerType, decode func([]byte) gopacket.Packet) {
	d := NewIPDefragmenter()
	// A small limit, so that short inputs reach the eviction path.
	d.memoryLimit = 4 * fragmentOverhead
	ts := time.Unix(1700000000, 0)
	for len(data) >= 3 {
		n := int(binary.BigEndian.Uint16(data))
		// The step can go back and forward, to cover clock steps.
		ts = ts.Add(time.Duration(int8(data[2])) * time.Second)
		data = data[3:]
		if n > len(data) {
			n = len(data)
		}
		pkt := decode(data[:n])
		data = data[n:]
		if pkt.NetworkLayer() == nil || pkt.NetworkLayer().LayerType() != first {
			continue
		}
		// DNS-collector only sends packets with a fragment to the defragmenter.
		if first == layers.LayerTypeIPv4 {
			ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || (ip4.Flags&layers.IPv4MoreFragments == 0 && ip4.FragOffset == 0) {
				continue
			}
		} else if pkt.Layer(layers.LayerTypeIPv6) == nil || pkt.Layer(layers.LayerTypeIPv6Fragment) == nil {
			continue
		}
		pkt.Metadata().Timestamp = ts
		_, _ = d.DefragIP(pkt)
		checkDefragmenter(t, d)
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
