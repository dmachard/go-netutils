package netutils

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// checkDefragmenter fails the test if the memory accounting or the lru list
// no longer match the tracked flows.
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
	}
	if size != d.size {
		t.Fatalf("flows hold %d bytes, defragmenter counts %d", size, d.size)
	}
	if d.size > d.memoryLimit {
		t.Fatalf("defragmenter holds %d bytes, limit is %d", d.size, d.memoryLimit)
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

func fuzzDefragIP(t *testing.T, data []byte, first gopacket.LayerType) {
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
		pkt := gopacket.NewPacket(data[:n], first, gopacket.Default)
		data = data[n:]
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
