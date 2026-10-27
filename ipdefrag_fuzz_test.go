package netutils

import (
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

// FuzzDefragIP feeds a sequence of raw IPv4 packets to one defragmenter. Each
// packet starts with a 1-byte length and a 1-byte capture time step in
// seconds. DefragIP runs on every captured fragment, so it must never panic.
func FuzzDefragIP(f *testing.F) {
	frag1, frag2 := dnsQueryIPv4Fragments()
	var seed []byte
	for _, p := range []gopacket.Packet{frag1, frag2} {
		ip := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		raw := append(append([]byte(nil), ip.Contents...), ip.Payload...)
		seed = append(seed, byte(len(raw)), 1)
		seed = append(seed, raw...)
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		d := NewIPDefragmenter()
		// A small limit, so that short inputs reach the eviction path.
		d.memoryLimit = 4 * fragmentOverhead
		ts := time.Unix(1700000000, 0)
		for len(data) >= 2 {
			n := int(data[0])
			ts = ts.Add(time.Duration(data[1]) * time.Second)
			data = data[2:]
			if n > len(data) {
				n = len(data)
			}
			pkt := gopacket.NewPacket(data[:n], layers.LayerTypeIPv4, gopacket.Default)
			data = data[n:]
			if pkt.Layer(layers.LayerTypeIPv4) == nil {
				continue
			}
			pkt.Metadata().Timestamp = ts
			_, _ = d.DefragIP(pkt)
			checkDefragmenter(t, d)
		}
	})
}
