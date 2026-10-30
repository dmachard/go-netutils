package netutils

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// dnsQueryIPv4Fragments returns the two fragments of a DNS query to port 53,
// see the packet in testsdata/pcap/dnsdump_ip4_fragmented_query.pcap
func dnsQueryIPv4Fragments() (gopacket.Packet, gopacket.Packet) {
	frag1Bytes := []byte{0x58, 0x1d, 0xd8, 0x12, 0x84, 0x10, 0xb0, 0x35, 0x9f, 0xd4, 0x03, 0x91, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x4c, 0x00, 0x01, 0x20, 0x00, 0x40, 0x11, 0xcb, 0x8f, 0x7f, 0x00, 0x00, 0x01,
		0x08, 0x08, 0x08, 0x08, 0x30, 0x39, 0x00, 0x35, 0x00, 0x5d, 0xf9, 0x10, 0xaa, 0xaa, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41}
	frag1 := gopacket.NewPacket(frag1Bytes, layers.LayerTypeEthernet, gopacket.Default)
	frag2Bytes := []byte{0x58, 0x1d, 0xd8, 0x12, 0x84, 0x10, 0xb0, 0x35, 0x9f, 0xd4, 0x03, 0x91, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x39, 0x00, 0x01, 0x00, 0x07, 0x40, 0x11, 0xeb, 0x9b, 0x7f, 0x00, 0x00, 0x01,
		0x08, 0x08, 0x08, 0x08, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x03, 0x63, 0x6f, 0x6d,
		0x00, 0x00, 0x01, 0x00, 0x01}
	frag2 := gopacket.NewPacket(frag2Bytes, layers.LayerTypeEthernet, gopacket.Default)
	return frag1, frag2
}

// newIPv4Fragment builds one IPv4 UDP fragment. offset is in 8-byte units, as in the IP header.
func newIPv4Fragment(t testing.TB, src net.IP, id uint16, offset uint16, more bool, payload []byte, ts time.Time, options ...layers.IPv4Option) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TTL:        64,
		Id:         id,
		FragOffset: offset,
		Protocol:   layers.IPProtocolUDP,
		SrcIP:      src,
		DstIP:      net.IP{10, 0, 0, 2},
		Options:    options,
	}
	if more {
		ip4.Flags = layers.IPv4MoreFragments
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize fragment: %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = ts
	return pkt
}

// trackedBytes returns the captured bytes that the defragmenter holds for incomplete flows.
func trackedBytes(d *IPDefragmenter) int {
	var n int
	for _, fl := range d.ipFlows {
		for e := fl.List.Front(); e != nil; e = e.Next() {
			n += len(e.Value.(gopacket.Packet).Data())
		}
	}
	return n
}

// testDecoder is one of the decoders that callers decode packets with before
// they call DefragIP. Each defrag test runs once per decoder, because the
// decoders build different layers for the same fragment.
type testDecoder struct {
	name        string
	decodeFrame func(frame []byte) gopacket.Packet // frame starts with an Ethernet header
}

var testDecoders = []testDecoder{
	// gopacket layers, as the pcap file reader decodes.
	{"gopacket", func(frame []byte) gopacket.Packet {
		return gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	}},
	// NetDecoder and RawIPDecoder, as the DNS-collector sniffer decodes. They
	// also decode the UDP header inside a fragment.
	{"NetDecoder", func(frame []byte) gopacket.Packet {
		return gopacket.NewPacket(frame, &NetDecoder{}, gopacket.NoCopy)
	}},
	{"RawIPDecoder", func(frame []byte) gopacket.Packet {
		return gopacket.NewPacket(frame[14:], &RawIPDecoder{}, gopacket.NoCopy)
	}},
}

// decode decodes the Ethernet frame of p again, and keeps its capture time.
func (d testDecoder) decode(p gopacket.Packet) gopacket.Packet {
	out := d.decodeFrame(p.Data())
	out.Metadata().Timestamp = p.Metadata().Timestamp
	return out
}

func (d testDecoder) newIPv4Fragment(t testing.TB, src net.IP, id uint16, offset uint16, more bool, payload []byte, ts time.Time, options ...layers.IPv4Option) gopacket.Packet {
	t.Helper()
	return d.decode(newIPv4Fragment(t, src, id, offset, more, payload, ts, options...))
}

func (d testDecoder) dnsQueryIPv4Fragments() (gopacket.Packet, gopacket.Packet) {
	frag1, frag2 := dnsQueryIPv4Fragments()
	return d.decode(frag1), d.decode(frag2)
}

func (d testDecoder) dnsQueryIPv6Fragments() (gopacket.Packet, gopacket.Packet) {
	frag1, frag2 := dnsQueryIPv6Fragments()
	return d.decode(frag1), d.decode(frag2)
}

// forEachDecoder runs fn as a subtest once per decoder.
func forEachDecoder(t *testing.T, fn func(t *testing.T, dec testDecoder)) {
	t.Helper()
	for _, dec := range testDecoders {
		t.Run(dec.name, func(t *testing.T) { fn(t, dec) })
	}
}

func TestIpDefrag_IPv4Fragment(t *testing.T) {
	forEachDecoder(t, func(t *testing.T, dec testDecoder) {
		frag1, frag2 := dec.dnsQueryIPv4Fragments()

		defragger := NewIPDefragmenter()
		_, err := defragger.DefragIP(frag1)
		if err != nil {
			t.Errorf("Unexpected error on the 1er defrag: %v", err)
		}

		pkt, err := defragger.DefragIP(frag2)
		if err != nil {
			t.Errorf("Unexpected error on the 2nd defrag: %v", err)
		}

		if pkt.Metadata().Length != 113 {
			t.Errorf("Invalid reassembled packet size: %v", err)
		}
	})
}

func TestIpDefrag_IPv4FragmentWithRetransmission(t *testing.T) {
	forEachDecoder(t, func(t *testing.T, dec testDecoder) {

		// fragmented packet, see the packet in testsdata/pcap/dnsdump_ip4_fragmented_query.pcap
		packetBytes := []byte{
			0x58, 0x1d, 0xd8, 0x12, 0x84, 0x10, 0xb0, 0x35, 0x9f, 0xd4, 0x03, 0x91, 0x08, 0x00, 0x45, 0x00,
			0x00, 0x39, 0x00, 0x01, 0x00, 0x07, 0x40, 0x11, 0xeb, 0x9b, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x08,
			0x08, 0x08, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x03, 0x63,
			0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
		}
		packet := dec.decodeFrame(packetBytes)

		// This packet is just a fragment
		defragger := NewIPDefragmenter()
		_, err := defragger.DefragIP(packet)
		if err != nil {
			t.Errorf("Unexpected error on the 1er defrag: %v", err)
		}

		// Try to defrag the same packet
		_, err = defragger.DefragIP(packet)
		if err != nil {
			t.Errorf("Unexpected error for the 2nd defrag: %v", err)
		}
	})
}

// dnsQueryIPv6Fragments returns the two fragments of a DNS query to port 53 over IPv6.
func dnsQueryIPv6Fragments() (gopacket.Packet, gopacket.Packet) {
	frag1Bytes := []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0xb0, 0x35, 0x9f, 0xd4, 0x03, 0x91, 0x86, 0xdd, 0x60, 0x00,
		0x00, 0x00, 0x00, 0x38, 0x2c, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x20,
		0xbf, 0xa1, 0x87, 0x8c, 0x3a, 0x68, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x01, 0xee, 0x8f, 0x5f, 0xf8, 0x30, 0x39,
		0x00, 0x35, 0x00, 0x61, 0x98, 0xc4, 0xaa, 0xaa, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x3f, 0x63, 0x6f, 0x6d, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41}
	frag1 := gopacket.NewPacket(frag1Bytes, layers.LayerTypeEthernet, gopacket.Default)
	frag2Bytes := []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0xb0, 0x35, 0x9f, 0xd4, 0x03, 0x91, 0x86, 0xdd, 0x60, 0x00,
		0x00, 0x00, 0x00, 0x39, 0x2c, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x20,
		0xbf, 0xa1, 0x87, 0x8c, 0x3a, 0x68, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x30, 0xee, 0x8f, 0x5f, 0xf8, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x01, 0x00, 0x01}
	frag2 := gopacket.NewPacket(frag2Bytes, layers.LayerTypeEthernet, gopacket.Default)

	return frag1, frag2
}

func TestIpDefrag_IPv6Fragment(t *testing.T) {
	forEachDecoder(t, func(t *testing.T, dec testDecoder) {
		frag1, frag2 := dec.dnsQueryIPv6Fragments()

		defragger := NewIPDefragmenter()
		_, err := defragger.DefragIP(frag1)
		if err != nil {
			t.Errorf("Unexpected error on the 1er defrag: %v", err)
		}

		pkt, err := defragger.DefragIP(frag2)
		if err != nil {
			t.Errorf("Unexpected error on the 2nd defrag: %v", err)
		}

		if pkt.Metadata().Length != 137 {
			t.Errorf("Invalid reassembled packet size: %v", err)
		}
	})
}

// A fragment whose flow never completes must not stay in memory forever. The
// sniffer BPF filter accepts every non-first fragment but drops the first
// fragment of a non-DNS datagram, so these flows are common in live capture.
func TestIpDefrag_IPv4IncompleteFlowsExpire(t *testing.T) {
	forEachDecoder(t, func(t *testing.T, dec testDecoder) {
		defragger := NewIPDefragmenter()
		start := time.Unix(1700000000, 0)
		src := net.IP{10, 0, 0, 1}

		for id := 0; id < 1000; id++ {
			frag := dec.newIPv4Fragment(t, src, uint16(id), 185, false, make([]byte, 100), start)
			if _, err := defragger.DefragIP(frag); err != nil {
				t.Fatalf("unexpected error for fragment %d: %v", id, err)
			}
		}

		later := dec.newIPv4Fragment(t, src, 5000, 185, false, make([]byte, 100), start.Add(10*time.Minute))
		if _, err := defragger.DefragIP(later); err != nil {
			t.Fatalf("unexpected error for the later fragment: %v", err)
		}

		if n := len(defragger.ipFlows); n > 1 {
			t.Errorf("%d incomplete flows still tracked 10 minutes later, want at most 1", n)
		}
	})
}

// A burst of incomplete flows inside the timeout must not grow memory without
// limit, and the burst must not block the reassembly of new DNS flows.
func TestIpDefrag_IPv4IncompleteFlowsAreBounded(t *testing.T) {
	forEachDecoder(t, func(t *testing.T, dec testDecoder) {
		defragger := NewIPDefragmenter()
		ts := time.Unix(1700000000, 0)
		payload := make([]byte, 1400)

		// 20000 flows of about 1.4 KB each is about 28 MB of captured data.
		for i := 0; i < 20000; i++ {
			src := net.IP{10, 1, byte(i >> 8), byte(i)}
			frag := dec.newIPv4Fragment(t, src, uint16(i), 185, true, payload, ts)
			if _, err := defragger.DefragIP(frag); err != nil {
				t.Fatalf("unexpected error for fragment %d: %v", i, err)
			}
		}

		checkDefragmenter(t, defragger)
		const limit = 8 * 1024 * 1024
		if n := trackedBytes(defragger); n > limit {
			t.Errorf("defragmenter holds %d bytes of incomplete flows, want at most %d", n, limit)
		}

		frag1, frag2 := dec.dnsQueryIPv4Fragments()
		frag1.Metadata().Timestamp = ts
		frag2.Metadata().Timestamp = ts
		if _, err := defragger.DefragIP(frag1); err != nil {
			t.Fatalf("unexpected error on the 1st DNS fragment: %v", err)
		}
		pkt, err := defragger.DefragIP(frag2)
		if err != nil {
			t.Fatalf("unexpected error on the 2nd DNS fragment: %v", err)
		}
		if pkt == nil {
			t.Fatal("DNS query not reassembled after a burst of incomplete flows")
		}
	})
}

// Overlapping fragments with IP options or a truncated capture must be
// rejected, not panic. A panic in the defragger goroutine stops the whole
// process.
func TestIpDefrag_IPv4MalformedOverlapDoesNotPanic(t *testing.T) {
	forEachDecoder(t, func(t *testing.T, dec testDecoder) {
		src := net.IP{10, 0, 0, 1}
		nop := layers.IPv4Option{OptionType: 1, OptionLength: 1}
		truncated := func(p gopacket.Packet, n int) gopacket.Packet {
			return dec.decodeFrame(p.Data()[:len(p.Data())-n])
		}

		tests := []struct {
			name  string
			frags []gopacket.Packet
		}{
			{
				name: "IP options on an overlapping fragment",
				frags: []gopacket.Packet{
					dec.newIPv4Fragment(t, src, 7, 0, true, make([]byte, 236), time.Time{}),
					dec.newIPv4Fragment(t, src, 7, 55, true, make([]byte, 64), time.Time{}),
					dec.newIPv4Fragment(t, src, 7, 4, false, make([]byte, 200), time.Time{}, nop, nop, nop, nop),
				},
			},
			{
				name: "truncated overlapping fragment",
				frags: []gopacket.Packet{
					dec.newIPv4Fragment(t, src, 8, 0, true, make([]byte, 16), time.Time{}),
					dec.newIPv4Fragment(t, src, 8, 5, true, make([]byte, 8), time.Time{}),
					truncated(newIPv4Fragment(t, src, 8, 1, false, make([]byte, 24), time.Time{}), 21),
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("DefragIP panicked: %v", r)
					}
				}()
				defragger := NewIPDefragmenter()
				for _, frag := range tc.frags {
					_, _ = defragger.DefragIP(frag)
				}
			})
		}
	})
}

// The fragment lengths must come from the header length in IHL, not from a
// fixed 20 bytes, or a datagram with IP options reassembles wrong.
func TestIpDefrag_IPv4FragmentsWithOptions(t *testing.T) {
	forEachDecoder(t, func(t *testing.T, dec testDecoder) {
		src := net.IP{10, 0, 0, 1}
		nop := layers.IPv4Option{OptionType: 1, OptionLength: 1}
		first := bytes.Repeat([]byte{0xaa}, 16)
		last := bytes.Repeat([]byte{0xbb}, 8)

		defragger := NewIPDefragmenter()
		if _, err := defragger.DefragIP(dec.newIPv4Fragment(t, src, 9, 0, true, first, time.Time{}, nop, nop, nop, nop)); err != nil {
			t.Fatalf("unexpected error on the 1st fragment: %v", err)
		}
		pkt, err := defragger.DefragIP(dec.newIPv4Fragment(t, src, 9, 2, false, last, time.Time{}, nop, nop, nop, nop))
		if err != nil {
			t.Fatalf("unexpected error on the 2nd fragment: %v", err)
		}
		if pkt == nil {
			t.Fatal("datagram with IP options not reassembled")
		}
		ip4 := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if want := append(append([]byte(nil), first...), last...); !bytes.Equal(ip4.Payload, want) {
			t.Errorf("reassembled payload = %x, want %x", ip4.Payload, want)
		}
	})
}

// One fragment with a far-future capture time must not stop the expiry of the
// flows that come after it.
func TestIpDefrag_IPv4FutureTimestampDoesNotStopExpiry(t *testing.T) {
	forEachDecoder(t, func(t *testing.T, dec testDecoder) {
		defragger := NewIPDefragmenter()
		start := time.Unix(1700000000, 0)
		src := net.IP{10, 0, 0, 1}

		future := dec.newIPv4Fragment(t, src, 1, 185, true, make([]byte, 100), start.Add(100*365*24*time.Hour))
		if _, err := defragger.DefragIP(future); err != nil {
			t.Fatalf("unexpected error for the future fragment: %v", err)
		}

		// One fragment per second for 1000 seconds, each in its own flow.
		for i := 0; i < 1000; i++ {
			frag := dec.newIPv4Fragment(t, src, uint16(i+2), 185, true, make([]byte, 100), start.Add(time.Duration(i)*time.Second))
			if _, err := defragger.DefragIP(frag); err != nil {
				t.Fatalf("unexpected error for fragment %d: %v", i, err)
			}
		}

		checkDefragmenter(t, defragger)
		if n := len(defragger.ipFlows); n > int(IPFragmentTimeout/time.Second)+2 {
			t.Errorf("%d flows tracked, want at most the last %v of flows", n, IPFragmentTimeout)
		}
	})
}

// A fragment that overlaps another one, but is not an exact duplicate, must
// drop the flow. A later datagram with the same ID must still reassemble.
func TestIpDefrag_IPv4OverlapDropsFlow(t *testing.T) {
	forEachDecoder(t, func(t *testing.T, dec testDecoder) {
		src := net.IP{10, 0, 0, 1}
		defragger := NewIPDefragmenter()

		if _, err := defragger.DefragIP(dec.newIPv4Fragment(t, src, 3, 0, true, make([]byte, 16), time.Time{})); err != nil {
			t.Fatalf("unexpected error on the 1st fragment: %v", err)
		}
		if _, err := defragger.DefragIP(dec.newIPv4Fragment(t, src, 3, 1, true, make([]byte, 16), time.Time{})); err == nil {
			t.Fatal("no error for an overlapping fragment")
		}
		if n := len(defragger.ipFlows); n != 0 {
			t.Fatalf("%d flows tracked after an overlap, want 0", n)
		}
		checkDefragmenter(t, defragger)

		if _, err := defragger.DefragIP(dec.newIPv4Fragment(t, src, 3, 0, true, make([]byte, 16), time.Time{})); err != nil {
			t.Fatalf("unexpected error on the new 1st fragment: %v", err)
		}
		pkt, err := defragger.DefragIP(dec.newIPv4Fragment(t, src, 3, 2, false, make([]byte, 8), time.Time{}))
		if err != nil || pkt == nil {
			t.Fatalf("new datagram not reassembled after an overlap: pkt=%v err=%v", pkt, err)
		}
	})
}

// Fragments that arrive out of order must reassemble in offset order.
func TestIpDefrag_IPv4OutOfOrder(t *testing.T) {
	forEachDecoder(t, func(t *testing.T, dec testDecoder) {
		src := net.IP{10, 0, 0, 1}
		a := bytes.Repeat([]byte{0xaa}, 8)
		b := bytes.Repeat([]byte{0xbb}, 8)
		c := bytes.Repeat([]byte{0xcc}, 8)

		defragger := NewIPDefragmenter()
		for _, frag := range []gopacket.Packet{
			dec.newIPv4Fragment(t, src, 4, 1, true, b, time.Time{}),
			dec.newIPv4Fragment(t, src, 4, 0, true, a, time.Time{}),
		} {
			if _, err := defragger.DefragIP(frag); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			checkDefragmenter(t, defragger)
		}
		pkt, err := defragger.DefragIP(dec.newIPv4Fragment(t, src, 4, 2, false, c, time.Time{}))
		if err != nil || pkt == nil {
			t.Fatalf("datagram not reassembled: pkt=%v err=%v", pkt, err)
		}
		ip4 := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if want := bytes.Join([][]byte{a, b, c}, nil); !bytes.Equal(ip4.Payload, want) {
			t.Errorf("reassembled payload = %x, want %x", ip4.Payload, want)
		}
	})
}

// BenchmarkDefragIP reassembles a DNS query of two fragments that NetDecoder
// decoded, as in the DNS-collector sniffer.
func BenchmarkDefragIP(b *testing.B) {
	tests := []struct {
		name      string
		fragments func() (gopacket.Packet, gopacket.Packet)
	}{
		{name: "IPv4", fragments: dnsQueryIPv4Fragments},
		{name: "IPv6", fragments: dnsQueryIPv6Fragments},
	}
	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			frag1, frag2 := tc.fragments()
			frag1 = gopacket.NewPacket(frag1.Data(), &NetDecoder{}, gopacket.NoCopy)
			frag2 = gopacket.NewPacket(frag2.Data(), &NetDecoder{}, gopacket.NoCopy)
			defragger := NewIPDefragmenter()
			b.ReportAllocs()
			for b.Loop() {
				if _, err := defragger.DefragIP(frag1); err != nil {
					b.Fatal(err)
				}
				if pkt, err := defragger.DefragIP(frag2); err != nil || pkt == nil {
					b.Fatalf("not reassembled: %v", err)
				}
			}
		})
	}
}
