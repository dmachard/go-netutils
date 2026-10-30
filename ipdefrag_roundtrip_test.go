package netutils

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// newIPv6Fragment builds one IPv6 fragment. offset is in 8-byte units, as in
// the fragment header. gopacket can't serialize IPv6Fragment, so the fragment
// header is written by hand.
func newIPv6Fragment(t testing.TB, id uint32, offset uint16, more bool, payload []byte, ts time.Time) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Fragment,
		HopLimit:   64,
		SrcIP:      net.ParseIP("fd00::1"),
		DstIP:      net.ParseIP("fd00::2"),
	}
	frag := make([]byte, 8, 8+len(payload))
	frag[0] = byte(layers.IPProtocolUDP)
	offsetAndFlags := offset << 3
	if more {
		offsetAndFlags |= 1
	}
	binary.BigEndian.PutUint16(frag[2:], offsetAndFlags)
	binary.BigEndian.PutUint32(frag[4:], id)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, gopacket.Payload(append(frag, payload...))); err != nil {
		t.Fatalf("serialize fragment: %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = ts
	return pkt
}

// checkRoundTrip splits a random datagram into fragments, and sends them to
// DefragIP in a random order, with duplicates, an optional overlap, and the
// fragments of other flows that never complete. The reassembled payload must
// equal the datagram, and without an overlap it must come out.
func checkRoundTrip(t *testing.T, dec testDecoder, seed int64, ipv6 bool) {
	rng := rand.New(rand.NewSource(seed))
	ts := time.Unix(1700000000, 0)
	datagram := make([]byte, 8+rng.Intn(4000))
	rng.Read(datagram)

	newFragment := func(id uint16, offset int, more bool, payload []byte) gopacket.Packet {
		if ipv6 {
			return dec.decode(newIPv6Fragment(t, uint32(id), uint16(offset/8), more, payload, ts))
		}
		return dec.newIPv4Fragment(t, net.IP{10, 0, 0, 1}, id, uint16(offset/8), more, payload, ts)
	}

	// Split in pieces of 8 to 1480 bytes, a multiple of 8 except the last.
	type piece struct{ offset, end int }
	var pieces []piece
	for offset := 0; offset < len(datagram); {
		end := offset + 8*(1+rng.Intn(185))
		if end >= len(datagram)-8 {
			end = len(datagram)
		}
		pieces = append(pieces, piece{offset, end})
		offset = end
	}
	if len(pieces) < 2 {
		return
	}
	end := len(datagram)
	rng.Shuffle(len(pieces), func(i, j int) { pieces[i], pieces[j] = pieces[j], pieces[i] })

	const id = 1
	var sends []gopacket.Packet
	for _, p := range pieces {
		more := p.end != end
		sends = append(sends, newFragment(id, p.offset, more, datagram[p.offset:p.end]))
		if rng.Intn(4) == 0 {
			sends = append(sends, newFragment(id, p.offset, more, datagram[p.offset:p.end]))
		}
		if rng.Intn(3) == 0 {
			// A fragment of another flow that never completes.
			sends = append(sends, newFragment(uint16(2+rng.Intn(1000)), 8*(1+rng.Intn(100)), true, make([]byte, 8)))
		}
	}
	overlap := rng.Intn(4) == 0
	if overlap {
		// 8 bytes more than a stored piece, at the same offset.
		p := pieces[rng.Intn(len(pieces))]
		data := append(append([]byte(nil), datagram[p.offset:p.end]...), make([]byte, 8)...)
		i := rng.Intn(len(sends) + 1)
		sends = append(sends[:i], append([]gopacket.Packet{newFragment(id, p.offset, true, data)}, sends[i:]...)...)
	}

	// A duplicate after the reassembly starts a new flow, which can complete
	// again, so each output must equal the datagram.
	d := NewIPDefragmenter()
	var outputs int
	for _, frag := range sends {
		out, _ := d.DefragIP(frag)
		checkDefragmenter(t, d)
		if out == nil {
			continue
		}
		outputs++
		var payload []byte
		if ipv6 {
			payload = out.Layer(layers.LayerTypeIPv6).(*layers.IPv6).Payload
		} else {
			payload = out.Layer(layers.LayerTypeIPv4).(*layers.IPv4).Payload
		}
		if !bytes.Equal(payload, datagram) {
			t.Fatalf("seed %d: reassembled %d bytes that differ from the %d-byte datagram", seed, len(payload), len(datagram))
		}
	}
	if outputs == 0 && !overlap {
		t.Fatalf("seed %d: datagram of %d bytes in %d fragments not reassembled", seed, len(datagram), len(pieces))
	}
}

func TestIpDefrag_RoundTrip(t *testing.T) {
	forEachDecoder(t, func(t *testing.T, dec testDecoder) {
		for seed := int64(0); seed < 300; seed++ {
			checkRoundTrip(t, dec, seed, false)
			checkRoundTrip(t, dec, seed, true)
		}
	})
}

// FuzzDefragRoundTrip runs checkRoundTrip on more seeds than the unit test.
func FuzzDefragRoundTrip(f *testing.F) {
	f.Add(int64(0), false)
	f.Add(int64(0), true)
	f.Fuzz(func(t *testing.T, seed int64, ipv6 bool) {
		for _, dec := range testDecoders {
			checkRoundTrip(t, dec, seed, ipv6)
		}
	})
}
