package netutils

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestIpDefrag_IPv4Fragment(t *testing.T) {
	// fragmented packet, see the packet in testsdata/pcap/dnsdump_ip4_fragmented_query.pcap
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
}

func TestIpDefrag_IPv4FragmentWithRetransmission(t *testing.T) {

	// fragmented packet, see the packet in testsdata/pcap/dnsdump_ip4_fragmented_query.pcap
	packetBytes := []byte{
		0x58, 0x1d, 0xd8, 0x12, 0x84, 0x10, 0xb0, 0x35, 0x9f, 0xd4, 0x03, 0x91, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x39, 0x00, 0x01, 0x00, 0x07, 0x40, 0x11, 0xeb, 0x9b, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x08,
		0x08, 0x08, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x03, 0x63,
		0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeEthernet, gopacket.Default)

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
}

func TestIpDefrag_IPv6Fragment(t *testing.T) {
	// fragmented packet, see the packet in testsdata/pcap/dnsdump_ip4_fragmented_query.pcap
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
}
