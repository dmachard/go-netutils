package netutils

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func Test_IpDefrag(t *testing.T) {
	tests := []struct {
		name      string
		pcapFile  string
		nbPackets int
	}{
		{
			name:      "DNS UDP with IPv4 Fragmented",
			pcapFile:  "./pcap/dnsdump_ip4_fragmented+udp.pcap",
			nbPackets: 2,
		},

		{
			name:      "DNS UDP with IPv6 Fragmented",
			pcapFile:  "./pcap/dnsdump_ip6_fragmented+udp.pcap",
			nbPackets: 2,
		},
	}

	done := make(chan bool)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.pcapFile)
			if err != nil {
				t.Errorf("unable to open file: %s", err)
				return
			}
			defer f.Close()

			pcapHandler, err := pcapgo.NewReader(f)
			if err != nil {
				t.Errorf("unable to open pcap file: %s", err)
				return
			}

			fragIP4Chan := make(chan gopacket.Packet)
			fragIP6Chan := make(chan gopacket.Packet)
			outputChan := make(chan gopacket.Packet, 2)

			// defrag ipv4
			go IPDefragger(fragIP4Chan, outputChan, outputChan, 53)
			// defrag ipv6
			go IPDefragger(fragIP6Chan, outputChan, outputChan, 53)

			packetSource := gopacket.NewPacketSource(pcapHandler, pcapHandler.LinkType())
			packetSource.DecodeOptions.Lazy = true

			nbPackets := 0
			timeout := time.After(1 * time.Second)
			go func() {

				for {
					select {
					case <-outputChan:
						nbPackets++
					case <-timeout:
						goto STOP
					}
				}
			STOP:
				done <- true
			}()

			for {
				packet, err := packetSource.NextPacket()
				if err != nil {
					break
				}

				// ipv4 fragmented packet ?
				if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
					ip4 := packet.NetworkLayer().(*layers.IPv4)
					if ip4.Flags&layers.IPv4MoreFragments == 1 || ip4.FragOffset > 0 {
						fragIP4Chan <- packet
					} else {
						outputChan <- packet
					}
				}

				if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
					v6frag := packet.Layer(layers.LayerTypeIPv6Fragment)
					if v6frag != nil {
						fragIP6Chan <- packet
					} else {
						outputChan <- packet
					}
				}

			}

			<-done

			if nbPackets != tc.nbPackets {
				t.Errorf("bad number of packets, wants: %d, got: %d", tc.nbPackets, nbPackets)
			}
		})
	}
}

// A fragment that DefragIP rejects must not stop the defragger goroutine.
// Before, the first error ended the loop, nothing read the input channel
// again, and the sniffer blocked for good.
func TestIPDefragger_ContinuesAfterRejectedFragment(t *testing.T) {
	tests := []struct {
		name string
		frag func(t *testing.T, dec testDecoder) gopacket.Packet
	}{
		{
			name: "offset too big",
			frag: func(t *testing.T, dec testDecoder) gopacket.Packet {
				return dec.newIPv4Fragment(t, net.IP{10, 0, 0, 1}, 1, IPv4MaximumFragmentOffset+1, false, make([]byte, 8), time.Time{})
			},
		},
		{
			name: "fragment too small",
			frag: func(t *testing.T, dec testDecoder) gopacket.Packet {
				return dec.newIPv4Fragment(t, net.IP{10, 0, 0, 1}, 1, 0, true, make([]byte, 4), time.Time{})
			},
		},
	}

	forEachDecoder(t, func(t *testing.T, dec testDecoder) {
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				ipInput := make(chan gopacket.Packet)
				udpOutput := make(chan gopacket.Packet, 1)
				tcpOutput := make(chan gopacket.Packet, 1)
				done := make(chan struct{})
				go func() {
					IPDefragger(ipInput, udpOutput, tcpOutput, 53)
					close(done)
				}()
				defer func() {
					close(ipInput)
					<-done
				}()

				send := func(p gopacket.Packet) {
					select {
					case ipInput <- p:
					case <-time.After(time.Second):
						t.Fatal("the defragger no longer reads its input")
					}
				}

				send(tc.frag(t, dec))
				frag1, frag2 := dec.dnsQueryIPv4Fragments()
				send(frag1)
				send(frag2)

				select {
				case <-udpOutput:
				case <-time.After(time.Second):
					t.Fatal("DNS query not reassembled after a rejected fragment")
				}
			})
		}
	})
}

// IPDefragmented must be true only for a datagram that IPDefragger
// reassembled. It must not follow Metadata().Truncated, because NetDecoder
// sets that on a UDP packet whose length field is larger than the packet.
func TestUDPProcessor_IPDefragmented(t *testing.T) {
	frag1, frag2 := dnsQueryIPv4Fragments()
	defragger := NewIPDefragmenter()
	if _, err := defragger.DefragIP(frag1); err != nil {
		t.Fatal(err)
	}
	reassembled, err := defragger.DefragIP(frag2)
	if err != nil || reassembled == nil {
		t.Fatalf("query not reassembled: %v", err)
	}

	// The first fragment again, without the fragment flags: a whole UDP
	// packet whose length field claims more bytes than the packet has.
	short := append([]byte(nil), frag1.Data()...)
	short[20], short[21] = 0, 0

	tests := []struct {
		name   string
		packet gopacket.Packet
		want   bool
	}{
		{name: "reassembled", packet: reassembled, want: true},
		{name: "short UDP from NetDecoder", packet: gopacket.NewPacket(short, &NetDecoder{}, gopacket.NoCopy), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			udpInput := make(chan gopacket.Packet, 1)
			dnsOutput := make(chan DNSPacket, 1)
			udpInput <- tc.packet
			close(udpInput)
			UDPProcessor(udpInput, dnsOutput, 0)
			if got := (<-dnsOutput).IPDefragmented; got != tc.want {
				t.Errorf("IPDefragmented = %v, want %v", got, tc.want)
			}
		})
	}
}
