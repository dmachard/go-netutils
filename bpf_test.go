package netutils

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/bpf"
)

func TestLabelResolver(t *testing.T) {
	bpfInstructions := &LabelResolver{LabelMap: make(map[string]int)}

	// Define some simple instructions with labels
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800}, "label_true", "label_false")
	bpfInstructions.Label("label_true")
	bpfInstructions.Add(bpf.RetConstant{Val: 0xFFFF}) // Accept packet
	bpfInstructions.Label("label_false")
	bpfInstructions.Add(bpf.RetConstant{Val: 0}) // Ignore packet

	// Resolve the instructions
	resolved, err := bpfInstructions.ResolveJumps()

	assert.NoError(t, err)
	assert.Equal(t, 3, len(resolved))
}

func TestGetBpfFilterPort(t *testing.T) {
	filter, err := GetBpfFilterPort(53)
	assert.NoError(t, err)
	assert.NotNil(t, filter)
}

// Test case for GetBpfFilterPort
func Test_GetBpfFilterPort_FromPcap(t *testing.T) {
	tests := []struct {
		name      string
		pcapFile  string
		port      int
		nbPackets int
	}{
		{
			name:      "DNS/UDP/IPv4 over GRE/IPv4",
			pcapFile:  "./pcap/gre_ipv4_dns_udp.pcap",
			port:      53, // DNS port
			nbPackets: 2,
		},
		{
			name:      "DNS/TCP/IPv4 over GRE/IPv4",
			pcapFile:  "./pcap/gre_ipv4_dns_tcp.pcap",
			port:      53, // DNS port
			nbPackets: 20,
		},
		{
			name:      "DNS/UDP/IPv4 over GRE/IPv4 with key",
			pcapFile:  "./pcap/gre+key_ipv4_dns_udp.pcap",
			port:      53, // DNS port
			nbPackets: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handle, err := pcap.OpenOffline(tt.pcapFile)
			if err != nil {
				t.Fatalf("failed to open pcap file: %v", err)
			}
			defer handle.Close()

			// Get BPF filter for the specified port
			bpfInstructions, err := GetBpfFilterPort(tt.port)
			if err != nil {
				t.Fatalf("failed to get BPF filter: %v", err)
			}

			// Convert BPF instructions to raw filter for pcap
			assembled, err := bpf.Assemble(bpfInstructions)
			if err != nil {
				t.Fatalf("failed to assemble BPF instructions: %v", err)
			}

			// Create a pcap BPF filter from the assembled instructions
			rawBPF := make([]pcap.BPFInstruction, len(assembled))
			for i, instr := range assembled {
				rawBPF[i] = pcap.BPFInstruction{
					Code: instr.Op,
					Jt:   instr.Jt,
					Jf:   instr.Jf,
					K:    instr.K,
				}
			}

			// Apply the filter to the pcap handle
			if err := handle.SetBPFInstructionFilter(rawBPF); err != nil {
				t.Fatalf("failed to set BPF filter: %v", err)
			}

			// Start capturing packets
			packetCount := 0
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for range packetSource.Packets() {
				packetCount += 1
			}

			// Check if the number of packets captured matches the expected value
			if packetCount != tt.nbPackets {
				t.Errorf("expected %d packets, got %d", tt.nbPackets, packetCount)
			}
		})
	}
}
