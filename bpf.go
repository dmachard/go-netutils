//go:build linux
// +build linux

package netutils

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	ethLen  = uint32(14)
	IPv6Len = uint32(40)

	offIPv6NxtHdr = uint32(6)
)

// Convert a uint16 to host byte order (big endian)
func Htons(v uint16) int {
	return int((v << 8) | (v >> 8))
}

// Instruction with optional label name
type LabeledInstruction struct {
	Instruction    bpf.Instruction
	SkipTrueLabel  string
	SkipFalseLabel string
	SkipLabel      string
}

// Helper to manage labels and calculate jumps
type LabelResolver struct {
	Instructions []LabeledInstruction
	LabelMap     map[string]int
}

// Add an instruction to the list
func (lr *LabelResolver) Add(instr bpf.Instruction) {
	lr.Instructions = append(lr.Instructions, LabeledInstruction{
		Instruction: instr,
	})
}

func (lr *LabelResolver) JumpTo(instr bpf.Instruction, jumpTo string) {
	lr.Instructions = append(lr.Instructions, LabeledInstruction{
		Instruction: instr,
		SkipLabel:   jumpTo,
	})
}

func (lr *LabelResolver) JumpIf(instr bpf.Instruction, onTrue, onFalse string) {
	lr.Instructions = append(lr.Instructions, LabeledInstruction{
		Instruction:    instr,
		SkipTrueLabel:  onTrue,
		SkipFalseLabel: onFalse,
	})
}

// Register a label at the current instruction position
func (lr *LabelResolver) Label(label string) error {
	if _, exists := lr.LabelMap[label]; exists {
		return fmt.Errorf("label %s already exists", label)
	}
	lr.LabelMap[label] = len(lr.Instructions)
	return nil
}

// Calculate the jump offsets based on labels
func (lr *LabelResolver) ResolveJumps() ([]bpf.Instruction, error) {
	finalInstructions := make([]bpf.Instruction, len(lr.Instructions))
	for i, labeledInstr := range lr.Instructions {
		instr := labeledInstr.Instruction
		switch jump := instr.(type) {
		case bpf.JumpIf:
			// Resolve SkipTrue based on label if provided
			if labeledInstr.SkipTrueLabel != "" {
				labelPos, ok := lr.LabelMap[labeledInstr.SkipTrueLabel]
				if !ok {
					return nil, fmt.Errorf("label %s not found for SkipTrue", labeledInstr.SkipTrueLabel)
				}
				jump.SkipTrue = uint8(labelPos - i - 1)
			}
			// Resolve SkipFalse based on label if provided
			if labeledInstr.SkipFalseLabel != "" {
				labelPos, ok := lr.LabelMap[labeledInstr.SkipFalseLabel]
				if !ok {
					return nil, fmt.Errorf("label %s not found for SkipFalse", labeledInstr.SkipFalseLabel)
				}
				jump.SkipFalse = uint8(labelPos - i - 1)
			}
			instr = jump
		case bpf.Jump:
			// Resolve SkipTrue based on label if provided
			if labeledInstr.SkipLabel != "" {
				labelPos, ok := lr.LabelMap[labeledInstr.SkipLabel]
				if !ok {
					return nil, fmt.Errorf("label %s not found for Skip", labeledInstr.SkipLabel)
				}
				jump.Skip = uint32(labelPos - i - 1)
			}
			instr = jump
		}
		finalInstructions[i] = instr
	}
	return finalInstructions, nil
}

func GetBpfDnsFilterPort(port int) ([]bpf.Instruction, error) {
	bpfInstructions := &LabelResolver{LabelMap: make(map[string]int)}

	// IPv4, IPv6 protocol condition from ethernet layer
	bpfInstructions.Add(bpf.LoadConstant{Dst: bpf.RegX, Val: ethLen})                                  // X = 14
	bpfInstructions.Add(bpf.LoadAbsolute{Off: 12, Size: 2})                                            // A = pkt[12:14] = eth.type (2 bytes)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800}, "read_ipv4", "")              // A == IPv4 ?
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd}, "read_ipv6", "ignore_packet") // A == IPv6 ?

	// Read IPv4 layer
	bpfInstructions.Label("read_ipv4")
	bpfInstructions.Add(bpf.LoadIndirect{Off: 6, Size: 2})                                                    // A = pkt[X+6:X+8] = flags and fragment offset (2 bytes)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff}, "accept_packet", "")               // A = 0x1fff == 0001 1111 1111 1111 (fragment) ?
	bpfInstructions.Add(bpf.LoadIndirect{Off: 9, Size: 1})                                                    // A = pkt[X+9:X+10] = ip.proto (1 byte)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_ipv4_transport", "")             // A == UDP ?
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_ipv4_transport", "ignore_packet") // A == TCP ?

	// Read Transport layer
	bpfInstructions.Label("read_ipv4_transport")
	bpfInstructions.Add(bpf.LoadIndirect{Off: 0, Size: 1})                                                       // A = pkt[X:X+1] (ihl)
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x0F})                                          // A = A & 0x0F (get IHL)
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpMul, Val: 4})                                             // A = A * 4 (length in bytes)
	bpfInstructions.Add(bpf.ALUOpX{Op: bpf.ALUOpAdd})                                                            // A = A + X
	bpfInstructions.Add(bpf.TAX{})                                                                               // X = A
	bpfInstructions.Add(bpf.LoadIndirect{Off: 0, Size: 2})                                                       // If A=53, accept the packet
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // If A=53, accept the packet
	bpfInstructions.Add(bpf.LoadIndirect{Off: 2, Size: 2})                                                       // A = pkt[X+2:X+4] = destination port
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // If A=53, accept the packet

	// // Read the IPv6 layer,  Register X  = ethLen
	bpfInstructions.Label("read_ipv6")
	bpfInstructions.Add(bpf.LoadIndirect{Off: offIPv6NxtHdr, Size: 1}) // A = pkt[X+6:X+7] = IPv6 Next Header (1 byte)

	// // Check the Next Header protocol to decide how to proceed
	bpfInstructions.Label("check_next_header")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2c}, "accept_packet", "")                   // If A == Fragmentation, accept the packet
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_ipv6_transport", "")             // If A == UDP, read transport layer
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_ipv6_transport", "ignore_packet") // If A == TCP, read transport layer

	// Read the IPv6 transport layer (UDP/TCP)
	bpfInstructions.Label("read_ipv6_transport")
	bpfInstructions.Add(bpf.TXA{})                                                                               // A = X
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: IPv6Len})                                       // A = A + 40
	bpfInstructions.Add(bpf.TAX{})                                                                               // X = A
	bpfInstructions.Add(bpf.LoadIndirect{Off: 0, Size: 2})                                                       // A = pkt[X:X+2] = source port
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // If A=53, accept the packet
	bpfInstructions.Add(bpf.LoadIndirect{Off: 2, Size: 2})                                                       // A = pkt[X+2:X+4] = destination port
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // If A=53, accept the packet

	// Keep the packet and send up to 65k of the packet to userspace
	bpfInstructions.Label("accept_packet")
	bpfInstructions.Add(bpf.RetConstant{Val: 0xFFFF})

	// Ignore packet
	bpfInstructions.Label("ignore_packet")
	bpfInstructions.Add(bpf.RetConstant{Val: 0})

	// Resolve and return final list of instructions
	return bpfInstructions.ResolveJumps()
}

func GetBpfGreDnsFilterPort(port int) ([]bpf.Instruction, error) {
	bpfInstructions := &LabelResolver{LabelMap: make(map[string]int)}

	// IPv4, IPv6 protocol condition from ethernet layer
	bpfInstructions.Add(bpf.LoadConstant{Dst: bpf.RegX, Val: ethLen})                                  // X = 14
	bpfInstructions.Add(bpf.LoadAbsolute{Off: 12, Size: 2})                                            // A = pkt[12:14] = eth.type (2 bytes)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800}, "read_ipv4", "")              // A == IPv4 ?
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd}, "read_ipv6", "ignore_packet") // A == IPv6 ?

	// Read IPv4 layer
	bpfInstructions.Label("read_ipv4")
	bpfInstructions.Add(bpf.LoadIndirect{Off: 6, Size: 2})                                               // A = pkt[X+6:X+8] = flags and fragment offset (2 bytes)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff}, "accept_packet", "")          // A = 0x1fff == 0001 1111 1111 1111 (fragment) ?
	bpfInstructions.Add(bpf.LoadIndirect{Off: 9, Size: 1})                                               // A = pkt[X+9:X+10] = ip.proto (1 byte)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_ipv4_transport", "")        // A == UDP ?
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_ipv4_transport", "")         // A == TCP ?
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2f}, "read_ipv4_gre", "ignore_packet") // A == GRE ?

	// Update X = Ethernet length + IP header length
	bpfInstructions.Label("read_ipv4_gre")
	bpfInstructions.Add(bpf.LoadMemShift{Off: ethLen}) // X = IP header size
	bpfInstructions.Add(bpf.TXA{})
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: ethLen}) // A = A + 14
	bpfInstructions.Add(bpf.TAX{})
	bpfInstructions.JumpTo(bpf.Jump{}, "read_gre")

	// Read Transport layer
	bpfInstructions.Label("read_ipv4_transport")
	bpfInstructions.Add(bpf.LoadIndirect{Off: 0, Size: 1})                                                       // A = pkt[X:X+1] (ihl)
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x0F})                                          // A = A & 0x0F (get IHL)
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpMul, Val: 4})                                             // A = A * 4 (length in bytes)
	bpfInstructions.Add(bpf.ALUOpX{Op: bpf.ALUOpAdd})                                                            // A = A + X
	bpfInstructions.Add(bpf.TAX{})                                                                               // X = A
	bpfInstructions.Add(bpf.LoadIndirect{Off: 0, Size: 2})                                                       // If A=53, accept the packet
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // If A=53, accept the packet
	bpfInstructions.Add(bpf.LoadIndirect{Off: 2, Size: 2})                                                       // A = pkt[X+2:X+4] = destination port
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // If A=53, accept the packet

	// // Read the IPv6 layer,  Register X  = ethLen
	bpfInstructions.Label("read_ipv6")
	bpfInstructions.Add(bpf.LoadConstant{Dst: bpf.RegA, Val: 0})                                             // A = 0
	bpfInstructions.Add(bpf.StoreScratch{Src: bpf.RegA, N: 0})                                               // N[0] = A , init with 0
	bpfInstructions.Add(bpf.LoadIndirect{Off: offIPv6NxtHdr, Size: 1})                                       // A = pkt[X+6:X+7] = IPv6 Next Header (1 byte)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2c}, "accept_packet", "")                  // If A == Fragmentation, accept the packet
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_ipv6_transport", "")            // If A == UDP, read transport layer
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_ipv6_transport", "")             // If A == TCP, read transport layer
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2f}, "read_ipv6_gre", "")                  // If A == GRE, jump to read GRE
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3c}, "read_ipv6_options", "ignore_packet") // If A == IPv6 Options, process options, otherwise ignore packet

	// Handle IPv6 options
	bpfInstructions.Label("read_ipv6_options")
	bpfInstructions.Add(bpf.LoadIndirect{Off: IPv6Len + 1, Size: 1}) // A = pkt[X+41:X+42] = length of IPv6 options (1 byte)
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 1}) // A = A + 1
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpMul, Val: 8}) // A = A x 8
	bpfInstructions.Add(bpf.StoreScratch{Src: bpf.RegA, N: 0})       // N[0] = A = length of IPv6options in bytes
	bpfInstructions.Add(bpf.LoadIndirect{Off: IPv6Len, Size: 1})     // A = pkt[X+40:X+41] = next header for IPv6 options
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2f}, "read_ipv6_gre", "ignore_packet")

	// Read the IPv6 transport layer (UDP/TCP)
	bpfInstructions.Label("read_ipv6_transport")
	bpfInstructions.Add(bpf.TXA{})                                                                               // A = X
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: IPv6Len})                                       // A = A + 40
	bpfInstructions.Add(bpf.TAX{})                                                                               // X = A
	bpfInstructions.Add(bpf.LoadIndirect{Off: 0, Size: 2})                                                       // A = pkt[X:X+2] = source port
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // If A=53, accept the packet
	bpfInstructions.Add(bpf.LoadIndirect{Off: 2, Size: 2})                                                       // A = pkt[X+2:X+4] = destination port
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // If A=53, accept the packet

	bpfInstructions.Label("read_ipv6_gre")
	bpfInstructions.Add(bpf.LoadScratch{Dst: bpf.RegA, N: 0})              // A = N[0]
	bpfInstructions.Add(bpf.ALUOpX{Op: bpf.ALUOpAdd})                      // A = A + X
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: IPv6Len}) // A = A + 40  = (ip option length + fixed ipv6 header len)
	bpfInstructions.Add(bpf.TAX{})                                         // X = A
	bpfInstructions.JumpTo(bpf.Jump{}, "read_gre")

	bpfInstructions.Label("read_gre")
	bpfInstructions.Add(bpf.LoadIndirect{Off: 0, Size: 2}) // A = pkt[X:X+2] = GRE flags (2 bytes)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0}, "read_gre_has_noflags", "")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2000}, "read_gre_has_K", "")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x4000}, "read_gre_has_S", "")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8000}, "read_gre_has_C", "")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6000}, "read_gre_has_KS", "")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xA000}, "read_gre_has_CK", "")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xC000}, "read_gre_has_CS", "")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xB000}, "read_gre_has_CKS", "ignore_packet")

	bpfInstructions.Label("read_gre_has_noflags")
	bpfInstructions.Add(bpf.TXA{})                                   // A = X
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 4}) // A = A + 4
	bpfInstructions.Add(bpf.StoreScratch{Src: bpf.RegA, N: 0})       // N[0] = A
	bpfInstructions.JumpTo(bpf.Jump{}, "read_gre_proto")

	bpfInstructions.Label("read_gre_has_C")
	bpfInstructions.Label("read_gre_has_K")
	bpfInstructions.Label("read_gre_has_S")
	bpfInstructions.Add(bpf.TXA{})                                   // A = X
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 8}) // A = A + 8
	bpfInstructions.Add(bpf.StoreScratch{Src: bpf.RegA, N: 0})       // N[0] = A
	bpfInstructions.JumpTo(bpf.Jump{}, "read_gre_proto")

	bpfInstructions.Label("read_gre_has_CK")
	bpfInstructions.Label("read_gre_has_KS")
	bpfInstructions.Label("read_gre_has_CS")
	bpfInstructions.Add(bpf.TXA{})                                    // A = X
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 12}) // A = A + 12
	bpfInstructions.Add(bpf.StoreScratch{Src: bpf.RegA, N: 0})        // N[0] = A
	bpfInstructions.JumpTo(bpf.Jump{}, "read_gre_proto")

	bpfInstructions.Label("read_gre_has_CKS")
	bpfInstructions.Add(bpf.TXA{})                                    // A = X
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 16}) // A = A + 16
	bpfInstructions.Add(bpf.StoreScratch{Src: bpf.RegA, N: 0})        // N[0] = A
	bpfInstructions.JumpTo(bpf.Jump{}, "read_gre_proto")

	bpfInstructions.Label("read_gre_proto")
	bpfInstructions.Add(bpf.LoadIndirect{Off: 2, Size: 2})                                                 // A = pkt[X+2:X+4] = GRE proto (2 bytes)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800}, "read_gre_ipv4", "")              // A = IPv4 ?
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd}, "read_gre_ipv6", "ignore_packet") // A = IPv6 ?

	// // Read the IPv6 layer,  Register X  = ethLen
	bpfInstructions.Label("read_gre_ipv6")
	bpfInstructions.Add(bpf.LoadScratch{Dst: bpf.RegX, N: 0})                                                     // X = N[0]
	bpfInstructions.Add(bpf.LoadIndirect{Off: offIPv6NxtHdr, Size: 1})                                            // A = pkt[X+6:X+7] = IPv6 Next Header (1 byte)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2c}, "accept_packet", "")                       // If A == Fragmentation, accept the packet
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_gre_ipv6_transport", "")             // If A == UDP, read transport layer
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_gre_ipv6_transport", "ignore_packet") // If A == TCP, read transport layer

	// Read the IPv6 transport layer (UDP/TCP)
	bpfInstructions.Label("read_gre_ipv6_transport")
	bpfInstructions.Add(bpf.TXA{})                                                                               // A = X
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: IPv6Len})                                       // A = A + 40
	bpfInstructions.Add(bpf.TAX{})                                                                               // X = A
	bpfInstructions.Add(bpf.LoadIndirect{Off: 0, Size: 2})                                                       // A = pkt[X:X+2] = source port
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // If A=53, accept the packet
	bpfInstructions.Add(bpf.LoadIndirect{Off: 2, Size: 2})                                                       // A = pkt[X+2:X+4] = destination port
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // If A=53, accept the packet

	// Read IPv4 layer
	bpfInstructions.Label("read_gre_ipv4")
	bpfInstructions.Add(bpf.LoadIndirect{Off: 6, Size: 2})                                                        // A = pkt[X+6:X+8] = flags and fragment offset (2 bytes)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff}, "accept_packet", "")                   // A = 0x1fff == 0001 1111 1111 1111 (fragment) ?
	bpfInstructions.Add(bpf.LoadIndirect{Off: 9, Size: 1})                                                        // A = pkt[X+9:X+10] = ip.proto (1 byte)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_gre_ipv4_transport", "")             // A == UDP ?
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_gre_ipv4_transport", "ignore_packet") // A == TCP ?

	// Read Transport layer
	bpfInstructions.Label("read_gre_ipv4_transport")
	bpfInstructions.Add(bpf.LoadIndirect{Off: 0, Size: 1})                                                       // A = pkt[X:X+1] (ihl)
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x0F})                                          // A = A & 0x0F (get IHL)
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpMul, Val: 4})                                             // A = A * 4 (length in bytes)
	bpfInstructions.Add(bpf.ALUOpX{Op: bpf.ALUOpAdd})                                                            // A = A + X
	bpfInstructions.Add(bpf.TAX{})                                                                               // X = A
	bpfInstructions.Add(bpf.LoadIndirect{Off: 0, Size: 2})                                                       // If A=53, accept the packet
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // If A=53, accept the packet
	bpfInstructions.Add(bpf.LoadIndirect{Off: 2, Size: 2})                                                       // A = pkt[X+2:X+4] = destination port
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // If A=53, accept the packet

	// Keep the packet and send up to 65k of the packet to userspace
	bpfInstructions.Label("accept_packet")
	bpfInstructions.Add(bpf.RetConstant{Val: 0xFFFF})

	// Ignore packet
	bpfInstructions.Label("ignore_packet")
	bpfInstructions.Add(bpf.RetConstant{Val: 0})

	// Resolve and return final list of instructions
	return bpfInstructions.ResolveJumps()
}

func ApplyBpfFilter(filter []bpf.Instruction, fd int) (err error) {
	var assembled []bpf.RawInstruction
	if assembled, err = bpf.Assemble(filter); err != nil {
		return err
	}

	prog := &unix.SockFprog{
		Len:    uint16(len(assembled)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&assembled[0])),
	}

	return unix.SetsockoptSockFprog(fd, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, prog)
}

func RemoveBpfFilter(fd int) (err error) {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_DETACH_FILTER, 0)
}
