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
func (lr *LabelResolver) Label(label string) {
	lr.LabelMap[label] = len(lr.Instructions)
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

const (
	EthLen  = uint32(14)
	IPv6Len = uint32(40)
	GreLen  = uint32(4)
)

func GetBpfFilterPort(port int) ([]bpf.Instruction, error) {
	bpfInstructions := &LabelResolver{LabelMap: make(map[string]int)}

	// IPv4, IPv6 protocol condition from ethernet layer
	bpfInstructions.Add(bpf.LoadAbsolute{Off: 12, Size: 2})                                            // load eth.type (2 bytes at offset 12) and push-it in register A
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800}, "read_ipv4", "")              // If eth.type == IPv4, goto read_ipv4
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd}, "read_ipv6", "ignore_packet") // If eth.type == IPv6, goto read_ipv6

	// Read IPv4 layer
	bpfInstructions.Label("read_ipv4")
	bpfInstructions.Add(bpf.LoadAbsolute{Off: EthLen + 6, Size: 2})                                            // load flags and fragment offset (2 bytes at offset 20)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff}, "accept_packet", "")                // Only look at the last 13 bits of the data saved in regiter A, 0x1fff == 0001 1111 1111 1111 (fragment offset)
	bpfInstructions.Add(bpf.LoadAbsolute{Off: EthLen + 9, Size: 1})                                            // Load ip.proto (1 byte at offset 23) and push-it in register A
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_ipv4_transport", "")              // ip.proto == UDP ? goto read_ipv4_transport
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_ipv4_transport", "")               // ip.proto == TCP ? goto read_ipv4_transport
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2f}, "read_ipv4_gre_proto", "ignore_packet") // ip.proto == GRE, goto read_gre else ignore packet
	bpfInstructions.Label("read_ipv4_transport")
	bpfInstructions.Add(bpf.LoadMemShift{Off: EthLen})                                                           // Load IP header size in Register X
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen, Size: 2})                                                  // Load source port in tcp or udp (2 bytes at offset Register X+EthLen)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // source port equal to 53 ?
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen + 2, Size: 2})                                              // Load destination port in tcp or udp  (2 bytes at offset x+16)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // destination port equal to 53 ?

	// Read GRE layer over IPv4
	bpfInstructions.Label("read_ipv4_gre_proto")
	bpfInstructions.Add(bpf.LoadMemShift{Off: EthLen})                                                                // Load IP header size in Register X
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen + 2, Size: 2})                                                   // Load GRE protocol type from header
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800}, "read_ipv4_gre_flags_ipv4", "ignore_packet") // If GRE proto == IPv4, goto read_gre_ipv4

	bpfInstructions.Label("read_ipv4_gre_flags_ipv4")
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen, Size: 2}) // Load GRE flags from header (2 bytes at offset 34)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x8000}, "has_C", "")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x2000}, "has_K", "")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0xA000}, "has_CK", "read_ipv4_gre_ipv4")
	bpfInstructions.Label("has_C")
	bpfInstructions.Add(bpf.TXA{})
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 2})
	bpfInstructions.Add(bpf.TAX{})
	bpfInstructions.JumpTo(bpf.Jump{}, "read_ipv4_gre_ipv4")
	bpfInstructions.Label("has_K")
	bpfInstructions.Add(bpf.TXA{})
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 4})
	bpfInstructions.Add(bpf.TAX{})
	bpfInstructions.JumpTo(bpf.Jump{}, "read_ipv4_gre_ipv4")
	bpfInstructions.Label("has_CK")
	bpfInstructions.Add(bpf.TXA{})
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 6})
	bpfInstructions.Add(bpf.TAX{})
	bpfInstructions.JumpTo(bpf.Jump{}, "read_ipv4_gre_ipv4")

	bpfInstructions.Label("read_ipv4_gre_ipv4")
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen + GreLen + 6, Size: 2})                                           // load flags and fragment offset (2 bytes at offset 20)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff}, "accept_packet", "")                        // Only look at the last 13 bits of the data saved in regiter A, 0x1fff == 0001 1111 1111 1111 (fragment offset)
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen + GreLen + 9, Size: 1})                                           // Load ip.proto (1 byte at offset 23) and push-it in register A
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_ipv4_gre_ipv4_transport", "")             // ip.proto == UDP ? goto read_ipv4_transport
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_ipv4_gre_ipv4_transport", "ignore_packet") // ip.proto == TCP ? goto read_ipv4_transport
	bpfInstructions.Label("read_ipv4_gre_ipv4_transport")
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen + GreLen, Size: 1})                                         // Load the byte at offset 14 into register A to get dynamix header size
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x0F})                                          // A = A & 0x0F (keep only the lower 4 bits)
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpShiftLeft, Val: 2})                                       // A = A << 2 (shift left by 2 bits to multiply by 4)
	bpfInstructions.Add(bpf.ALUOpX{Op: bpf.ALUOpAdd})                                                            // add register X+A
	bpfInstructions.Add(bpf.TAX{})                                                                               // move register A to X
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen + GreLen, Size: 2})                                         // Load source port in tcp or udp (2 bytes at offset Register X+EthLen)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // source port equal to 53 ?
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen + GreLen + 2, Size: 2})                                     // Load destination port in tcp or udp  (2 bytes at offset x+16)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // destination port equal to 53 ?

	// read IPv6 layer
	bpfInstructions.Label("read_ipv6")
	bpfInstructions.Add(bpf.LoadAbsolute{Off: EthLen + 6, Size: 1})                                            // Load ipv6.nxt (2 bytes at offset 12) and push-it in register A
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2c}, "accept_packet", "")                    // fragment ?
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_ipv6_transport", "")              // ip.proto == UDP ?
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_ipv6_transport", "ignore_packet")  // ip.proto == TCP ?
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2f}, "read_ipv6_gre_proto", "ignore_packet") // ip.proto == GRE, goto read_gre else ignore packet
	bpfInstructions.Label("read_ipv6_transport")
	bpfInstructions.Add(bpf.LoadAbsolute{Off: EthLen + IPv6Len, Size: 2})                                        // Load source port tcp or udp (2 bytes at offset 54)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // source port equal to 53 ?
	bpfInstructions.Add(bpf.LoadAbsolute{Off: EthLen + IPv6Len + 2, Size: 2})                                    // Load destination port tcp or udp (2 bytes at offset 56)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // destination port equal to 53 ?

	// Read GRE layer over IPv6
	bpfInstructions.Label("read_ipv6_gre_proto")
	bpfInstructions.Add(bpf.LoadMemShift{Off: EthLen})                                                                // Load IP header size in Register X
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen + 2, Size: 2})                                                   // Load GRE protocol type from header
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd}, "read_ipv4_gre_flags_ipv6", "ignore_packet") // If GRE proto == IPv4, goto read_gre_ipv4

	bpfInstructions.Label("read_ipv4_gre_flags_ipv6")
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen, Size: 2}) // Load GRE flags from header (2 bytes at offset 34)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x8000}, "has_C", "")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x2000}, "has_K", "")
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0xA000}, "has_CK", "read_ipv6_gre_ipv6")
	bpfInstructions.Label("has_C")
	bpfInstructions.Add(bpf.TXA{})
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 2})
	bpfInstructions.Add(bpf.TAX{})
	bpfInstructions.JumpTo(bpf.Jump{}, "read_ipv6_gre_ipv6")
	bpfInstructions.Label("has_K")
	bpfInstructions.Add(bpf.TXA{})
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 4})
	bpfInstructions.Add(bpf.TAX{})
	bpfInstructions.JumpTo(bpf.Jump{}, "read_ipv6_gre_ipv6")
	bpfInstructions.Label("has_CK")
	bpfInstructions.Add(bpf.TXA{})
	bpfInstructions.Add(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 6})
	bpfInstructions.Add(bpf.TAX{})
	bpfInstructions.JumpTo(bpf.Jump{}, "read_ipv6_gre_ipv6")

	bpfInstructions.Label("read_ipv6_gre_ipv6")
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen + GreLen + 6, Size: 1})                                           // Load ipv6.nxt (2 bytes at offset 12) and push-it in register A
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2c}, "accept_packet", "")                            // fragment ?
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_ipv6_gre_ipv6_transport", "")             // ip.proto == UDP ? goto read_ipv6_gre_ipv6_transport
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_ipv6_gre_ipv6_transport", "ignore_packet") // ip.proto == TCP ? goto read_ipv6_gre_ipv6_transport
	bpfInstructions.Label("read_ipv6_gre_ipv6_transport")
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen + GreLen + IPv6Len, Size: 2})                               // Load source port in tcp or udp (2 bytes at offset Register X+EthLen)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // source port equal to 53 ?
	bpfInstructions.Add(bpf.LoadIndirect{Off: EthLen + GreLen + IPv6Len + 2, Size: 2})                           // Load destination port in tcp or udp  (2 bytes at offset x+16)
	bpfInstructions.JumpIf(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // destination port equal to 53 ?

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
