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
}

// Helper to manage labels and calculate jumps
type LabelResolver struct {
	Instructions []LabeledInstruction
	LabelMap     map[string]int
}

// Add an instruction to the list
func (lr *LabelResolver) Add(instr bpf.Instruction, gotoTrue, gotoFalse string) {
	lr.Instructions = append(lr.Instructions, LabeledInstruction{
		Instruction:    instr,
		SkipTrueLabel:  gotoTrue,
		SkipFalseLabel: gotoFalse,
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
		}
		finalInstructions[i] = instr
	}
	return finalInstructions, nil
}

func GetBpfFilterPort(port int) ([]bpf.Instruction, error) {
	bpfInstructions := &LabelResolver{LabelMap: make(map[string]int)}

	// Read ethernet protocol type
	bpfInstructions.Add(bpf.LoadAbsolute{Off: 12, Size: 2}, "", "") // load eth.type (2 bytes at offset 12) and push-it in register A

	// IPv4, IPv6 ou GRE packet condition ?
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800}, "read_ipv4", "")              // If eth.type == IPv4, goto read_ipv4
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd}, "read_ipv6", "ignore_packet") // If eth.type == IPv6, goto read_ipv6

	// read IPv4 packet
	bpfInstructions.Label("read_ipv4")
	bpfInstructions.Add(bpf.LoadAbsolute{Off: 23, Size: 1}, "", "")                                   // Load ip.proto (1 byte at offset 23) and push-it in register A
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_ipv4_port", "")             // ip.proto == UDP ? goto read_port
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_ipv4_port", "")              // ip.proto == TCP ? goto read_port
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2f}, "accept_packet", "ignore_packet") // ip.proto == GRE, goto read_gre else ignore packet
	bpfInstructions.Label("read_ipv4_port")
	bpfInstructions.Add(bpf.LoadAbsolute{Off: 20, Size: 2}, "", "")                                           // load flags and fragment offset (2 bytes at offset 20)
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff}, "accept_packet", "")                  // Only look at the last 13 bits of the data saved in regiter A, 0x1fff == 0001 1111 1111 1111 (fragment offset)
	bpfInstructions.Add(bpf.LoadMemShift{Off: 14}, "", "")                                                    // Register X = ip header len * 4
	bpfInstructions.Add(bpf.LoadIndirect{Off: 14, Size: 2}, "", "")                                           // Load source port in tcp or udp (2 bytes at offset x+14)
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // source port equal to 53 ?
	bpfInstructions.Add(bpf.LoadIndirect{Off: 16, Size: 2}, "", "")                                           // Load destination port in tcp or udp  (2 bytes at offset x+16)
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // destination port equal to 53 ?

	// read IPv6 packet
	bpfInstructions.Label("read_ipv6")
	bpfInstructions.Add(bpf.LoadAbsolute{Off: 20, Size: 1}, "", "")                                   // Load ipv6.nxt (2 bytes at offset 12) and push-it in register A
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2c}, "accept_packet", "")              // fragment ?
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11}, "read_ipv6_port", "")             // ip.proto == UDP ?
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6}, "read_ipv6_port", "ignore_packet") // ip.proto == TCP ?
	bpfInstructions.Label("read_ipv6_port")
	bpfInstructions.Add(bpf.LoadAbsolute{Off: 54, Size: 2}, "", "")                                           // Load source port tcp or udp (2 bytes at offset 54)
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "")              // source port equal to 53 ?
	bpfInstructions.Add(bpf.LoadAbsolute{Off: 56, Size: 2}, "", "")                                           // Load destination port tcp or udp (2 bytes at offset 56)
	bpfInstructions.Add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)}, "accept_packet", "ignore_packet") // destination port equal to 53 ?

	// Keep the packet and send up to 65k of the packet to userspace
	bpfInstructions.Label("accept_packet")
	bpfInstructions.Add(bpf.RetConstant{Val: 0xFFFF}, "", "")

	// Ignore packet
	bpfInstructions.Label("ignore_packet")
	bpfInstructions.Add(bpf.RetConstant{Val: 0}, "", "")

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
