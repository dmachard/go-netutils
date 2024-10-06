package netutils

import (
	"testing"

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
