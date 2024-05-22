package netutils

import (
	"net"
	"reflect"
	"testing"
)

func TestParseCIDRMask(t *testing.T) {
	tests := []struct {
		mask      string
		expected  net.IPMask
		expectErr bool
	}{
		// valid IPv4
		{"192.168.0.0/24", net.CIDRMask(24, 32), false},
		{"10.0.0.0/8", net.CIDRMask(8, 32), false},
		// valid IPv6
		{"2001:db8::/32", net.CIDRMask(32, 128), false},
		{"fe80::/10", net.CIDRMask(10, 128), false},
		// invalid cases
		{"192.168.0.0", nil, true},
		{"192.168.0.0/abc", nil, true},
		{"192.168.0.0/-1", nil, true},
		{"2001:db8::", nil, true},
		{"2001:db8::/xyz", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.mask, func(t *testing.T) {
			result, err := ParseCIDRMask(tt.mask)
			if (err != nil) != tt.expectErr {
				t.Errorf("unexpected error status: got %v, want %v, error: %v", (err != nil), tt.expectErr, err)
			}
			if !tt.expectErr && !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("unexpected result: got %v, want %v", result, tt.expected)
			}
		})
	}
}
