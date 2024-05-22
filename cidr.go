package netutils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func parseCIDRMask(mask string) (net.IPMask, error) {
	parts := strings.Split(mask, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid mask format, expected /integer: %s", mask)
	}

	ones, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid /%s cidr", mask)
	}
	if ones < 0 {
		return nil, fmt.Errorf("invalid /%s cidr", mask)
	}

	if strings.Contains(parts[0], ":") {
		ipv6Mask := net.CIDRMask(ones, 128)
		return ipv6Mask, nil
	}

	ipv4Mask := net.CIDRMask(ones, 32)
	return ipv4Mask, nil
}
