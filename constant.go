package netutils

import "crypto/tls"

const (
	ProtoInet  = "INET"
	ProtoInet6 = "INET6"
	ProtoIPv6  = "IPv6"
	ProtoIPv4  = "IPv4"

	ProtoUDP = "UDP"
	ProtoTCP = "TCP"

	SocketTCP  = "tcp"
	SocketUDP  = "udp"
	SocketUnix = "unix"
	SocketTLS  = "tcp+tls"
)

var (
	IPVersion = map[string]string{
		ProtoInet:  ProtoIPv4,
		ProtoInet6: ProtoIPv6,
	}

	IPToInet = map[string]string{
		ProtoIPv4: ProtoInet,
		ProtoIPv6: ProtoInet6,
	}
)

const (
	TLSV10 = "1.0"
	TLSV11 = "1.1"
	TLSV12 = "1.2"
	TLSV13 = "1.3"
)

var (
	TLSVersion = map[string]uint16{
		TLSV10: tls.VersionTLS10,
		TLSV11: tls.VersionTLS11,
		TLSV12: tls.VersionTLS12,
		TLSV13: tls.VersionTLS13,
	}
)
