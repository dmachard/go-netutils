<img src="https://img.shields.io/badge/go%20version-min%201.21-green" alt="Go version"/>

# go-netutils

Network utilities in Golang
- TCP assembly stream for dns packets
- Generic IP defrag function
- Generate BPF filter: (ip4 || ip6) && (tcp || udp) && port == int
- Get EBPF program to inject in kernel (XDP DNS filter)
- Easy config for TLS
- String IPv4/v6 CIDR parser to net.IPMask
- Minimal network decoder for gopacket

## Build eBPF bytecode

Install prerequisites

```bash
sudo apt install llvm clang
sudo apt-get install gcc-multilib
```

Update `libpbf` library and generate `vmlinux.h`

```bash
cd ebpf/headers
./update.sh
```

Compiles a C source file into eBPF bytecode

```bash
cd xdp/
go generate .
```

## Running tests

```bash
$ go test -cover -v
```

## Examples
### String CIDR parser

```go
import (
	"github.com/dmachard/go-netutils"
)

v4Mask, err = netutils.ParseCIDRMask("10.0.0.0/8")
if err != nil {
   fmt.Println(err)
}
// v4Mask == net.CIDRMask(8, 32)
```

### Generate BPF filter

```go
import (
	"github.com/dmachard/go-netutils"
)


fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, netutils.Htons(syscall.ETH_P_ALL))
if err != nil {
   fmt.Println(err)
}

filter := GetBpfFilterPort(53)
err = netutils.ApplyBpfFilter(filter, fd)
if err != nil {
   fmt.Println(err)
}
```

### TLS client config


```go
import (
	"github.com/dmachard/go-netutils"
)

tlsOptions := netutils.TLSOptions{
   InsecureSkipVerify: true,
   MinVersion:         "1.2",
   CAFile:             "",
   CertFile:           "",
   KeyFile:            "",
}

tlsConfig, err := netutils.TLSClientConfig(tlsOptions)
if err != nil {
   w.LogFatal("logger=kafka - tls config failed:", err)
}
```

### Minimal network layers decoders

```go
import (
	"github.com/dmachard/go-netutils"
)

netDecoder := &netutils.NetDecoder{}

// copy packet data from buffer
pkt := make([]byte, bufN)
copy(pkt, buf[:bufN])

// decode minimal layers
packet := gopacket.NewPacket(pkt, netDecoder, gopacket.NoCopy)
```