# go-netutils

Network utilities in Golang
- TCP assembly stream for dns packets
- Generic IP defrag function
- Generate BPF filter: (ip4 || ip6) && (tcp || udp) && port == int
- Get EBPF program to inject in kernel (XDP DNS filter)
- Easy config for TLS

## Generate eBPF bytecode

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