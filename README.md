# go-netutils

Network utilities in Golang
- TCP assembly stream for dns packets
- IP defrag
- BPF filter
- EBPF

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