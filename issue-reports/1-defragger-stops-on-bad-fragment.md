# IPDefragger stops for good after one rejected fragment, and DNS capture freezes

> [!WARNING]
> ## Clanker generated
> An AI coding agent wrote this report. Check each claim against the code and the tests on this branch before you rely on it.

## Summary

`IPDefragger` exits its loop on the first error from `DefragIP`. After that, nothing reads `ipInput`. The next fragment blocks the sender, so the AF_PACKET sniffer in DNS-collector stops capture on that interface until the process restarts. Nothing is logged.

## Versions

- go-netutils v1.9.1, v1.9.2, and `main` at [c277573][main].
- DNS-collector v3.1.0 with the `afpacket-sniffer` collector and `enable-defrag-ipv4` or `enable-defrag-ipv6` on.

## Root cause

[`packetproccesor.go` L91-L95][break]:

```go
for fragment := range ipInput {
    reassembled, err := defragger.DefragIP(fragment)
    if err != nil {
        break
    }
```

`DefragIP` returns an error for every fragment that `securityChecks` rejects ([L333-L370][checks]). It also returns an error at the fragment list limit. Any one of these ends the goroutine:

- an IPv4 fragment offset above `IPv4MaximumFragmentOffset` (8183)
- an IPv4 fragment with fewer than 8 bytes of data
- a fragment that makes the datagram larger than 65535 bytes
- a flow with more than `IPv4MaximumFragmentListLen` fragments.

The BPF filter from `GetBpfDnsFilterPort` accepts every non-first IPv4 fragment before the port check ([`bpf.go` L130-L131][bpf]). So a fragment of this kind does not need to be DNS traffic to reach the defragger.

In DNS-collector, the sniffer sends fragments on an unbuffered channel ([`sniffer_afpacket_linux.go` L117-L121][sniffer]). When the defragger goroutine is gone, that send blocks forever, and the read loop for the interface stops.

## Reproduction

A test on the branch sends one rejected fragment to `IPDefragger`, then a valid fragmented DNS query. It covers two cases, an offset that is too big and a fragment that is too small. Before the fix, the second send blocks:

```
--- FAIL: TestIPDefragger_ContinuesAfterRejectedFragment/offset_too_big
    packetprocessor_test.go: the defragger no longer reads its input
--- FAIL: TestIPDefragger_ContinuesAfterRejectedFragment/fragment_too_small
    packetprocessor_test.go: the defragger no longer reads its input
```

## Proposed fix

Replace `break` with `continue`, so that only the rejected fragment is dropped. The PR is a one-line change plus the test.

A later change can add a counter for rejected fragments, so that a user can see them.

## Related branches

The three fixes are on separate branches of [anyasabo/go-netutils](https://github.com/anyasabo/go-netutils). Each branch starts from `main` at c277573, has a failing test commit before the fix, and merges cleanly with the other two in any order.

| Branch | Report |
|---|---|
| [fix/ipdefrag-freeze](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-freeze) | `issue-reports/1-defragger-stops-on-bad-fragment.md` |
| [fix/ipdefrag-flow-leak](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-flow-leak) | `issue-reports/2-incomplete-fragment-flows-leak.md` |
| [fix/ipdefrag-overlap-panic](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-overlap-panic) | `issue-reports/3-overlap-fragment-panic.md` |

Merge the freeze fix first. The leak fix adds a "memory limit reached" error, and without the freeze fix `IPDefragger` stops on that error, as it does today on the list-limit error. [fix/ipdefrag-leak-and-freeze](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-leak-and-freeze) has all three fixes together.

[main]: https://github.com/dmachard/go-netutils/tree/c2775736c0f3890412245d6f88019da96a893715
[break]: https://github.com/dmachard/go-netutils/blob/c2775736c0f3890412245d6f88019da96a893715/packetproccesor.go#L91-L95
[checks]: https://github.com/dmachard/go-netutils/blob/c2775736c0f3890412245d6f88019da96a893715/ipdefrag.go#L333-L370
[bpf]: https://github.com/dmachard/go-netutils/blob/c2775736c0f3890412245d6f88019da96a893715/bpf.go#L130-L131
[sniffer]: https://github.com/dmachard/DNS-collector/blob/53e2a9e12626c1e5139d8fed87cde1f254a3bf62/workers/sniffer_afpacket_linux.go#L117-L121
