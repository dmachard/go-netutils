# IPDefragmenter keeps incomplete fragment flows forever, so memory grows until OOM

> [!WARNING]
> ## Clanker generated
> An AI coding agent wrote this report. Check each claim against the code and the tests on this branch before you rely on it.

## Summary

`IPDefragmenter` removes a fragment flow in two cases only: the flow completes, or it reaches the fragment list limit. Nothing calls `DiscardOlderThan`, and nothing limits the memory that incomplete flows hold. In live capture, many flows can never complete, so the `ipFlows` map grows until the process runs out of memory.

## Versions

- go-netutils v1.9.1, v1.9.2, and `main` at [c277573][main].
- DNS-collector v3.1.0 with the `afpacket-sniffer` collector and `enable-defrag-ipv4` on.

## Root cause

- `DefragIP` adds a `*fragments` entry to `d.ipFlows` for each new flow ([`ipdefrag.go` L281-L306][defrag]). It deletes the entry only on completion or at the list limit.
- `DiscardOlderThan` exists ([L378-L389][discard]), but nothing in go-netutils or DNS-collector calls it.
- The BPF filter accepts every non-first IPv4 fragment before the port check, because those fragments have no UDP header ([`bpf.go` L130-L131][bpf]). The first fragment of a non-DNS datagram does have the UDP header, and the filter drops it on the port check. So every fragmented non-DNS datagram that reaches the interface leaves a flow that can never complete.
- A DNS datagram with a lost fragment also stays forever.

## Impact we saw

We run DNS-collector on every host, under a systemd memory limit. On the hosts that receive heavy fragmented non-DNS UDP traffic:

- RSS climbs from about 60 MiB to the 512 MiB limit in about 2.5 hours, and the process is killed. Then the cycle starts again.
- The DNS rate stays at about 0.3 messages per second, and the LRU caches stay at about 14 entries, during the whole climb. So the growth is not from DNS traffic or the caches.
- The goroutine count stays flat, so it is not a goroutine leak.

A local reproduction showed `IPDefragmenter.DefragIP` at the top of the `inuse_space` heap profile.

## Reproduction

Three tests on the branch fail on `main`:

```
TestIpDefrag_IPv4IncompleteFlowsExpire: 1001 incomplete flows still tracked 10 minutes later, want at most 1
TestIpDefrag_IPv4IncompleteFlowsAreBounded: defragmenter holds 28680000 bytes of incomplete flows, want at most 8388608
TestIpDefrag_IPv4FutureTimestampDoesNotStopExpiry: 1001 flows tracked, want at most the last 30s of flows
```

A heap check with 200k junk non-first fragments over 2000 seconds of capture time, with a fragmented DNS query every 1000 fragments:

| | Heap growth | DNS queries reassembled |
|---|---|---|
| `main` | 461 MiB | 200 of 200 |
| fix | 4 MiB | 200 of 200 |

The fix keeps the heap flat and still reassembles every DNS query.

## Proposed fix

`DefragIP` keeps the flows in least recently seen order, and it does three things:

- It removes a flow that got no fragment for `IPFragmentTimeout` (30s). The clock is the capture timestamp, not the wall clock, so a pcap replay behaves the same as a live capture. A flow more than 30s in the future also expires, so one bad timestamp or a clock step back cannot stop expiry.
- Above `IPFragmentMemoryLimit` (4 MiB) of stored fragments, it removes the oldest flows. The oldest flows are almost always the ones that can never complete. A new DNS flow usually completes within milliseconds.
- It removes a flow that failed to build, because that flow can never complete.

The two defaults are the same as the Linux `ipfrag_time` and `ipfrag_high_thresh` sysctls. Each fragment costs its captured bytes plus a measured 1 KB of heap overhead. An IPv6 fragment costs its bytes twice, because `NetDecoder.decodeIPv6Fragment` decodes into a second packet that copies the data.

`DefragIP` now holds the lock for the whole call, so `DiscardOlderThan` is safe to call from another goroutine. The exported API does not change. The change adds the two exported constants.

Cost: a reassembled DNS fragment pair takes about 70 ns more (1013 to 1083 ns, with 1000 incomplete flows tracked).

## Open questions for the maintainer

- Do you want the timeout and the memory limit as options on `IPDefragmenter`, or as DNS-collector config?
- A counter for evicted flows can show the real DNS flows that the memory limit drops. Do you want that in this PR or in a follow-up?

## Related branches

The three fixes are on separate branches of [anyasabo/go-netutils](https://github.com/anyasabo/go-netutils). Each branch starts from `main` at c277573, has a failing test commit before the fix, and merges cleanly with the other two in any order.

| Branch | Report |
|---|---|
| [fix/ipdefrag-freeze](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-freeze) | `issue-reports/1-defragger-stops-on-bad-fragment.md` |
| [fix/ipdefrag-flow-leak](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-flow-leak) | `issue-reports/2-incomplete-fragment-flows-leak.md` |
| [fix/ipdefrag-overlap-panic](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-overlap-panic) | `issue-reports/3-overlap-fragment-panic.md` |

Merge the freeze fix first. The leak fix adds a "memory limit reached" error, and without the freeze fix `IPDefragger` stops on that error, as it does today on the list-limit error. [fix/ipdefrag-leak-and-freeze](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-leak-and-freeze) has all three fixes together.

[main]: https://github.com/dmachard/go-netutils/tree/c2775736c0f3890412245d6f88019da96a893715
[defrag]: https://github.com/dmachard/go-netutils/blob/c2775736c0f3890412245d6f88019da96a893715/ipdefrag.go#L281-L306
[discard]: https://github.com/dmachard/go-netutils/blob/c2775736c0f3890412245d6f88019da96a893715/ipdefrag.go#L378-L389
[bpf]: https://github.com/dmachard/go-netutils/blob/c2775736c0f3890412245d6f88019da96a893715/bpf.go#L130-L131
