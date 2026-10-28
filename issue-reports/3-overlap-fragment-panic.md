# Overlapping fragments with IP options or a truncated capture make DefragIP panic

> [!WARNING]
> ## Clanker generated
> An AI coding agent wrote this report. Check each claim against the code and the tests on this branch before you rely on it.

## Summary

`fragments.insert` and `fragments.build` compute each fragment's data length as the IP total length minus a fixed 20 bytes. A fragment with IP options (IHL above 5), or a truncated capture, has less payload than that. When such a fragment overlaps an earlier one, `build` slices past the end of its payload and panics. The panic is in the `IPDefragger` goroutine, and nothing recovers it, so the whole process exits.

## Versions

- go-netutils v1.9.1, v1.9.2, and `main` at [c277573][main].
- DNS-collector v3.1.0 with the `afpacket-sniffer` collector and `enable-defrag-ipv4` on.

## Root cause

- `insert` takes the length as `inIP4.Length - 20` ([`ipdefrag.go` L47][insert]).
- `build` checks `startAt > fragLength-ipOffset` with the same fixed 20 bytes, and then takes `fragPayload[startAt:]` ([L130-L135][build]). With IP options, `fragPayload` is 4 or more bytes shorter than `fragLength-20`, so the check passes and the slice panics.
- With a truncated capture, gopacket keeps the claimed `Length` but `Payload` holds only the captured bytes. The result is the same.
- The overlap case also sets `currentOffset += fragOffset * 8`. The end of the fragment is `offset + length`, so the next fragments are checked against the wrong offset.
- The overrun check `fragOffset+ip4.Length > IPv4MaximumSize` sums in `uint16` ([L364][overrun]), so it wraps and never fires.

The BPF filter accepts every non-first IPv4 fragment ([`bpf.go` L130-L131][bpf]), and `NetDecoder` gives any payload of 8 or more bytes a UDP layer. So these fragments reach `DefragIP` in DNS-collector. Only the first fragment needs UDP port 53.

Side effect of the same fixed 20 bytes: a valid fragmented datagram with IP options never reassembles.

## Reproduction

On `main`, the tests on the branch fail:

```
TestIpDefrag_IPv4MalformedOverlapDoesNotPanic/IP_options_on_an_overlapping_fragment: DefragIP panicked: runtime error: slice bounds out of range [204:200]
TestIpDefrag_IPv4MalformedOverlapDoesNotPanic/truncated_overlapping_fragment: DefragIP panicked: runtime error: slice bounds out of range [8:5]
TestIpDefrag_IPv4FragmentsWithOptions: datagram with IP options not reassembled
```

The test code in `ipdefrag_overlap_test.go` builds both inputs.

## Proposed fix

- `insert` and `build` use the length of the decoded payload, so the slice cannot go past the end.
- `securityChecks` rejects a truncated fragment: gopacket marked it truncated, or its payload is shorter than `Length - IHL*4`.
- The overlap case sets the current offset to the end of the fragment.
- The IPv4 overrun check sums in `uint32`.

The branch also adds fuzz targets for IPv4 and IPv6 (`FuzzDefragIPv4`, `FuzzDefragIPv6`), with the two crash inputs as seeds. The seeds panic on `main`. On the fix, each target ran 15 million inputs with no failure.

## Not fixed here (for context)

- If the last fragment (MF clear) does not arrive last, the datagram never reassembles, because `insert` checks for completion only on that fragment.
- A legal last fragment with 1 to 7 bytes of data is rejected as "too small". RFC 791 requires 8-byte multiples only for fragments that are not the last.

## Related branches

The three fixes are on separate branches of [anyasabo/go-netutils](https://github.com/anyasabo/go-netutils). Each branch starts from `main` at c277573, has a failing test commit before the fix, and merges cleanly with the other two in any order.

| Branch | Report |
|---|---|
| [fix/ipdefrag-freeze](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-freeze) | `issue-reports/1-defragger-stops-on-bad-fragment.md` |
| [fix/ipdefrag-flow-leak](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-flow-leak) | `issue-reports/2-incomplete-fragment-flows-leak.md` |
| [fix/ipdefrag-overlap-panic](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-overlap-panic) | `issue-reports/3-overlap-fragment-panic.md` |

Merge the freeze fix first. The leak fix adds a "memory limit reached" error, and without the freeze fix `IPDefragger` stops on that error, as it does today on the list-limit error. [fix/ipdefrag-leak-and-freeze](https://github.com/anyasabo/go-netutils/tree/fix/ipdefrag-leak-and-freeze) has all three fixes together.

[main]: https://github.com/dmachard/go-netutils/tree/c2775736c0f3890412245d6f88019da96a893715
[insert]: https://github.com/dmachard/go-netutils/blob/c2775736c0f3890412245d6f88019da96a893715/ipdefrag.go#L47
[build]: https://github.com/dmachard/go-netutils/blob/c2775736c0f3890412245d6f88019da96a893715/ipdefrag.go#L130-L135
[overrun]: https://github.com/dmachard/go-netutils/blob/c2775736c0f3890412245d6f88019da96a893715/ipdefrag.go#L364
[bpf]: https://github.com/dmachard/go-netutils/blob/c2775736c0f3890412245d6f88019da96a893715/bpf.go#L130-L131
