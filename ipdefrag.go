package netutils

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	IPv6MinimumFragmentSize    = 1280
	IPv6MaximumSize            = 65535
	IPv6MaximumFragmentOffset  = 8189
	IPv6MaximumFragmentListLen = 52

	IPv4MinimumFragmentSize    = 8     // Minimum size of a single fragment
	IPv4MaximumSize            = 65535 // Maximum size of a fragment (2^16)
	IPv4MaximumFragmentOffset  = 8183  // Maximum offset of a fragment
	IPv4MaximumFragmentListLen = 8192  // Back out if we get more than this many fragments

	// The Linux ipfrag_time and ipfrag_high_thresh defaults:
	// https://github.com/torvalds/linux/blob/v7.3/net/ipv4/ip_fragment.c#L671-L678
	IPFragmentTimeout     = 30 * time.Second // Drop a flow that got no fragment for this long
	IPFragmentMemoryLimit = 4 * 1024 * 1024  // Drop the least recently seen flows above this many bytes

	// fragmentOverhead is the measured heap cost of one stored fragment on top
	// of its data, so that tiny fragments can't exceed the memory limit.
	fragmentOverhead = 1024
)

type fragments struct {
	List     list.List
	Highest  uint16
	Current  uint16
	LastSeen time.Time

	key  ipFlow
	size int           // bytes charged to IPFragmentMemoryLimit
	elem *list.Element // position in IPDefragmenter.lru
}

// fragmentInfo returns the offset in bytes, the payload, and the more
// fragments flag of a fragment.
func fragmentInfo(p gopacket.Packet) (uint16, []byte, bool) {
	if frag6, ok := p.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment); ok {
		return frag6.FragmentOffset * 8, frag6.Payload, frag6.MoreFragments
	}
	ip4 := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	return ip4.FragOffset * 8, ip4.Payload, ip4.Flags&layers.IPv4MoreFragments > 0
}

// insert keeps the fragments sorted by offset. It ignores an exact duplicate
// and rejects any other overlap, as Linux and RFC 5722 do. So when Current
// reaches Highest, the fragments cover the datagram with no holes.
func (f *fragments) insert(in gopacket.Packet) (gopacket.Packet, error) {
	inFragOffset, inPayload, inFragMore := fragmentInfo(in)
	inFragLength := uint16(len(inPayload))
	inFragEnd := inFragOffset + inFragLength

	if inFragOffset >= f.Highest {
		f.List.PushBack(in)
	} else {
		for e := f.List.Front(); e != nil; e = e.Next() {
			fragOffset, payload, _ := fragmentInfo(e.Value.(gopacket.Packet))
			fragEnd := fragOffset + uint16(len(payload))

			if inFragOffset == fragOffset && inFragEnd == fragEnd {
				return nil, nil
			}
			if inFragOffset < fragEnd && fragOffset < inFragEnd {
				return nil, fmt.Errorf("defrag: overlapping fragment")
			}
			if inFragOffset < fragOffset {
				f.List.InsertBefore(in, e)
				break
			}
		}
	}

	if f.Highest < inFragEnd {
		f.Highest = inFragEnd
	}
	f.Current += inFragLength

	// Final Fragment ?
	if !inFragMore && f.Highest == f.Current {
		return f.build(in)
	}
	return nil, nil
}

func (f *fragments) build(in gopacket.Packet) (gopacket.Packet, error) {
	var final []byte

	for e := f.List.Front(); e != nil; e = e.Next() {
		offset, payload, _ := fragmentInfo(e.Value.(gopacket.Packet))
		if int(offset) != len(final) {
			return nil, fmt.Errorf("defrag: hole found")
		}
		final = append(final, payload...)
	}

	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ip4 := in.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		out := &layers.IPv4{
			Version:    ip4.Version,
			IHL:        ip4.IHL,
			TOS:        ip4.TOS,
			Length:     f.Highest,
			Id:         ip4.Id,
			Flags:      0,
			FragOffset: 0,
			TTL:        ip4.TTL,
			Protocol:   ip4.Protocol,
			Checksum:   0,
			SrcIP:      ip4.SrcIP,
			DstIP:      ip4.DstIP,
			Options:    ip4.Options,
			Padding:    ip4.Padding,
		}
		out.Payload = final

		buf := gopacket.NewSerializeBuffer()
		ops := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		ip4Payload, _ := buf.PrependBytes(len(final))
		copy(ip4Payload, final)
		out.SerializeTo(buf, ops)

		outPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
		outPacket.Metadata().CaptureLength = len(outPacket.Data())
		outPacket.Metadata().Length = len(outPacket.Data())
		outPacket.Metadata().Timestamp = in.Metadata().Timestamp

		// workaround to mark the packet as reassembled
		outPacket.Metadata().Truncated = true
		return outPacket, nil
	}

	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		ip6 := in.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		frag6 := in.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
		out := &layers.IPv6{
			Version:      ip6.Version,
			TrafficClass: ip6.TrafficClass,
			FlowLabel:    ip6.FlowLabel,
			Length:       f.Highest,
			NextHeader:   frag6.NextHeader,
			HopLimit:     ip6.HopLimit,
			SrcIP:        ip6.SrcIP,
			DstIP:        ip6.DstIP,
			HopByHop:     ip6.HopByHop,
		}
		out.Payload = final

		buf := gopacket.NewSerializeBuffer()
		ops := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		v6Payload, _ := buf.PrependBytes(len(final))
		copy(v6Payload, final)

		out.SerializeTo(buf, ops)
		outPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
		outPacket.Metadata().CaptureLength = len(outPacket.Data())
		outPacket.Metadata().Length = len(outPacket.Data())
		outPacket.Metadata().Timestamp = in.Metadata().Timestamp

		// workaround to mark the packet as reassembled
		outPacket.Metadata().Truncated = true

		return outPacket, nil
	}
	return nil, nil
}

type ipFlow struct {
	flow gopacket.Flow
	id   uint32
}

func newIPv4(packet gopacket.Packet) ipFlow {
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	return ipFlow{
		flow: ip4.NetworkFlow(),
		id:   uint32(ip4.Id),
	}
}

func newIPv6(packet gopacket.Packet) ipFlow {
	frag := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
	ip6 := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	return ipFlow{
		flow: ip6.NetworkFlow(),
		id:   frag.Identification,
	}
}

type IPDefragmenter struct {
	sync.RWMutex
	ipFlows map[ipFlow]*fragments
	// lru holds the flows from least to most recently seen.
	lru         list.List
	size        int
	memoryLimit int
}

func NewIPDefragmenter() *IPDefragmenter {
	return &IPDefragmenter{
		ipFlows:     make(map[ipFlow]*fragments),
		memoryLimit: IPFragmentMemoryLimit,
	}
}

func (d *IPDefragmenter) DefragIP(in gopacket.Packet) (gopacket.Packet, error) {
	// check if we need to defrag
	if st := d.dontDefrag(in); st {
		return in, nil
	}

	// perfom security checks
	if err := d.securityChecks(in); err != nil {
		return nil, err
	}

	// ok, got a fragment
	// have we already seen a flow between src/dst with that Id?
	var ipf ipFlow
	var fl *fragments
	var exist bool
	var maxFrag int

	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ipf = newIPv4(in)
		maxFrag = IPv4MaximumFragmentListLen
	}
	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		ipf = newIPv6(in)
		maxFrag = IPv6MaximumFragmentListLen
	}
	d.Lock()
	defer d.Unlock()

	// The capture time, so that a pcap replay expires flows like a live capture.
	now := in.Metadata().Timestamp
	d.expire(now)

	fl, exist = d.ipFlows[ipf]
	if !exist {
		fl = &fragments{key: ipf}
		fl.elem = d.lru.PushBack(fl)
		d.ipFlows[ipf] = fl
	} else {
		d.lru.MoveToBack(fl.elem)
	}
	fl.LastSeen = now

	// insert, and if final build it
	before := fl.List.Len()
	out, err2 := fl.insert(in)
	if fl.List.Len() > before {
		cost := len(in.Data()) + fragmentOverhead
		if in.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
			// NetDecoder.decodeIPv6Fragment keeps a second copy of the data.
			cost += len(in.Data())
		}
		fl.size += cost
		d.size += cost
	}

	// at last, if we hit the maximum frag list len
	// without any defrag success, we just drop everything and
	// raise an error
	if out == nil && fl.List.Len()+1 > maxFrag {
		d.remove(fl)
		return nil, fmt.Errorf("fragment List hits its maximum")
	}

	// if we got a packet, it's a new one, and he is defragmented
	// when defrag is done for a flow between two ip clean the list
	if out != nil {
		d.remove(fl)
		return out, nil
	}

	// a flow with an overlap or a hole can never complete
	if err2 != nil {
		d.remove(fl)
		return nil, err2
	}

	// Drop the oldest flows first. Flows that never complete collect at the
	// front, and a new flow at the back usually completes in milliseconds.
	for e := d.lru.Front(); e != nil && d.size > d.memoryLimit; e = d.lru.Front() {
		oldest := e.Value.(*fragments)
		d.remove(oldest)
		if oldest == fl {
			return nil, fmt.Errorf("fragment memory limit reached")
		}
	}
	return nil, nil
}

func (d *IPDefragmenter) dontDefrag(in gopacket.Packet) bool {
	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		// check if we need to defrag
		frag := in.Layer(layers.LayerTypeIPv6Fragment)
		if frag == nil {
			return true
		}
	}

	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ip4 := in.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		// don't defrag packet with DF flag
		if ip4.Flags&layers.IPv4DontFragment != 0 {
			return true
		}
		// don't defrag not fragmented ones
		if ip4.Flags&layers.IPv4MoreFragments == 0 && ip4.FragOffset == 0 {
			return true
		}
	}

	return false
}

func (d *IPDefragmenter) securityChecks(in gopacket.Packet) error {
	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		frag6 := in.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)

		// don't allow a fragment with less data than its header claims. Don't
		// use Metadata().Truncated: NetDecoder decodes UDP inside fragments,
		// and that sets it on every first fragment.
		ip6 := in.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if int(ip6.Length) != len(ip6.Payload) {
			return fmt.Errorf("fragment truncated (%d < %d)", len(ip6.Payload), ip6.Length)
		}

		// don't allow too big fragment offset
		if frag6.FragmentOffset > IPv6MaximumFragmentOffset {
			return fmt.Errorf("fragment offset too big (handcrafted? %d > %d)", frag6.FragmentOffset, IPv6MaximumFragmentOffset)
		}
		fragOffset := uint32(frag6.FragmentOffset * 8)

		// don't allow fragment that would oversize an IP packet
		if fragOffset+uint32(len(frag6.Payload)) > IPv6MaximumSize {
			return fmt.Errorf("fragment will overrun (handcrafted? %d > %d)", fragOffset+uint32(len(frag6.Payload)), IPv6MaximumFragmentOffset)
		}
	}
	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ip4 := in.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		fragSize := ip4.Length - uint16(ip4.IHL)*4

		// don't allow small fragments outside of specification
		if fragSize < IPv4MinimumFragmentSize {
			return fmt.Errorf("fragment too small(handcrafted? %d < %d)", fragSize, IPv4MinimumFragmentSize)
		}

		// don't allow too big fragment offset
		if ip4.FragOffset > IPv4MaximumFragmentOffset {
			return fmt.Errorf("fragment offset too big (handcrafted? %d > %d)", ip4.FragOffset, IPv4MaximumFragmentOffset)
		}
		if int(fragSize) != len(ip4.Payload) {
			return fmt.Errorf("fragment truncated (%d < %d)", len(ip4.Payload), fragSize)
		}

		// don't allow fragment that would oversize an IP packet, in uint32 so
		// that the sum can't wrap around
		fragOffset := uint32(ip4.FragOffset) * 8
		if fragOffset+uint32(ip4.Length) > IPv4MaximumSize {
			return fmt.Errorf("fragment will overrun (handcrafted? %d > %d)", fragOffset+uint32(ip4.Length), IPv4MaximumSize)
		}
	}

	return nil
}

// remove must be called with the lock held.
func (d *IPDefragmenter) remove(fl *fragments) {
	delete(d.ipFlows, fl.key)
	d.lru.Remove(fl.elem)
	d.size -= fl.size
}

// expire removes the flows last seen more than IPFragmentTimeout before or
// after now. It must be called with the lock held. It stops at the first
// recent flow in lru. A flow after now comes from a clock step back, and it
// would otherwise block expiry until the clock caught up.
func (d *IPDefragmenter) expire(now time.Time) {
	for e := d.lru.Front(); e != nil; e = d.lru.Front() {
		fl := e.Value.(*fragments)
		age := now.Sub(fl.LastSeen)
		if age <= IPFragmentTimeout && age >= -IPFragmentTimeout {
			return
		}
		d.remove(fl)
	}
}

func (d *IPDefragmenter) DiscardOlderThan(t time.Time) int {
	var nb int
	d.Lock()
	for _, fl := range d.ipFlows {
		if fl.LastSeen.Before(t) {
			nb++
			d.remove(fl)
		}
	}
	d.Unlock()
	return nb
}
