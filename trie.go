package cidranger

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	rnet "github.com/monoidic/cidranger/v2/net"
)

// prefixTrie is a path-compressed (PC) trie implementation of the
// ranger interface inspired by this blog post:
// https://vincent.bernat.im/en/blog/2017-ipv4-route-lookup-linux
//
// CIDR blocks are stored using a prefix tree structure where each node has its
// parent as prefix, and the path from the root node represents current CIDR
// block.
//
// For IPv4, the trie structure guarantees max depth of 32 as IPv4 addresses are
// 32 bits long and each bit represents a prefix tree starting at that bit. This
// property also guarantees constant lookup time in Big-O notation.
//
// Path compression compresses a string of node with only 1 child into a single
// node, decrease the amount of lookups necessary during containment tests.
//
// Level compression dictates the amount of direct children of a node by
// allowing it to handle multiple bits in the path.  The heuristic (based on
// children population) to decide when the compression and decompression happens
// is outlined in the prior linked blog, and will be experimented with in more
// depth in this project in the future.
//
// Note: Can not insert both IPv4 and IPv6 network addresses into the same
// prefix trie, use versionedRanger wrapper instead.
//
// TODO: Implement level-compressed component of the LPC trie.
type prefixTrie[T any] struct {
	parent   *prefixTrie[T]
	children [2]*prefixTrie[T]
	network  rnet.Network

	numBitsSkipped int
	numBitsHandled uint
	size           int // This is only maintained in the root trie.

	entry    RangerEntry[T]
	entrySet bool
}

// newPrefixTree creates a new prefixTrie.
func newPrefixTree[T any](version rnet.IPVersion) Ranger[T] {
	rootStr := "0.0.0.0/0"
	if version == rnet.IPv6 {
		rootStr = "0::0/0"
	}
	rootNet := netip.MustParsePrefix(rootStr)
	return &prefixTrie[T]{
		numBitsSkipped: 0,
		numBitsHandled: 1,
		network:        rnet.NewNetwork(rootNet),
	}
}

func newPathprefixTrie[T any](network rnet.Network, numBitsSkipped int) *prefixTrie[T] {
	return &prefixTrie[T]{
		numBitsSkipped: numBitsSkipped,
		numBitsHandled: 1,
		network:        network.Masked(numBitsSkipped),
	}
}

func newEntryTrie[T any](network rnet.Network, entry RangerEntry[T]) *prefixTrie[T] {
	ones := network.IPNet.Bits()
	leaf := newPathprefixTrie[T](network, ones)
	leaf.entry = entry
	leaf.entrySet = true
	return leaf
}

// Insert inserts a RangerEntry into prefix trie.
func (p *prefixTrie[T]) Insert(net netip.Prefix, entry T) error {
	sizeIncreased, err := p.insert(rnet.NewNetwork(net.Masked()), RangerEntry[T]{Network: net.Masked(), Value: entry})
	if sizeIncreased {
		p.size++
	}
	return err
}

// Remove removes RangerEntry identified by given network from trie.
func (p *prefixTrie[T]) Remove(network netip.Prefix) (T, bool, error) {
	entry, removed, err := p.remove(rnet.NewNetwork(network.Masked()))
	if removed {
		p.size--
	}
	return entry.Value, removed, err
}

// Contains returns boolean indicating whether given ip is contained in any
// of the inserted networks.
func (p *prefixTrie[T]) Contains(ip netip.Addr) (bool, error) {
	nn := rnet.NewNetworkNumber(ip)
	if nn == nil {
		return false, ErrInvalidNetworkNumberInput
	}
	return p.contains(nn)
}

// ContainingNetworks returns the list of RangerEntry(s) the given ip is
// contained in in ascending prefix order.
func (p *prefixTrie[T]) ContainingNetworks(ip netip.Addr) ([]RangerEntry[T], error) {
	nn := rnet.NewNetworkNumber(ip)
	if nn == nil {
		return nil, ErrInvalidNetworkNumberInput
	}
	return p.containingNetworks(nn)
}

// CoveredNetworks returns the list of RangerEntry(s) the given ipnet
// covers.  That is, the networks that are completely subsumed by the
// specified network.
func (p *prefixTrie[T]) CoveredNetworks(network netip.Prefix) ([]RangerEntry[T], error) {
	net := rnet.NewNetwork(network)
	return p.coveredNetworks(net)
}

// Covering returns the list of RangerEntry(s) the given ipnet
// is covered by. It's like ContainingNetworks() for ipnet.
func (p *prefixTrie[T]) CoveringNetworks(network netip.Prefix) ([]RangerEntry[T], error) {
	net := rnet.NewNetwork(network)
	return p.coveringNetworks(net)
}

// Len returns number of networks in ranger.
func (p *prefixTrie[T]) Len() int {
	return p.size
}

// String returns string representation of trie, mainly for visualization and
// debugging.
func (p *prefixTrie[T]) String() string {
	var children []string
	padding := strings.Repeat("| ", p.level()+1)
	for bits, child := range p.children {
		if child == nil {
			continue
		}
		childStr := fmt.Sprintf("\n%s%d--> %s", padding, bits, child.String())
		children = append(children, childStr)
	}
	return fmt.Sprintf("%s (target_pos:%d:has_entry:%t)%s", p.network,
		p.targetBitPosition(), p.hasEntry(), strings.Join(children, ""))
}

// Returns adjacent entries to givent entry, identified by given network. Returns nil if adjacent entry not exists.
// Adjacent networks are networks with only different lower bit in network address, e.g. 192.168.0.0/24 and 192.168.1.0/24
// That networks can be mergeg, e.g 192.168.0.0/24 + 192.168.1.0/24 = 192.168.0.0/23
func (p *prefixTrie[T]) Adjacent(network netip.Prefix) (entry RangerEntry[T], success bool, err error) {
	addr := network.Masked().Addr()
	adjacentNumber := rnet.NewNetworkNumber(addr)
	ones := network.Bits()
	var size int
	if addr.Is4() {
		size = 32
	} else if addr.Is6() {
		size = 128
	} else {
		return entry, false, errors.New("invalid subnet")
	}

	if ones == 0 {
		// It's a full network, e.g. 0.0.0.0/0, there is no adjacents
		return entry, false, nil
	}
	position := size - ones
	if err := adjacentNumber.FlipNthBit(uint(position)); err != nil {
		return entry, false, err
	}
	adjacentNet := rnet.NewNetwork(netip.PrefixFrom(adjacentNumber.ToIP(), ones))
	return p.adjacent(adjacentNet)
}

func (p *prefixTrie[T]) adjacent(network rnet.Network) (entry RangerEntry[T], success bool, err error) {
	if p.hasEntry() && p.network.Equal(network) {
		return p.entry, true, nil
	}
	if p.targetBitPosition() < 0 {
		return entry, false, nil
	}
	bit, err := p.targetBitFromIP(network.Number)
	if err != nil {
		return entry, false, err
	}
	child := p.children[bit]
	if child != nil {
		return child.adjacent(network)
	}
	return entry, false, nil
}

func (p *prefixTrie[T]) contains(number rnet.NetworkNumber) (bool, error) {
	if !p.network.Contains(number) {
		return false, nil
	}
	if p.hasEntry() {
		return true, nil
	}
	if p.targetBitPosition() < 0 {
		return false, nil
	}
	bit, err := p.targetBitFromIP(number)
	if err != nil {
		return false, err
	}
	child := p.children[bit]
	if child != nil {
		return child.contains(number)
	}
	return false, nil
}

func (p *prefixTrie[T]) containingNetworks(number rnet.NetworkNumber) ([]RangerEntry[T], error) {
	var results []RangerEntry[T]
	if !p.network.Contains(number) {
		return results, nil
	}
	if p.hasEntry() {
		results = []RangerEntry[T]{p.entry}
	}
	if p.targetBitPosition() < 0 {
		return results, nil
	}
	bit, err := p.targetBitFromIP(number)
	if err != nil {
		return nil, err
	}
	child := p.children[bit]
	if child != nil {
		ranges, err := child.containingNetworks(number)
		if err != nil {
			return nil, err
		}
		if len(ranges) > 0 {
			if len(results) > 0 {
				results = append(results, ranges...)
			} else {
				results = ranges
			}
		}
	}
	return results, nil
}

func (p *prefixTrie[T]) coveredNetworks(network rnet.Network) ([]RangerEntry[T], error) {
	var results []RangerEntry[T]
	if network.Covers(p.network) {
		for entry := range p.walkDepth() {
			results = append(results, entry)
		}
	} else if p.targetBitPosition() >= 0 {
		bit, err := p.targetBitFromIP(network.Number)
		if err != nil {
			return results, err
		}
		child := p.children[bit]
		if child != nil {
			return child.coveredNetworks(network)
		}
	}
	return results, nil
}

func (p *prefixTrie[T]) coveringNetworks(network rnet.Network) ([]RangerEntry[T], error) {
	var results []RangerEntry[T]
	if !p.network.Covers(network) {
		return results, nil
	}
	if p.hasEntry() {
		results = []RangerEntry[T]{p.entry}
	}
	if p.targetBitPosition() < 0 {
		return results, nil
	}
	bit, err := p.targetBitFromIP(network.Number)
	if err != nil {
		return nil, err
	}
	child := p.children[bit]
	if child != nil {
		ranges, err := child.coveringNetworks(network)
		if err != nil {
			return nil, err
		}
		if len(ranges) > 0 {
			if len(results) > 0 {
				results = append(results, ranges...)
			} else {
				results = ranges
			}
		}
	}
	return results, nil
}

func (p *prefixTrie[T]) insert(network rnet.Network, entry RangerEntry[T]) (bool, error) {
	if p.network.Equal(network) {
		sizeIncreased := !p.entrySet
		p.entry = entry
		p.entrySet = true
		return sizeIncreased, nil
	}

	bit, err := p.targetBitFromIP(network.Number)
	if err != nil {
		return false, err
	}
	existingChild := p.children[bit]

	// No existing child, insert new leaf trie.
	if existingChild == nil {
		p.appendTrie(bit, newEntryTrie(network, entry))
		return true, nil
	}

	// Check whether it is necessary to insert additional path prefix between current trie and existing child,
	// in the case that inserted network diverges on its path to existing child.
	lcb, err := network.LeastCommonBitPosition(existingChild.network)
	if err != nil {
		return false, err
	}
	divergingBitPos := lcb - 1
	if divergingBitPos > existingChild.targetBitPosition() {
		pathPrefix := newPathprefixTrie[T](network, p.totalNumberOfBits()-lcb)
		err := p.insertPrefix(bit, pathPrefix, existingChild)
		if err != nil {
			return false, err
		}
		// Update new child
		existingChild = pathPrefix
	}
	return existingChild.insert(network, entry)
}

func (p *prefixTrie[T]) appendTrie(bit byte, prefix *prefixTrie[T]) {
	p.children[bit] = prefix
	prefix.parent = p
}

func (p *prefixTrie[T]) insertPrefix(bit byte, pathPrefix, child *prefixTrie[T]) error {
	// Set parent/child relationship between current trie and inserted pathPrefix
	p.children[bit] = pathPrefix
	pathPrefix.parent = p

	// Set parent/child relationship between inserted pathPrefix and original child
	pathPrefixBit, err := pathPrefix.targetBitFromIP(child.network.Number)
	if err != nil {
		return err
	}
	pathPrefix.children[pathPrefixBit] = child
	child.parent = pathPrefix
	return nil
}

func (p *prefixTrie[T]) remove(network rnet.Network) (RangerEntry[T], bool, error) {
	var empty RangerEntry[T]
	if p.hasEntry() && p.network.Equal(network) {
		entry := p.entry
		p.entry = empty
		p.entrySet = false

		err := p.compressPathIfPossible()
		if err != nil {
			return empty, false, err
		}
		return entry, true, nil
	}
	if p.targetBitPosition() < 0 {
		return empty, false, nil
	}
	bit, err := p.targetBitFromIP(network.Number)
	if err != nil {
		return empty, false, err
	}
	child := p.children[bit]
	if child != nil {
		return child.remove(network)
	}
	return empty, false, nil
}

func (p *prefixTrie[T]) qualifiesForPathCompression() bool {
	// Current prefix trie can be path compressed if it meets all following.
	//		1. records no CIDR entry
	//		2. has single or no child
	//		3. is not root trie
	return !p.hasEntry() && p.childrenCount() <= 1 && p.parent != nil
}

func (p *prefixTrie[T]) compressPathIfPossible() error {
	if !p.qualifiesForPathCompression() {
		// Does not qualify to be compressed
		return nil
	}

	// Find lone child.
	var loneChild *prefixTrie[T]
	for _, child := range p.children {
		if child != nil {
			loneChild = child
			break
		}
	}

	// Find root of currnt single child lineage.
	parent := p.parent
	for ; parent.qualifiesForPathCompression(); parent = parent.parent {
	}
	parentBit, err := parent.targetBitFromIP(p.network.Number)
	if err != nil {
		return err
	}
	parent.children[parentBit] = loneChild

	// Attempts to furthur apply path compression at current lineage parent, in case current lineage
	// compressed into parent.
	return parent.compressPathIfPossible()
}

func (p *prefixTrie[T]) childrenCount() int {
	count := 0
	for _, child := range p.children {
		if child != nil {
			count++
		}
	}
	return count
}

func (p *prefixTrie[T]) totalNumberOfBits() int {
	return rnet.BitsPerUint32 * len(p.network.Number)
}

func (p *prefixTrie[T]) targetBitPosition() int {
	return p.totalNumberOfBits() - p.numBitsSkipped - 1
}

func (p *prefixTrie[T]) targetBitFromIP(n rnet.NetworkNumber) (byte, error) {
	// This is a safe uint boxing of int since we should never attempt to get
	// target bit at a negative position.
	return n.Bit(uint(p.targetBitPosition()))
}

func (p *prefixTrie[T]) hasEntry() bool {
	return p.entrySet
}

func (p *prefixTrie[T]) level() int {
	if p.parent == nil {
		return 0
	}
	return p.parent.level() + 1
}

// walkDepth walks the trie in depth order, for unit testing.
// TODO also works pretty well as a iter.Seq[RangerEntry[T]]
func (p *prefixTrie[T]) walkDepth() <-chan RangerEntry[T] {
	entries := make(chan RangerEntry[T])
	go func() {
		if p.hasEntry() {
			entries <- p.entry
		}

		for _, trie := range p.children {
			if trie == nil {
				continue
			}

			for entry := range trie.walkDepth() {
				entries <- entry
			}
		}
		close(entries)
	}()
	return entries
}
