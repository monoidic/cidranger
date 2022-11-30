package cidranger

import (
	"fmt"
	"net/netip"
	"strings"

	rnet "github.com/yl2chen/cidranger/net"
)

// Trie is a path-compressed (PC) trie implementation of the
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
type Trie[T any] struct {
	parent   *Trie[T]
	children []*Trie[T]

	numBitsSkipped uint
	numBitsHandled uint

	size int // This is only maintained in the root trie.

	network  rnet.Network
	value    T
	hasValue bool
}

// newPrefixTree creates a new prefixTrie.
func newPrefixTree[T any](version rnet.IPVersion) *Trie[T] {
	rootStr := "0.0.0.0/0"
	if version == rnet.IPv6 {
		rootStr = "0::0/0"
	}

	rootNet := netip.MustParsePrefix(rootStr)

	return &Trie[T]{
		children:       make([]*Trie[T], 2),
		numBitsSkipped: 0,
		numBitsHandled: 1,
		network:        rnet.NewNetwork(rootNet),
	}
}

func newPathPrefixTrie[T any](network rnet.Network, numBitsSkipped uint) *Trie[T] {
	return &Trie[T]{
		children:       make([]*Trie[T], 2),
		numBitsSkipped: numBitsSkipped,
		numBitsHandled: 1,
		network:        network.Masked(int(numBitsSkipped)),
	}
}

func newValueTrie[T any](network rnet.Network, value T) *Trie[T] {
	ones := network.IPNet.Bits()
	leaf := newPathPrefixTrie[T](network, uint(ones))
	leaf.value = value

	return leaf
}

// Insert inserts a RangerEntry into prefix trie.
func (p *Trie[T]) Insert(prefix netip.Prefix, value T) error {
	sizeIncreased, err := p.insert(rnet.NewNetwork(prefix.Masked()), value)
	if sizeIncreased {
		p.size++
	}
	return err
}

// Remove removes the value identified by given network from trie.
func (p *Trie[T]) Remove(prefix netip.Prefix) (T, bool, error) {
	value, ok, err := p.remove(rnet.NewNetwork(prefix.Masked()))
	if ok {
		p.size--
	}
	return value, ok, err
}

// Contains returns boolean indicating whether given ip is contained in any
// of the inserted networks.
func (p *Trie[T]) Contains(ip netip.Addr) (bool, error) {
	nn := rnet.NewNetworkNumber(ip)
	if nn == nil {
		return false, ErrInvalidNetworkNumberInput
	}
	return p.contains(nn)
}

// ContainingNetworks returns the list of values the given ip is
// contained in, in ascending prefix order.
func (p *Trie[T]) ContainingNetworks(ip netip.Addr) ([]T, error) {
	nn := rnet.NewNetworkNumber(ip)
	if nn == nil {
		return nil, ErrInvalidNetworkNumberInput
	}

	return p.containingNetworks(nn, nil)
}

// CoveredNetworks returns the list of RangerEntry(s) the given ipnet
// covers.  That is, the networks that are completely subsumed by the
// specified network.
func (p *Trie[T]) CoveredNetworks(network netip.Prefix) ([]T, error) {
	net := rnet.NewNetwork(network)
	return p.coveredNetworks(net, nil)
}

// Len returns number of networks in ranger.
func (p *Trie[T]) Len() int {
	return p.size
}

// String returns string representation of trie, mainly for visualization and
// debugging.
func (p *Trie[T]) String() string {
	children := []string{}
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

func (p *Trie[T]) contains(number rnet.NetworkNumber) (bool, error) {
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

func (p *Trie[T]) containingNetworks(number rnet.NetworkNumber, values []T) ([]T, error) {
	if !p.network.Contains(number) {
		return values, nil
	}
	if p.hasEntry() {
		values = append(values, p.value)
	}
	if p.targetBitPosition() < 0 {
		return values, nil
	}
	bit, err := p.targetBitFromIP(number)
	if err != nil {
		return nil, err
	}
	child := p.children[bit]
	if child != nil {
		values, err = child.containingNetworks(number, values)
		if err != nil {
			return nil, err
		}
	}
	return values, nil
}

func (p *Trie[T]) coveredNetworks(network rnet.Network, values []T) ([]T, error) {
	if network.Covers(p.network) {
		for entry := range p.walkDepth() {
			values = append(values, entry)
		}
	} else if p.targetBitPosition() >= 0 {
		bit, err := p.targetBitFromIP(network.Number)
		if err != nil {
			return values, err
		}
		child := p.children[bit]
		if child != nil {
			return child.coveredNetworks(network, values)
		}
	}
	return values, nil
}

func (p *Trie[T]) insert(network rnet.Network, value T) (bool, error) {
	if p.network.Equal(network) {
		sizeIncreased := !p.hasValue
		p.value = value
		p.hasValue = true
		return sizeIncreased, nil
	}

	bit, err := p.targetBitFromIP(network.Number)
	if err != nil {
		return false, err
	}
	existingChild := p.children[bit]

	// No existing child, insert new leaf trie.
	if existingChild == nil {
		p.appendTrie(bit, newValueTrie(network, value))
		return true, nil
	}

	// Check whether it is necessary to insert additional path prefix between current trie and existing child,
	// in the case that inserted network diverges on its path to existing child.
	lcb, err := network.LeastCommonBitPosition(existingChild.network)
	if err != nil {
		return false, err
	}
	divergingBitPos := int(lcb) - 1
	if divergingBitPos > existingChild.targetBitPosition() {
		pathPrefix := newPathPrefixTrie[T](network, p.totalNumberOfBits()-lcb)
		err := p.insertPrefix(bit, pathPrefix, existingChild)
		if err != nil {
			return false, err
		}
		// Update new child
		existingChild = pathPrefix
	}
	return existingChild.insert(network, value)
}

func (p *Trie[T]) appendTrie(bit uint32, prefix *Trie[T]) {
	p.children[bit] = prefix
	prefix.parent = p
}

func (p *Trie[T]) insertPrefix(bit uint32, pathPrefix, child *Trie[T]) error {
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

func (p *Trie[T]) remove(network rnet.Network) (T, bool, error) {
	var zero T
	if p.hasEntry() && p.network.Equal(network) {
		value := p.value
		hasValue := p.hasValue

		p.value = zero
		p.hasValue = false

		err := p.compressPathIfPossible()
		if err != nil {
			return zero, false, err
		}
		return value, hasValue, err
	}
	if p.targetBitPosition() < 0 {
		return zero, false, nil
	}
	bit, err := p.targetBitFromIP(network.Number)
	if err != nil {
		return zero, false, err
	}
	child := p.children[bit]
	if child != nil {
		return child.remove(network)
	}
	return zero, false, nil
}

func (p *Trie[T]) qualifiesForPathCompression() bool {
	// Current prefix trie can be path compressed if it meets all following.
	//		1. records no CIDR entry
	//		2. has single or no child
	//		3. is not root trie
	return !p.hasEntry() && p.childrenCount() <= 1 && p.parent != nil
}

func (p *Trie[T]) compressPathIfPossible() error {
	if !p.qualifiesForPathCompression() {
		// Does not qualify to be compressed
		return nil
	}

	// Find lone child.
	var loneChild *Trie[T]
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

func (p *Trie[T]) childrenCount() int {
	count := 0
	for _, child := range p.children {
		if child != nil {
			count++
		}
	}
	return count
}

func (p *Trie[T]) totalNumberOfBits() uint {
	return rnet.BitsPerUint32 * uint(len(p.network.Number))
}

func (p *Trie[T]) targetBitPosition() int {
	return int(p.totalNumberOfBits()-p.numBitsSkipped) - 1
}

func (p *Trie[T]) targetBitFromIP(n rnet.NetworkNumber) (uint32, error) {
	// This is a safe uint boxing of int since we should never attempt to get
	// target bit at a negative position.
	return n.Bit(uint(p.targetBitPosition()))
}

func (p *Trie[T]) hasEntry() bool {
	return p.hasValue
}

func (p *Trie[T]) level() int {
	if p.parent == nil {
		return 0
	}
	return p.parent.level() + 1
}

// walkDepth walks the trie in depth order, for unit testing.
func (p *Trie[T]) walkDepth() <-chan T {
	entries := make(chan T)
	go func() {
		if p.hasEntry() {
			entries <- p.value
		}
		var childEntriesList []<-chan T
		for _, trie := range p.children {
			if trie == nil {
				continue
			}
			childEntriesList = append(childEntriesList, trie.walkDepth())
		}
		for _, childEntries := range childEntriesList {
			for entry := range childEntries {
				entries <- entry
			}
		}
		close(entries)
	}()
	return entries
}
