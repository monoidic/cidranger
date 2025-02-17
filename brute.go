package cidranger

import (
	"iter"
	"log"
	"net/netip"

	rnet "github.com/monoidic/cidranger/v2/net"
)

// bruteRanger is a brute force implementation of Ranger.  Insertion and
// deletion of networks is performed on an internal storage in the form of
// map[netip.Prefix]T (constant time operations).  However, inclusion tests are
// always performed linearly at no guaranteed traversal order of recorded networks,
// so one can assume a worst case performance of O(N).  The performance can be
// boosted many ways, e.g. changing usage of net.IPNet.Contains() to using masked
// bits equality checking, but the main purpose of this implementation is for
// testing because the correctness of this implementation can be easily guaranteed,
// and used as the ground truth when running a wider range of 'random' tests on
// other more sophisticated implementations.
type bruteRanger[T any] struct {
	ipV4Entries map[netip.Prefix]T
	ipV6Entries map[netip.Prefix]T
}

// newBruteRanger returns a new Ranger.
func newBruteRanger[T any]() Ranger[T] {
	return &bruteRanger[T]{
		ipV4Entries: make(map[netip.Prefix]T),
		ipV6Entries: make(map[netip.Prefix]T),
	}
}

// Insert inserts an entry into ranger.
func (b *bruteRanger[T]) Insert(net netip.Prefix, entry T) error {
	if _, found := b.ipV4Entries[net]; found {
		return nil
	}
	entries, err := b.getEntriesByVersion(net.Addr())
	if err != nil {
		return err
	}
	entries[net] = entry
	return nil
}

// Remove removes an entry identified by given network from ranger.
func (b *bruteRanger[T]) Remove(network netip.Prefix) (entry T, removed bool, err error) {
	var empty T
	networks, err := b.getEntriesByVersion(network.Addr())
	if err != nil {
		return empty, false, err
	}
	if networkToDelete, found := networks[network]; found {
		delete(networks, network)
		return networkToDelete, true, nil
	}
	return empty, false, nil
}

// Contains returns bool indicating whether given ip is contained by any
// network in ranger.
func (b *bruteRanger[T]) Contains(ip netip.Addr) (bool, error) {
	entries, err := b.getEntriesByVersion(ip)
	if err != nil {
		return false, err
	}
	for net := range entries {
		if net.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// ContainingNetworks returns all RangerEntry(s) that contain the given ip.
func (b *bruteRanger[T]) ContainingNetworks(ip netip.Addr) ([]RangerEntry[T], error) {
	entries, err := b.getEntriesByVersion(ip)
	if err != nil {
		return nil, err
	}
	var results []RangerEntry[T]
	for net, entry := range entries {
		if net.Contains(ip) {
			results = append(results, RangerEntry[T]{Network: net, Value: entry})
		}
	}
	return results, nil
}

func (b *bruteRanger[T]) ContainingNetworksIter(ip netip.Addr) iter.Seq[RangerEntry[T]] {
	return func(yield func(RangerEntry[T]) bool) {
		entries := check1(b.getEntriesByVersion(ip))
		for net, entry := range entries {
			if net.Contains(ip) {
				if !yield(RangerEntry[T]{Network: net, Value: entry}) {
					return
				}
			}
		}
	}
}

// CoveredNetworks returns the list of RangerEntry(s) covered by
// the given ipnet.  That is, the networks that are completely subsumed by the
// specified network.
func (b *bruteRanger[T]) CoveredNetworks(network netip.Prefix) ([]RangerEntry[T], error) {
	entries, err := b.getEntriesByVersion(network.Addr())
	if err != nil {
		return nil, err
	}
	var results []RangerEntry[T]
	testNetwork := rnet.NewNetwork(network)
	for net, entry := range entries {
		entryNetwork := rnet.NewNetwork(net)
		if testNetwork.Covers(entryNetwork) {
			results = append(results, RangerEntry[T]{Network: net, Value: entry})
		}
	}
	return results, nil
}

func (b *bruteRanger[T]) CoveredNetworksIter(network netip.Prefix) iter.Seq[RangerEntry[T]] {
	return func(yield func(RangerEntry[T]) bool) {
		entries := check1(b.getEntriesByVersion(network.Addr()))

		testNetwork := rnet.NewNetwork(network)
		for net, entry := range entries {
			entryNetwork := rnet.NewNetwork(net)
			if testNetwork.Covers(entryNetwork) {
				if !yield(RangerEntry[T]{Network: net, Value: entry}) {
					return
				}
			}
		}
	}
}

// Covering returns the list of RangerEntry(s) the given ipnet
// is covered. It's like ContainingNetworks() for ipnet.
func (b *bruteRanger[T]) CoveringNetworks(network netip.Prefix) ([]RangerEntry[T], error) {
	entries, err := b.getEntriesByVersion(network.Addr())
	if err != nil {
		return nil, err
	}
	var results []RangerEntry[T]
	testNetwork := rnet.NewNetwork(network)
	for net, entry := range entries {
		entryNetwork := rnet.NewNetwork(net)
		if entryNetwork.Covers(testNetwork) {
			results = append(results, RangerEntry[T]{Network: net, Value: entry})
		}
	}
	return results, nil
}

// Covering returns the list of RangerEntry(s) the given ipnet
// is covered. It's like ContainingNetworks() for ipnet.
func (b *bruteRanger[T]) CoveringNetworksIter(network netip.Prefix) iter.Seq[RangerEntry[T]] {
	return func(yield func(RangerEntry[T]) bool) {
		entries := check1(b.getEntriesByVersion(network.Addr()))
		testNetwork := rnet.NewNetwork(network)
		for net, entry := range entries {
			entryNetwork := rnet.NewNetwork(net)
			if entryNetwork.Covers(testNetwork) {
				if !yield(RangerEntry[T]{Network: net, Value: entry}) {
					return
				}
			}
		}
	}
}

// Len returns number of networks in ranger.
func (b *bruteRanger[T]) Len() int {
	return len(b.ipV4Entries) + len(b.ipV6Entries)
}

func (b *bruteRanger[T]) getEntriesByVersion(ip netip.Addr) (map[netip.Prefix]T, error) {
	if ip.Is4() {
		return b.ipV4Entries, nil
	}
	if ip.Is6() {
		return b.ipV6Entries, nil
	}
	return nil, ErrInvalidNetworkInput
}

// Just to complete interface
func (p *bruteRanger[T]) Adjacent(network netip.Prefix) (entry RangerEntry[T], success bool, err error) {
	return
}

func check(err error) {
	if err != nil {
		log.Panicf("err: %s", err)
	}
}

func check1[T any](arg1 T, err error) T {
	check(err)
	return arg1
}
