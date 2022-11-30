package cidranger

import (
	"net/netip"

	rnet "github.com/yl2chen/cidranger/net"
)

// bruteRanger is a brute force implementation of Ranger.  Insertion and
// deletion of networks is performed on an internal storage in the form of
// map[string]net.IPNet (constant time operations).  However, inclusion tests are
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
func newBruteRanger[T any]() iface[T] {
	return &bruteRanger[T]{
		ipV4Entries: make(map[netip.Prefix]T),
		ipV6Entries: make(map[netip.Prefix]T),
	}
}

// Insert inserts a RangerEntry into ranger.
func (b *bruteRanger[T]) Insert(prefix netip.Prefix, value T) error {
	if _, found := b.ipV4Entries[prefix]; !found {
		entries, err := b.getEntriesByVersion(prefix.Addr())
		if err != nil {
			return err
		}
		entries[prefix] = value
	}
	return nil
}

// Remove removes a value identified by given network from ranger.
func (b *bruteRanger[T]) Remove(prefix netip.Prefix) (T, bool, error) {
	networks, err := b.getEntriesByVersion(prefix.Addr())
	if err != nil {
		var zero T
		return zero, false, err
	}
	value, found := networks[prefix]
	delete(networks, prefix)
	return value, found, nil
}

// Contains returns bool indicating whether given ip is contained by any
// network in ranger.
func (b *bruteRanger[T]) Contains(ip netip.Addr) (bool, error) {
	entries, err := b.getEntriesByVersion(ip)
	if err != nil {
		return false, err
	}
	for prefix := range entries {
		if prefix.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// ContainingNetworks returns all values that given ip is contained in.
func (b *bruteRanger[T]) ContainingNetworks(ip netip.Addr) ([]T, error) {
	entries, err := b.getEntriesByVersion(ip)
	if err != nil {
		return nil, err
	}
	var values []T
	for prefix, value := range entries {
		if prefix.Contains(ip) {
			values = append(values, value)
		}
	}
	return values, nil
}

// CoveredNetworks returns the list of values the given ipnet
// covers.  That is, the networks that are completely subsumed by the
// specified network.
func (b *bruteRanger[T]) CoveredNetworks(prefix netip.Prefix) ([]T, error) {
	entries, err := b.getEntriesByVersion(prefix.Addr())
	if err != nil {
		return nil, err
	}
	var values []T
	testNetwork := rnet.NewNetwork(prefix)
	for entryPrefix, value := range entries {
		entryNetwork := rnet.NewNetwork(entryPrefix)
		if testNetwork.Covers(entryNetwork) {
			values = append(values, value)
		}
	}
	return values, nil
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
