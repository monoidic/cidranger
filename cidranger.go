/*
Package cidranger provides utility to store CIDR blocks and perform ip
inclusion tests against it.

To create a new instance of the path-compressed trie:

	ranger := NewPCTrieRanger[someType]()

To insert or remove an entry of the type specified at ranger creation:

	var entry someType = genValue()
	network := netip.MustParsePrefix("192.168.0.0/24")
	ranger.Insert(network, entry)
	ranger.Remove(network)

To test whether an IP is contained in the constructed networks ranger:

	// returns bool, error
	containsBool, err := ranger.Contains(netip.MustParseAddr("192.168.0.1"))

To get a list of CIDR blocks in constructed ranger that contains IP:

	// returns []RangerEntry, error
	entries, err := ranger.ContainingNetworks(netip.MustParseAddr("192.168.0.1"))

To get a list of all IPv4/IPv6 rangers respectively:

	// returns []RangerEntry, error
	entries, err := ranger.CoveredNetworks(AllIPv4)
	entries, err := ranger.CoveredNetworks(AllIPv6)
*/
package cidranger

import (
	"fmt"
	"iter"
	"net/netip"
)

// ErrInvalidNetworkInput is returned upon invalid network input.
var ErrInvalidNetworkInput = fmt.Errorf("invalid network input")

// ErrInvalidNetworkNumberInput is returned upon invalid network input.
var ErrInvalidNetworkNumberInput = fmt.Errorf("invalid network number input")

// AllIPv4 is a IPv4 prefix that contains all networks
var AllIPv4 = netip.MustParsePrefix("0.0.0.0/0")

// AllIPv6 is a IPv6 prefix that contains all networks
var AllIPv6 = netip.MustParsePrefix("::/0")

// RangerEntry is an entry in Ranger when multiple values
// and their associated networks are returned
type RangerEntry[T any] struct {
	Network netip.Prefix
	Value   T
}

// Ranger is an interface for cidr block containment lookups.
type Ranger[T any] interface {
	Insert(net netip.Prefix, entry T) error
	Remove(network netip.Prefix) (T, bool, error)
	Contains(ip netip.Addr) (bool, error)
	ContainingNetworks(ip netip.Addr) ([]RangerEntry[T], error)
	ContainingNetworksIter(ip netip.Addr) iter.Seq[RangerEntry[T]]
	CoveredNetworks(network netip.Prefix) ([]RangerEntry[T], error)
	CoveredNetworksIter(network netip.Prefix) iter.Seq[RangerEntry[T]]
	CoveringNetworks(network netip.Prefix) ([]RangerEntry[T], error)
	CoveringNetworksIter(network netip.Prefix) iter.Seq[RangerEntry[T]]
	Adjacent(network netip.Prefix) (RangerEntry[T], bool, error)
	Len() int
}

// NewPCTrieRanger returns a Ranger that supports both IPv4 and IPv6
// using the path compressed trie implemention.
func NewPCTrieRanger[T any]() Ranger[T] {
	return newVersionedRanger[T](newPrefixTree)
}
