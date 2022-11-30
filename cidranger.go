/*
Package cidranger provides utility to store CIDR blocks and perform ip
inclusion tests against it.

To create a new instance of the path-compressed trie:

			ranger := NewPCTrieRanger()

To insert or remove an entry (any object that satisfies the RangerEntry
interface):

			_, network, _ := net.ParseCIDR("192.168.0.0/24")
			ranger.Insert(NewBasicRangerEntry(*network))
			ranger.Remove(network)

If you desire for any value to be attached to the entry, simply
create custom struct that satisfies the RangerEntry interface:

			type RangerEntry interface {
				Network() net.IPNet
			}

To test whether an IP is contained in the constructed networks ranger:

			// returns bool, error
			containsBool, err := ranger.Contains(net.ParseIP("192.168.0.1"))

To get a list of CIDR blocks in constructed ranger that contains IP:

			// returns []RangerEntry, error
			entries, err := ranger.ContainingNetworks(net.ParseIP("192.168.0.1"))

To get a list of all IPv4/IPv6 rangers respectively:

			// returns []RangerEntry, error
			entries, err := ranger.CoveredNetworks(*AllIPv4)
			entries, err := ranger.CoveredNetworks(*AllIPv6)

*/
package cidranger

import (
	"fmt"
	"net/netip"

	rnet "github.com/yl2chen/cidranger/net"
)

// ErrInvalidNetworkInput is returned upon invalid network input.
var ErrInvalidNetworkInput = fmt.Errorf("invalid network input")

// ErrInvalidNetworkNumberInput is returned upon invalid network input.
var ErrInvalidNetworkNumberInput = fmt.Errorf("invalid network number input")

// AllIPv4 is a IPv4 CIDR that contains all networks
var AllIPv4 = parseCIDRUnsafe("0.0.0.0/0")

// AllIPv6 is a IPv6 CIDR that contains all networks
var AllIPv6 = parseCIDRUnsafe("0::0/0")

func parseCIDRUnsafe(s string) netip.Prefix {
	cidr, _ := netip.ParsePrefix(s)
	return cidr
}

// Entry is an insertable entry into a Ranger.
type Entry[T any] struct {
	Network netip.Prefix
	Value   T
}

// iface is an interface for cidr block containment lookups.
type iface[T any] interface {
	Insert(netip.Prefix, T) error
	Remove(netip.Prefix) (T, bool, error)
	Contains(netip.Addr) (bool, error)
	ContainingNetworks(netip.Addr) ([]T, error)
	CoveredNetworks(netip.Prefix) ([]T, error)
	Len() int
}

// New returns a versionedRanger that supports both IPv4 and IPv6
// using the path compressed trie implemention.
func New[T any]() iface[T] {
	fn := func(version rnet.IPVersion) iface[T] {
		return newPrefixTree[T](version)
	}

	return newVersionedRanger(fn)
}
