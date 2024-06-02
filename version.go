package cidranger

import (
	"net/netip"

	rnet "github.com/monoidic/cidranger/v2/net"
)

type rangerFactory[T any] func(rnet.IPVersion) Ranger[T]

type versionedRanger[T any] struct {
	ipV4Ranger Ranger[T]
	ipV6Ranger Ranger[T]
}

func newVersionedRanger[T any](factory rangerFactory[T]) Ranger[T] {
	return &versionedRanger[T]{
		ipV4Ranger: factory(rnet.IPv4),
		ipV6Ranger: factory(rnet.IPv6),
	}
}

func (v *versionedRanger[T]) Insert(net netip.Prefix, entry T) error {
	ranger, err := v.getRangerForIP(net.Addr())
	if err != nil {
		return err
	}
	return ranger.Insert(net, entry)
}

func (v *versionedRanger[T]) Remove(network netip.Prefix) (T, bool, error) {
	var empty T
	ranger, err := v.getRangerForIP(network.Addr())
	if err != nil {
		return empty, false, err
	}
	return ranger.Remove(network)
}

func (v *versionedRanger[T]) Contains(ip netip.Addr) (bool, error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return false, err
	}
	return ranger.Contains(ip)
}

func (v *versionedRanger[T]) ContainingNetworks(ip netip.Addr) ([]RangerEntry[T], error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return nil, err
	}
	return ranger.ContainingNetworks(ip)
}

func (v *versionedRanger[T]) CoveredNetworks(network netip.Prefix) ([]RangerEntry[T], error) {
	ranger, err := v.getRangerForIP(network.Addr())
	if err != nil {
		return nil, err
	}
	return ranger.CoveredNetworks(network)
}

func (v *versionedRanger[T]) CoveringNetworks(network netip.Prefix) ([]RangerEntry[T], error) {
	ranger, err := v.getRangerForIP(network.Addr())
	if err != nil {
		return nil, err
	}
	return ranger.CoveringNetworks(network)
}

// Len returns number of networks in ranger.
func (v *versionedRanger[T]) Len() int {
	return v.ipV4Ranger.Len() + v.ipV6Ranger.Len()
}

// Adjacent returns the adjacent network
func (v *versionedRanger[T]) Adjacent(network netip.Prefix) (entry RangerEntry[T], success bool, err error) {
	ranger, err := v.getRangerForIP(network.Addr())
	if err != nil {
		return entry, false, err
	}
	return ranger.Adjacent(network)
}

func (v *versionedRanger[T]) getRangerForIP(ip netip.Addr) (Ranger[T], error) {
	if ip.Is4() {
		return v.ipV4Ranger, nil
	} else if ip.Is6() {
		return v.ipV6Ranger, nil
	}
	return nil, ErrInvalidNetworkNumberInput
}
