package cidranger

import (
	"net/netip"

	rnet "github.com/yl2chen/cidranger/net"
)

type rangerFactory[T any] func(rnet.IPVersion) iface[T]

type versionedRanger[T any] struct {
	ipV4Ranger iface[T]
	ipV6Ranger iface[T]
}

func newVersionedRanger[T any](factory rangerFactory[T]) iface[T] {
	return &versionedRanger[T]{
		ipV4Ranger: factory(rnet.IPv4),
		ipV6Ranger: factory(rnet.IPv6),
	}
}

func (v *versionedRanger[T]) Insert(prefix netip.Prefix, value T) error {
	ranger, err := v.getRangerForIP(prefix.Addr())
	if err != nil {
		return err
	}
	return ranger.Insert(prefix, value)
}

func (v *versionedRanger[T]) Remove(prefix netip.Prefix) (T, bool, error) {
	ranger, err := v.getRangerForIP(prefix.Addr())
	if err != nil {
		var zero T
		return zero, false, err
	}
	return ranger.Remove(prefix)
}

func (v *versionedRanger[T]) Contains(ip netip.Addr) (bool, error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return false, err
	}
	return ranger.Contains(ip)
}

func (v *versionedRanger[T]) ContainingNetworks(ip netip.Addr) ([]T, error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return nil, err
	}
	return ranger.ContainingNetworks(ip)
}

func (v *versionedRanger[T]) CoveredNetworks(prefix netip.Prefix) ([]T, error) {
	ranger, err := v.getRangerForIP(prefix.Addr())
	if err != nil {
		return nil, err
	}
	return ranger.CoveredNetworks(prefix)
}

// Len returns number of networks in ranger.
func (v *versionedRanger[T]) Len() int {
	return v.ipV4Ranger.Len() + v.ipV6Ranger.Len()
}

func (v *versionedRanger[T]) getRangerForIP(ip netip.Addr) (iface[T], error) {
	if ip.Is4() {
		return v.ipV4Ranger, nil
	} else if ip.Is6() {
		return v.ipV6Ranger, nil
	}
	return nil, ErrInvalidNetworkNumberInput
}
