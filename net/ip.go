/*
Package net provides utility functions for working with IPs (net.IP).
*/
package net

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
)

// IPVersion is version of IP address.
type IPVersion string

// Helper constants.
const (
	IPv4Uint32Count = 1
	IPv6Uint32Count = 4

	BitsPerUint32 = 32
	BytePerUint32 = 4

	IPv4 IPVersion = "IPv4"
	IPv6 IPVersion = "IPv6"
)

// ErrInvalidBitPosition is returned when bits requested is not valid.
var ErrInvalidBitPosition = fmt.Errorf("bit position not valid")

// ErrVersionMismatch is returned upon mismatch in network input versions.
var ErrVersionMismatch = fmt.Errorf("Network input version mismatch")

// ErrNoGreatestCommonBit is an error returned when no greatest common bit
// exists for the cidr ranges.
var ErrNoGreatestCommonBit = fmt.Errorf("no greatest common bit")

// NetworkNumber represents an IP address using uint32 as internal storage.
// IPv4 usings 1 uint32, while IPv6 uses 4 uint32.
type NetworkNumber []uint32

// NewNetworkNumber returns a equivalent NetworkNumber to given IP address,
// return nil if ip is neither IPv4 nor IPv6.
func NewNetworkNumber(ip netip.Addr) NetworkNumber {
	var parts int
	if ip.Is4() {
		parts = 1
	} else if ip.Is6() {
		parts = 4
	} else {
		return nil
	}

	nn := make(NetworkNumber, parts)
	sl := ip.AsSlice()
	for i := range parts {
		nn[i] = binary.BigEndian.Uint32(sl[i*4 : (i+1)*4])
	}
	return nn
}

// ToV4 returns ip address if ip is IPv4, returns nil otherwise.
func (n NetworkNumber) ToV4() NetworkNumber {
	if len(n) != IPv4Uint32Count {
		return nil
	}
	return n
}

// ToV6 returns ip address if ip is IPv6, returns nil otherwise.
func (n NetworkNumber) ToV6() NetworkNumber {
	if len(n) != IPv6Uint32Count {
		return nil
	}
	return n
}

// ToIP returns equivalent net.IP.
func (n NetworkNumber) ToIP() netip.Addr {
	sl := make([]byte, len(n)*BytePerUint32)
	for i := 0; i < len(n); i++ {
		binary.BigEndian.PutUint32(sl[i*4:(i+1)*4], n[i])
	}
	ip, _ := netip.AddrFromSlice(sl)
	return ip
}

// Equal is the equality test for 2 network numbers.
func (n NetworkNumber) Equal(n1 NetworkNumber) bool {
	if len(n) != len(n1) {
		return false
	}
	if n[0] != n1[0] {
		return false
	}
	if len(n) == IPv6Uint32Count {
		return n[1] == n1[1] && n[2] == n1[2] && n[3] == n1[3]
	}
	return true
}

// Next returns the next logical network number.
func (n NetworkNumber) Next() NetworkNumber {
	newIP := make(NetworkNumber, len(n))
	copy(newIP, n)
	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		if newIP[i] > 0 {
			break
		}
	}
	return newIP
}

// Previous returns the previous logical network number.
func (n NetworkNumber) Previous() NetworkNumber {
	newIP := make(NetworkNumber, len(n))
	copy(newIP, n)
	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]--
		if newIP[i] < math.MaxUint32 {
			break
		}
	}
	return newIP
}

// Bit returns uint32 representing the bit value at given position, e.g.,
// "128.0.0.0" has bit value of 1 at position 31, and 0 for positions 30 to 0.
func (n NetworkNumber) Bit(position uint) (byte, error) {
	if int(position) > len(n)*BitsPerUint32-1 {
		return 0, ErrInvalidBitPosition
	}
	idx := len(n) - 1 - int(position/BitsPerUint32)
	// Mod 31 to get array index.
	rShift := position & (BitsPerUint32 - 1)
	return byte(n[idx]>>rShift) & 1, nil
}

// FlipNthBit reverses the bit value at position. Position numbering is LSB 0.
func (n *NetworkNumber) FlipNthBit(position uint) error {
	if int(position) > len(*n)*BitsPerUint32-1 {
		return ErrInvalidBitPosition
	}
	idx := len(*n) - 1 - int(position/BitsPerUint32)
	bitUintPosition := position % 32
	XORMask := 1 << bitUintPosition
	//byteNum := net.IPv6len - (position / 8) - 1
	//	getByteIndexOfBit(bitNum)
	(*n)[idx] ^= uint32(XORMask)
	return nil
}

// LeastCommonBitPosition returns the smallest position of the preceding common
// bits of the 2 network numbers, and returns an error ErrNoGreatestCommonBit
// if the two network number diverges from the first bit.
// e.g., if the network number diverges after the 1st bit, it returns 131 for
// IPv6 and 31 for IPv4 .
func (n NetworkNumber) LeastCommonBitPosition(n1 NetworkNumber) (int, error) {
	if len(n) != len(n1) {
		return 0, ErrVersionMismatch
	}
	for i := 0; i < len(n); i++ {
		pos := 31
		for mask := uint32(1 << 31); mask > 0; mask >>= 1 {
			if n[i]&mask != n1[i]&mask {
				if i == 0 && pos == 31 {
					return 0, ErrNoGreatestCommonBit
				}
				return pos + 1 + BitsPerUint32*(len(n)-i-1), nil
			}
			pos--
		}
	}
	return 0, nil
}

// Network represents a block of network numbers, also known as CIDR.
type Network struct {
	IPNet  netip.Prefix
	Number NetworkNumber
	Mask   NetworkNumberMask
}

// NewNetwork returns Network built using given net.IPNet.
func NewNetwork(ipNet netip.Prefix) Network {
	return Network{
		IPNet:  ipNet, //.Masked(),
		Number: NewNetworkNumber(ipNet.Addr()),
		Mask:   bitsToMask(ipNet.Bits(), ipNet.Addr().BitLen()),
	}
}

func bitsToMask(ones, bits int) NetworkNumberMask {
	parts := bits / BitsPerUint32
	sl := make([]uint32, parts)
	for i := 0; i < parts; i++ {
		if ones == 0 {
			break
		}
		var maskBits uint32
		if ones >= 32 {
			maskBits = 0xffff_ffff
			ones -= 32
		} else {
			maskBits = ((1 << ones) - 1) << (32 - ones)
			ones = 0
		}
		sl[i] = maskBits
	}

	return NetworkNumberMask(sl)
}

// Masked returns a new network conforming to new mask.
func (n Network) Masked(ones int) Network {
	return NewNetwork(netip.PrefixFrom(n.IPNet.Addr(), ones).Masked())
}

// Contains returns true if NetworkNumber is in range of Network, false
// otherwise.
func (n Network) Contains(nn NetworkNumber) bool {
	if len(n.Mask) != len(nn) {
		return false
	}
	if nn[0]&n.Mask[0] != n.Number[0] {
		return false
	}
	if len(nn) == IPv6Uint32Count {
		return nn[1]&n.Mask[1] == n.Number[1] && nn[2]&n.Mask[2] == n.Number[2] && nn[3]&n.Mask[3] == n.Number[3]
	}
	return true
}

// Covers returns true if Network covers o, false otherwise
func (n Network) Covers(o Network) bool {
	if len(n.Number) != len(o.Number) {
		return false
	}
	nMaskSize := n.IPNet.Bits()
	oMaskSize := o.IPNet.Bits()
	return n.Contains(o.Number) && nMaskSize <= oMaskSize
}

// LeastCommonBitPosition returns the smallest position of the preceding common
// bits of the 2 networks, and returns an error ErrNoGreatestCommonBit
// if the two network number diverges from the first bit.
func (n Network) LeastCommonBitPosition(n1 Network) (max int, err error) {
	maskSize := n.IPNet.Bits()
	if maskSize1 := n1.IPNet.Bits(); maskSize1 < maskSize {
		maskSize = maskSize1
	}

	if max, err = n.Number.LeastCommonBitPosition(n1.Number); err != nil {
		return 0, err
	}
	if maskPosition := len(n1.Number)*BitsPerUint32 - maskSize; maskPosition > max {
		max = maskPosition
	}

	return max, nil
}

// Equal is the equality test for 2 networks.
func (n Network) Equal(n1 Network) bool {
	return n.IPNet == n1.IPNet
}

func (n Network) String() string {
	return n.IPNet.String()
}

// NetworkNumberMask is an IP address.
type NetworkNumberMask NetworkNumber

// Mask returns a new masked NetworkNumber from given NetworkNumber.
func (m NetworkNumberMask) Mask(n NetworkNumber) (NetworkNumber, error) {
	if len(m) != len(n) {
		return nil, ErrVersionMismatch
	}
	result := make(NetworkNumber, len(m))
	result[0] = m[0] & n[0]
	if len(m) == IPv6Uint32Count {
		result[1] = m[1] & n[1]
		result[2] = m[2] & n[2]
		result[3] = m[3] & n[3]
	}
	return result, nil
}

// NextIP returns the next sequential ip.
func NextIP(ip netip.Addr) netip.Addr {
	return NewNetworkNumber(ip).Next().ToIP()
}

// PreviousIP returns the previous sequential ip.
func PreviousIP(ip netip.Addr) netip.Addr {
	return NewNetworkNumber(ip).Previous().ToIP()
}
