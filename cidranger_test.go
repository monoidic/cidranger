package cidranger

import (
	"encoding/json"
	"math/rand"
	"net/netip"
	"os"
	"testing"

	rnet "github.com/monoidic/cidranger/v2/net"
	"github.com/stretchr/testify/assert"
)

/*
 ******************************************************************
 Test Contains/ContainingNetworks against basic brute force ranger.
 ******************************************************************
*/

func TestContainsAgainstBaseIPv4(t *testing.T) {
	testContainsAgainstBase(t, 100000, randIPv4Gen)
}

func TestContainingNetworksAgaistBaseIPv4(t *testing.T) {
	testContainingNetworksAgainstBase(t, 100000, randIPv4Gen)
}

func TestCoveredNetworksAgainstBaseIPv4(t *testing.T) {
	testCoversNetworksAgainstBase(t, 100000, randomIPNetGenFactory(ipV4AWSRangesIPNets))
}

func TestCoveringNetworksAgainstBaseIPv4(t *testing.T) {
	testCoveringNetworksAgainstBase(t, 100000, randomIPNetGenFactory(ipV4AWSRangesIPNets))
}

// IPv6 spans an extremely large address space (2^128), randomly generated IPs
// will often fall outside of the test ranges (AWS public CIDR blocks), so it
// it more meaningful for testing to run from a curated list of IPv6 IPs.
func TestContainsAgaistBaseIPv6(t *testing.T) {
	testContainsAgainstBase(t, 100000, curatedAWSIPv6Gen)
}

func TestContainingNetworksAgaistBaseIPv6(t *testing.T) {
	testContainingNetworksAgainstBase(t, 100000, curatedAWSIPv6Gen)
}

func TestCoveredNetworksAgainstBaseIPv6(t *testing.T) {
	testCoversNetworksAgainstBase(t, 100000, randomIPNetGenFactory(ipV6AWSRangesIPNets))
}

func TestCoveringNetworksAgainstBaseIPv6(t *testing.T) {
	testCoveringNetworksAgainstBase(t, 100000, randomIPNetGenFactory(ipV6AWSRangesIPNets))
}

func testContainsAgainstBase(t *testing.T, iterations int, ipGen ipGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger[empty]{NewPCTrieRanger[empty]()}
	baseRanger := newBruteRanger[empty]()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(ranger)
	}
	configureRangerWithAWSRanges(baseRanger)

	for i := 0; i < iterations; i++ {
		nn := ipGen()
		ip := nn.ToIP()
		expected, err := baseRanger.Contains(ip)
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.Contains(ip)
			assert.NoError(t, err)
			assert.Equal(t, expected, actual)
		}
	}
}

func testContainingNetworksAgainstBase(t *testing.T, iterations int, ipGen ipGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger[empty]{NewPCTrieRanger[empty]()}
	baseRanger := newBruteRanger[empty]()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(ranger)
	}
	configureRangerWithAWSRanges(baseRanger)

	for i := 0; i < iterations; i++ {
		nn := ipGen()
		expected, err := baseRanger.ContainingNetworks(nn.ToIP())
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.ContainingNetworks(nn.ToIP())
			assert.NoError(t, err)
			assert.Equal(t, len(expected), len(actual))
			for _, network := range actual {
				assert.Contains(t, expected, network)
			}
		}
	}
}

func testCoversNetworksAgainstBase(t *testing.T, iterations int, netGen networkGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger[empty]{NewPCTrieRanger[empty]()}
	baseRanger := newBruteRanger[empty]()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(ranger)
	}
	configureRangerWithAWSRanges(baseRanger)

	for i := 0; i < iterations; i++ {
		network := netGen()
		expected, err := baseRanger.CoveredNetworks(network.IPNet)
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.CoveredNetworks(network.IPNet)
			assert.NoError(t, err)
			assert.Equal(t, len(expected), len(actual))
			for _, network := range actual {
				assert.Contains(t, expected, network)
			}
		}
	}
}

func testCoveringNetworksAgainstBase(t *testing.T, iterations int, netGen networkGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger[empty]{NewPCTrieRanger[empty]()}
	baseRanger := newBruteRanger[empty]()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(ranger)
	}
	configureRangerWithAWSRanges(baseRanger)

	for i := 0; i < iterations; i++ {
		network := netGen()
		expected, err := baseRanger.CoveringNetworks(network.IPNet)
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.CoveringNetworks(network.IPNet)
			assert.NoError(t, err)
			assert.Equal(t, len(expected), len(actual))
			for _, network := range actual {
				assert.Contains(t, expected, network)
			}
		}
	}
}

/*
 ******************************************************************
 Benchmarks.
 ******************************************************************
*/

func BenchmarkPCTrieHitIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, netip.MustParseAddr("52.95.110.1"), NewPCTrieRanger[empty]())
}
func BenchmarkBruteRangerHitIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, netip.MustParseAddr("52.95.110.1"), newBruteRanger[empty]())
}

func BenchmarkPCTrieHitIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, netip.MustParseAddr("2620:107:300f::36b7:ff81"), NewPCTrieRanger[empty]())
}
func BenchmarkBruteRangerHitIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, netip.MustParseAddr("2620:107:300f::36b7:ff81"), newBruteRanger[empty]())
}

func BenchmarkPCTrieMissIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, netip.MustParseAddr("123.123.123.123"), NewPCTrieRanger[empty]())
}
func BenchmarkBruteRangerMissIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, netip.MustParseAddr("123.123.123.123"), newBruteRanger[empty]())
}

func BenchmarkPCTrieHMissIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, netip.MustParseAddr("2620::ffff"), NewPCTrieRanger[empty]())
}
func BenchmarkBruteRangerMissIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, netip.MustParseAddr("2620::ffff"), newBruteRanger[empty]())
}

func BenchmarkPCTrieHitContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("52.95.110.1"), NewPCTrieRanger[empty]())
}
func BenchmarkBruteRangerHitContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("52.95.110.1"), newBruteRanger[empty]())
}

func BenchmarkPCTrieHitContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("2620:107:300f::36b7:ff81"), NewPCTrieRanger[empty]())
}
func BenchmarkBruteRangerHitContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("2620:107:300f::36b7:ff81"), newBruteRanger[empty]())
}

func BenchmarkPCTrieMissContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("123.123.123.123"), NewPCTrieRanger[empty]())
}
func BenchmarkBruteRangerMissContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("123.123.123.123"), newBruteRanger[empty]())
}

func BenchmarkPCTrieHMissContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("2620::ffff"), NewPCTrieRanger[empty]())
}
func BenchmarkBruteRangerMissContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("2620::ffff"), newBruteRanger[empty]())
}

func BenchmarkNewPathprefixTriev4(b *testing.B) {
	benchmarkNewPathprefixTrie(b, "192.128.0.0/24")
}

func BenchmarkNewPathprefixTriev6(b *testing.B) {
	benchmarkNewPathprefixTrie(b, "8000::/24")
}

func benchmarkContainsUsingAWSRanges(b *testing.B, nn netip.Addr, ranger Ranger[empty]) {
	configureRangerWithAWSRanges(ranger)
	for n := 0; n < b.N; n++ {
		ranger.Contains(nn)
	}
}

func benchmarkContainingNetworksUsingAWSRanges(b *testing.B, nn netip.Addr, ranger Ranger[empty]) {
	configureRangerWithAWSRanges(ranger)
	for n := 0; n < b.N; n++ {
		ranger.ContainingNetworks(nn)
	}
}

func benchmarkNewPathprefixTrie(b *testing.B, net1 string) {
	ipNet1 := netip.MustParsePrefix(net1)
	ones := ipNet1.Bits()

	n1 := rnet.NewNetwork(ipNet1)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		newPathprefixTrie[empty](n1, ones)
	}
}

/*
 ******************************************************************
 Helper methods and initialization.
 ******************************************************************
*/

type ipGenerator func() rnet.NetworkNumber

func randIPv4Gen() rnet.NetworkNumber {
	return rnet.NetworkNumber{rand.Uint32()}
}

func curatedAWSIPv6Gen() rnet.NetworkNumber {
	randIdx := rand.Intn(len(ipV6AWSRangesIPNets))

	// Randomly generate an IP somewhat near the range.
	network := ipV6AWSRangesIPNets[randIdx]
	nn := rnet.NewNetworkNumber(network.Addr())

	bits := 32
	addr := network.Addr()
	if addr.Is6() {
		bits = 128
	}
	ones := network.Bits()
	zeros := bits - ones
	nnPartIdx := zeros / rnet.BitsPerUint32
	nn[nnPartIdx] = rand.Uint32()
	return nn
}

type networkGenerator func() rnet.Network

func randomIPNetGenFactory(pool []netip.Prefix) networkGenerator {
	return func() rnet.Network {
		return rnet.NewNetwork(pool[rand.Intn(len(pool))])
	}
}

type AWSRanges struct {
	Prefixes     []Prefix     `json:"prefixes"`
	IPv6Prefixes []IPv6Prefix `json:"ipv6_prefixes"`
}

type Prefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

type IPv6Prefix struct {
	IPPrefix string `json:"ipv6_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

var awsRanges *AWSRanges
var ipV4AWSRangesIPNets []netip.Prefix
var ipV6AWSRangesIPNets []netip.Prefix

func loadAWSRanges() *AWSRanges {
	file, err := os.ReadFile("./testdata/aws_ip_ranges.json")
	if err != nil {
		panic(err)
	}
	var ranges AWSRanges
	err = json.Unmarshal(file, &ranges)
	if err != nil {
		panic(err)
	}
	return &ranges
}

func configureRangerWithAWSRanges(ranger Ranger[empty]) {
	for _, prefix := range awsRanges.Prefixes {
		network := netip.MustParsePrefix(prefix.IPPrefix)
		ranger.Insert(network, emptyV)
	}
	for _, prefix := range awsRanges.IPv6Prefixes {
		network := netip.MustParsePrefix(prefix.IPPrefix)
		ranger.Insert(network, emptyV)
	}
}

func init() {
	awsRanges = loadAWSRanges()
	for _, prefix := range awsRanges.IPv6Prefixes {
		network := netip.MustParsePrefix(prefix.IPPrefix)
		ipV6AWSRangesIPNets = append(ipV6AWSRangesIPNets, network)
	}
	for _, prefix := range awsRanges.Prefixes {
		network := netip.MustParsePrefix(prefix.IPPrefix)
		ipV4AWSRangesIPNets = append(ipV4AWSRangesIPNets, network)
	}
}
