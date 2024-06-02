package cidranger

import (
	"net/netip"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInsert(t *testing.T) {
	ranger := newBruteRanger[int]().(*bruteRanger[int])
	networkIPv4 := netip.MustParsePrefix("0.0.1.0/24")
	networkIPv6 := netip.MustParsePrefix("8000::/96")

	ranger.Insert(networkIPv4, 12)
	ranger.Insert(networkIPv6, 34)

	assert.Equal(t, 1, len(ranger.ipV4Entries))
	assert.Equal(t, 12, ranger.ipV4Entries[networkIPv4])
	assert.Equal(t, 1, len(ranger.ipV6Entries))
	assert.Equal(t, 34, ranger.ipV6Entries[networkIPv6])
}

func TestRemove(t *testing.T) {
	ranger := newBruteRanger[int]().(*bruteRanger[int])
	networkIPv4 := netip.MustParsePrefix("0.0.1.0/24")
	networkIPv6 := netip.MustParsePrefix("8000::/96")
	notInserted := netip.MustParsePrefix("8000::/96")

	ranger.Insert(networkIPv4, 12)
	deletedIPv4, _, err := ranger.Remove(networkIPv4)
	assert.NoError(t, err)

	ranger.Insert(networkIPv6, 34)
	deletedIPv6, _, err := ranger.Remove(networkIPv6)
	assert.NoError(t, err)

	entry, _, err := ranger.Remove(notInserted)
	assert.NoError(t, err)
	assert.Equal(t, 0, entry)

	assert.Equal(t, 12, deletedIPv4)
	assert.Equal(t, 0, len(ranger.ipV4Entries))
	assert.Equal(t, 34, deletedIPv6)
	assert.Equal(t, 0, len(ranger.ipV6Entries))
}

func TestContains(t *testing.T) {
	r := newBruteRanger[empty]().(*bruteRanger[empty])
	network1 := netip.MustParsePrefix("0.0.1.0/24")
	network2 := netip.MustParsePrefix("8000::/112")
	r.Insert(network1, emptyV)
	r.Insert(network2, emptyV)

	cases := []struct {
		ip       netip.Addr
		contains bool
		err      error
		name     string
	}{
		{netip.MustParseAddr("0.0.1.255"), true, nil, "IPv4 should contain"},
		{netip.MustParseAddr("0.0.0.255"), false, nil, "IPv4 shouldn't contain"},
		{netip.MustParseAddr("8000::ffff"), true, nil, "IPv6 shouldn't contain"},
		{netip.MustParseAddr("8000::1:ffff"), false, nil, "IPv6 shouldn't contain"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			contains, err := r.Contains(tc.ip)
			if tc.err != nil {
				assert.Equal(t, tc.err, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.contains, contains)
			}
		})
	}
}

func TestContainingNetworks(t *testing.T) {
	r := newBruteRanger[empty]().(*bruteRanger[empty])
	network1 := netip.MustParsePrefix("0.0.1.0/24")
	network2 := netip.MustParsePrefix("0.0.1.0/25")
	network3 := netip.MustParsePrefix("8000::/112")
	network4 := netip.MustParsePrefix("8000::/113")
	entry1 := newEmptyRangerEntry(network1)
	entry2 := newEmptyRangerEntry(network2)
	entry3 := newEmptyRangerEntry(network3)
	entry4 := newEmptyRangerEntry(network4)
	r.Insert(network1, emptyV)
	r.Insert(network2, emptyV)
	r.Insert(network3, emptyV)
	r.Insert(network4, emptyV)
	cases := []struct {
		ip                 netip.Addr
		containingNetworks []RangerEntry[empty]
		err                error
		name               string
	}{
		{netip.MustParseAddr("0.0.1.255"), []RangerEntry[empty]{entry1}, nil, "IPv4 should contain"},
		{netip.MustParseAddr("0.0.1.127"), []RangerEntry[empty]{entry1, entry2}, nil, "IPv4 should contain both"},
		{netip.MustParseAddr("0.0.0.127"), nil, nil, "IPv4 should contain none"},
		{netip.MustParseAddr("8000::ffff"), []RangerEntry[empty]{entry3}, nil, "IPv6 should constain"},
		{netip.MustParseAddr("8000::7fff"), []RangerEntry[empty]{entry3, entry4}, nil, "IPv6 should contain both"},
		{netip.MustParseAddr("8000::1:7fff"), nil, nil, "IPv6 should contain none"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			networks, err := r.ContainingNetworks(tc.ip)
			if tc.err != nil {
				assert.Equal(t, tc.err, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tc.containingNetworks), len(networks))
				for _, network := range tc.containingNetworks {
					assert.Contains(t, networks, network)
				}
			}
		})
	}
}

func TestCoveredNetworks(t *testing.T) {
	for _, tc := range coveredNetworkTests {
		t.Run(tc.name, func(t *testing.T) {
			ranger := newBruteRanger[empty]()
			for _, insert := range tc.inserts {
				network := netip.MustParsePrefix(insert)
				err := ranger.Insert(network, emptyV)
				assert.NoError(t, err)
			}

			var expectedEntries []string
			expectedEntries = append(expectedEntries, tc.networks...)
			sort.Strings(expectedEntries)
			snet := netip.MustParsePrefix(tc.search)
			networks, err := ranger.CoveredNetworks(snet)
			assert.NoError(t, err)

			var results []string
			for _, entry := range networks {
				results = append(results, entry.Network.String())
			}
			sort.Strings(results)

			assert.Equal(t, expectedEntries, results)
		})
	}
}

func TestCoveringNetworks(t *testing.T) {
	for _, tc := range coveringNetworkTests {
		t.Run(tc.name, func(t *testing.T) {
			ranger := newBruteRanger[empty]()
			for _, insert := range tc.inserts {
				network := netip.MustParsePrefix(insert)
				err := ranger.Insert(network, emptyV)
				assert.NoError(t, err)
			}
			var expectedEntries []string
			expectedEntries = append(expectedEntries, tc.networks...)
			sort.Strings(expectedEntries)
			snet := netip.MustParsePrefix(tc.search)
			networks, err := ranger.CoveringNetworks(snet)
			assert.NoError(t, err)

			var results []string
			for _, result := range networks {
				results = append(results, result.Network.String())
			}
			sort.Strings(results)

			assert.Equal(t, expectedEntries, results)
		})
	}
}
