package cidranger

import (
	"encoding/binary"
	"math"
	"math/rand"
	"net/netip"
	"runtime"
	"testing"

	rnet "github.com/monoidic/cidranger/v2/net"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func getAllByVersion(version rnet.IPVersion) netip.Prefix {
	if version == rnet.IPv6 {
		return AllIPv6
	}
	return AllIPv4
}

func TestPrefixTrieInsert(t *testing.T) {
	cases := []struct {
		version                      rnet.IPVersion
		inserts                      []string
		expectedNetworksInDepthOrder []string
		name                         string
	}{
		{rnet.IPv4, []string{"192.168.0.1/24"}, []string{"192.168.0.0/24"}, "basic insert"},
		{
			rnet.IPv4,
			[]string{"1.2.3.4/32", "1.2.3.5/32"},
			[]string{"1.2.3.4/32", "1.2.3.5/32"},
			"single ip IPv4 network insert",
		},
		{
			rnet.IPv6,
			[]string{"0::1/128", "0::2/128"},
			[]string{"0::1/128", "0::2/128"},
			"single ip IPv6 network insert",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/16", "192.168.0.1/24"},
			[]string{"192.168.0.0/16", "192.168.0.0/24"},
			"in order insert",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/32", "192.168.0.1/32"},
			[]string{"192.168.0.1/32"},
			"duplicate network insert",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.0.1/16"},
			[]string{"192.168.0.0/16", "192.168.0.0/24"},
			"reverse insert",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.1.1/24"},
			[]string{"192.168.0.0/24", "192.168.1.0/24"},
			"branch insert",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.1.1/24", "192.168.1.1/30"},
			[]string{"192.168.0.0/24", "192.168.1.0/24", "192.168.1.0/30"},
			"branch inserts",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree[empty](tc.version).(*prefixTrie[empty])
			for _, insert := range tc.inserts {
				network := netip.MustParsePrefix(insert)
				err := trie.Insert(network, emptyV)
				assert.NoError(t, err)
			}

			assert.Equal(t, len(tc.expectedNetworksInDepthOrder), trie.Len(), "trie size should match")

			allNetworks, err := trie.CoveredNetworks(getAllByVersion(tc.version))
			assert.Nil(t, err)
			assert.Equal(t, len(allNetworks), trie.Len(), "trie size should match")

			walk := trie.walkDepth()
			for _, network := range tc.expectedNetworksInDepthOrder {
				ipnet := netip.MustParsePrefix(network)
				expected := newEmptyRangerEntry(ipnet)
				actual := <-walk
				assert.Equal(t, expected, actual)
			}

			// Ensure no unexpected elements in trie.
			for network := range walk {
				assert.Nil(t, network)
			}
		})
	}
}

func TestPrefixTrieString(t *testing.T) {
	inserts := []string{"192.168.0.1/24", "192.168.1.1/24", "192.168.1.1/30"}
	trie := newPrefixTree[empty](rnet.IPv4).(*prefixTrie[empty])
	for _, insert := range inserts {
		network := netip.MustParsePrefix(insert)
		trie.Insert(network, emptyV)
	}
	expected := `0.0.0.0/0 (target_pos:31:has_entry:false)
| 1--> 192.168.0.0/23 (target_pos:8:has_entry:false)
| | 0--> 192.168.0.0/24 (target_pos:7:has_entry:true)
| | 1--> 192.168.1.0/24 (target_pos:7:has_entry:true)
| | | 0--> 192.168.1.0/30 (target_pos:1:has_entry:true)`
	assert.Equal(t, expected, trie.String())
}

func TestPrefixTrieRemove(t *testing.T) {
	cases := []struct {
		version                      rnet.IPVersion
		inserts                      []string
		removes                      []string
		expectedRemoves              []string
		expectedNetworksInDepthOrder []string
		expectedTrieString           string
		name                         string
	}{
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24"},
			[]string{"192.168.0.1/24"},
			[]string{"192.168.0.0/24"},
			nil,
			"0.0.0.0/0 (target_pos:31:has_entry:false)",
			"basic remove",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/32"},
			[]string{"192.168.0.1/24"},
			[]string{""},
			[]string{"192.168.0.1/32"},
			`0.0.0.0/0 (target_pos:31:has_entry:false)
| 1--> 192.168.0.1/32 (target_pos:-1:has_entry:true)`,
			"remove from ranger that contains a single ip block",
		},
		{
			rnet.IPv4,
			[]string{"1.2.3.4/32", "1.2.3.5/32"},
			[]string{"1.2.3.5/32"},
			[]string{"1.2.3.5/32"},
			[]string{"1.2.3.4/32"},
			`0.0.0.0/0 (target_pos:31:has_entry:false)
| 0--> 1.2.3.4/32 (target_pos:-1:has_entry:true)`,
			"single ip IPv4 network remove",
		},
		{
			rnet.IPv4,
			[]string{"0::1/128", "0::2/128"},
			[]string{"0::2/128"},
			[]string{"0::2/128"},
			[]string{"0::1/128"},
			`0.0.0.0/0 (target_pos:31:has_entry:false)
| 0--> ::1/128 (target_pos:-1:has_entry:true)`,
			"single ip IPv6 network remove",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.0.1/25", "192.168.0.1/26"},
			[]string{"192.168.0.1/25"},
			[]string{"192.168.0.0/25"},
			[]string{"192.168.0.0/24", "192.168.0.0/26"},
			`0.0.0.0/0 (target_pos:31:has_entry:false)
| 1--> 192.168.0.0/24 (target_pos:7:has_entry:true)
| | 0--> 192.168.0.0/26 (target_pos:5:has_entry:true)`,
			"remove path prefix",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.0.1/25", "192.168.0.64/26", "192.168.0.1/26"},
			[]string{"192.168.0.1/25"},
			[]string{"192.168.0.0/25"},
			[]string{"192.168.0.0/24", "192.168.0.0/26", "192.168.0.64/26"},
			`0.0.0.0/0 (target_pos:31:has_entry:false)
| 1--> 192.168.0.0/24 (target_pos:7:has_entry:true)
| | 0--> 192.168.0.0/25 (target_pos:6:has_entry:false)
| | | 0--> 192.168.0.0/26 (target_pos:5:has_entry:true)
| | | 1--> 192.168.0.64/26 (target_pos:5:has_entry:true)`,
			"remove path prefix with more than 1 children",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.0.1/25"},
			[]string{"192.168.0.1/26"},
			[]string{""},
			[]string{"192.168.0.0/24", "192.168.0.0/25"},
			`0.0.0.0/0 (target_pos:31:has_entry:false)
| 1--> 192.168.0.0/24 (target_pos:7:has_entry:true)
| | 0--> 192.168.0.0/25 (target_pos:6:has_entry:true)`,
			"remove non existent",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree[empty](tc.version).(*prefixTrie[empty])
			for _, insert := range tc.inserts {
				network := netip.MustParsePrefix(insert)
				err := trie.Insert(network, emptyV)
				assert.NoError(t, err)
			}
			for i, remove := range tc.removes {
				network := netip.MustParsePrefix(remove)
				_, removed, err := trie.Remove(network)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedRemoves[i] != "", removed)
			}

			assert.Equal(t, len(tc.expectedNetworksInDepthOrder), trie.Len(), "trie size should match after revmoval")

			allNetworks, err := trie.CoveredNetworks(getAllByVersion(tc.version))
			assert.Nil(t, err)
			assert.Equal(t, len(allNetworks), trie.Len(), "trie size should match")

			walk := trie.walkDepth()
			for _, network := range tc.expectedNetworksInDepthOrder {
				ipnet := netip.MustParsePrefix(network)
				expected := newEmptyRangerEntry(ipnet)
				actual := <-walk
				assert.Equal(t, expected, actual)
			}

			// Ensure no unexpected elements in trie.
			for network := range walk {
				assert.Nil(t, network)
			}

			assert.Equal(t, tc.expectedTrieString, trie.String())
		})
	}
}

func TestToReplicateIssue(t *testing.T) {
	cases := []struct {
		version  rnet.IPVersion
		inserts  []string
		ip       netip.Addr
		networks []string
		name     string
	}{
		{
			rnet.IPv4,
			[]string{"192.168.0.1/32"},
			netip.MustParseAddr("192.168.0.1"),
			[]string{"192.168.0.1/32"},
			"basic containing network for /32 mask",
		},
		{
			rnet.IPv6,
			[]string{"a::1/128"},
			netip.MustParseAddr("a::1"),
			[]string{"a::1/128"},
			"basic containing network for /128 mask",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree[empty](tc.version)
			for _, insert := range tc.inserts {
				network := netip.MustParsePrefix(insert)
				err := trie.Insert(network, emptyV)
				assert.NoError(t, err)
			}
			var expectedNets []RangerEntry[empty]
			for _, network := range tc.networks {
				net := netip.MustParsePrefix(network)
				expectedNets = append(expectedNets, RangerEntry[empty]{Network: net})
			}
			contains, err := trie.Contains(tc.ip)
			assert.NoError(t, err)
			assert.True(t, contains)
			networks, err := trie.ContainingNetworks(tc.ip)
			assert.NoError(t, err)
			assert.Equal(t, expectedNets, networks)
		})
	}
}

type expectedIPRange struct {
	start netip.Addr
	end   netip.Addr
}

func TestPrefixTrieContains(t *testing.T) {
	cases := []struct {
		version     rnet.IPVersion
		inserts     []string
		expectedIPs []expectedIPRange
		name        string
	}{
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24"},
			[]expectedIPRange{
				{netip.MustParseAddr("192.168.0.0"), netip.MustParseAddr("192.168.1.0")},
			},
			"basic contains",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24", "128.168.0.0/24"},
			[]expectedIPRange{
				{netip.MustParseAddr("192.168.0.0"), netip.MustParseAddr("192.168.1.0")},
				{netip.MustParseAddr("128.168.0.0"), netip.MustParseAddr("128.168.1.0")},
			},
			"multiple ranges contains",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree[empty](tc.version)
			for _, insert := range tc.inserts {
				network := netip.MustParsePrefix(insert)
				err := trie.Insert(network, emptyV)
				assert.NoError(t, err)
			}
			for _, expectedIPRange := range tc.expectedIPs {
				var contains bool
				var err error
				for start := expectedIPRange.start; expectedIPRange.end != start; start = rnet.NextIP(start) {
					contains, err = trie.Contains(start)
					assert.NoError(t, err)
					assert.True(t, contains)
				}

				// Check out of bounds ips on both ends
				contains, err = trie.Contains(rnet.PreviousIP(expectedIPRange.start))
				assert.NoError(t, err)
				assert.False(t, contains)
				contains, err = trie.Contains(rnet.NextIP(expectedIPRange.end))
				assert.NoError(t, err)
				assert.False(t, contains)
			}
		})
	}
}

func TestPrefixTrieContainingNetworks(t *testing.T) {
	cases := []struct {
		version  rnet.IPVersion
		inserts  []string
		ip       netip.Addr
		networks []string
		name     string
	}{
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24"},
			netip.MustParseAddr("192.168.0.1"),
			[]string{"192.168.0.0/24"},
			"basic containing networks",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24", "192.168.0.0/25"},
			netip.MustParseAddr("192.168.0.1"),
			[]string{"192.168.0.0/24", "192.168.0.0/25"},
			"inclusive networks",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree[empty](tc.version)
			for _, insert := range tc.inserts {
				network := netip.MustParsePrefix(insert)
				err := trie.Insert(network, emptyV)
				assert.NoError(t, err)
			}
			var expectedNets []RangerEntry[empty]
			for _, network := range tc.networks {
				net := netip.MustParsePrefix(network)
				expectedNets = append(expectedNets, RangerEntry[empty]{Network: net})
			}
			networks, err := trie.ContainingNetworks(tc.ip)
			assert.NoError(t, err)
			assert.Equal(t, expectedNets, networks)
		})
	}
}

func TestPrefixTrie_Adjacent(t *testing.T) {
	cases := []struct {
		version         rnet.IPVersion
		inserts         []string
		network         string
		expected        string
		name            string
		expectedSuccess bool
	}{
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24"},
			"192.168.1.0/24",
			"192.168.0.0/24",
			"check /24 adjacent",
			true,
		},
		{
			rnet.IPv4,
			[]string{"128.0.0.5/1"},
			"0.0.5.0/1",
			"128.0.0.0/1",
			"check /1 adjacent, with some bits in ip address range",
			true,
		},
		{
			rnet.IPv4,
			[]string{"0.0.0.0/0"},
			"0.0.0.0/0",
			"",
			"0.0.0.0/0 can't have adjacent",
			false,
		},
	}
	log.SetLevel(log.TraceLevel)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree[empty](tc.version)
			for _, insert := range tc.inserts {
				network := netip.MustParsePrefix(insert)
				err := trie.Insert(network, emptyV)
				assert.NoError(t, err)
			}
			testNet := netip.MustParsePrefix(tc.network)
			entry, success, err := trie.Adjacent(testNet)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedSuccess, success)
			netString := ""
			if success {
				netString = entry.Network.String()
			}
			assert.Equal(t, tc.expected, netString)
		})
	}
}

type networkTest struct {
	version  rnet.IPVersion
	inserts  []string
	search   string
	networks []string
	name     string
}

var coveredNetworkTests = []networkTest{
	{
		rnet.IPv4,
		[]string{"192.168.0.0/24"},
		"192.168.0.0/16",
		[]string{"192.168.0.0/24"},
		"basic covered networks",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/24"},
		"192.168.0.0/24",
		[]string{"192.168.0.0/24"},
		"covered of equal networks",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/24"},
		"10.1.0.0/16",
		nil,
		"nothing",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/24", "192.168.0.0/25"},
		"192.168.0.0/16",
		[]string{"192.168.0.0/24", "192.168.0.0/25"},
		"multiple networks",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/24", "192.168.0.0/25", "192.168.0.1/32"},
		"192.168.0.0/16",
		[]string{"192.168.0.0/24", "192.168.0.0/25", "192.168.0.1/32"},
		"multiple networks 2",
	},
	{
		rnet.IPv4,
		[]string{"192.168.1.1/32"},
		"192.168.0.0/16",
		[]string{"192.168.1.1/32"},
		"leaf",
	},
	{
		rnet.IPv4,
		[]string{"0.0.0.0/0", "192.168.1.1/32"},
		"192.168.0.0/16",
		[]string{"192.168.1.1/32"},
		"leaf with root",
	},
	{
		rnet.IPv4,
		[]string{
			"0.0.0.0/0", "192.168.0.0/24", "192.168.1.1/32",
			"10.1.0.0/16", "10.1.1.0/24",
		},
		"192.168.0.0/16",
		[]string{"192.168.0.0/24", "192.168.1.1/32"},
		"path not taken",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/15"},
		"192.168.0.0/16",
		nil,
		"only masks different",
	},
}

var coveringNetworkTests = []networkTest{
	{
		rnet.IPv4,
		[]string{"192.168.0.0/16"},
		"192.168.0.0/24",
		[]string{"192.168.0.0/16"},
		"basic covering networks",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/24"},
		"192.168.0.0/24",
		[]string{"192.168.0.0/24"},
		"covering of equal networks",
	},
	{
		rnet.IPv4,
		[]string{"10.1.0.0/16"},
		"192.168.0.0/24",
		nil,
		"nothing",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/16", "192.168.0.0/24"},
		"192.168.0.0/25",
		[]string{"192.168.0.0/16", "192.168.0.0/24"},
		"multiple networks",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/16", "192.168.0.0/24", "192.168.0.0/25"},
		"192.168.0.1/32",
		[]string{"192.168.0.0/16", "192.168.0.0/24", "192.168.0.0/25"},
		"multiple networks 2",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/16"},
		"192.168.1.1/32",
		[]string{"192.168.0.0/16"},
		"leaf",
	},
	{
		rnet.IPv4,
		[]string{"0.0.0.0/0", "192.168.1.1/32"},
		"192.168.0.0/16",
		[]string{"0.0.0.0/0"},
		"leaf with root",
	},
	{
		rnet.IPv4,
		[]string{
			"0.0.0.0/0", "192.168.0.0/24", "192.168.1.1/32",
			"10.1.0.0/16", "10.1.1.0/24",
		},
		"192.168.0.0/16",
		[]string{"0.0.0.0/0"},
		"path not taken",
	},
	{
		rnet.IPv4,
		[]string{
			"192.168.0.0/16",
		},
		"192.168.0.0/15",
		nil,
		"only masks different",
	},
}

func TestPrefixTrieCoveredNetworks(t *testing.T) {
	for _, tc := range coveredNetworkTests {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree[empty](tc.version)
			for _, insert := range tc.inserts {
				network := netip.MustParsePrefix(insert)
				err := trie.Insert(network, emptyV)
				assert.NoError(t, err)
			}
			var expectedNets []RangerEntry[empty]
			for _, network := range tc.networks {
				net := netip.MustParsePrefix(network)
				expectedNets = append(expectedNets, RangerEntry[empty]{Network: net})
			}
			snet := netip.MustParsePrefix(tc.search)
			networks, err := trie.CoveredNetworks(snet)
			assert.NoError(t, err)
			assert.Equal(t, expectedNets, networks)
		})
	}
}

func TestPrefixTrieCoveringNetworks(t *testing.T) {
	for _, tc := range coveringNetworkTests {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree[empty](tc.version)
			for _, insert := range tc.inserts {
				network := netip.MustParsePrefix(insert)
				err := trie.Insert(network, emptyV)
				assert.NoError(t, err)
			}
			var expectedEntries []RangerEntry[empty]
			for _, network := range tc.networks {
				net := netip.MustParsePrefix(network)
				expectedEntries = append(expectedEntries,
					newEmptyRangerEntry(net))
			}
			snet := netip.MustParsePrefix(tc.search)
			networks, err := trie.CoveringNetworks(snet)
			assert.NoError(t, err)
			assert.Equal(t, expectedEntries, networks)
		})
	}
}

func TestTrieMemUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	numIPs := 100000
	runs := 10

	// Avg heap allocation over all runs should not be more than the heap allocation of first run multiplied
	// by threshold, picking 1% as sane number for detecting memory leak.
	thresh := 1.01

	trie := newPrefixTree[empty](rnet.IPv4)

	var baseLineHeap, totalHeapAllocOverRuns uint64
	for i := 0; i < runs; i++ {
		t.Logf("Executing Run %d of %d", i+1, runs)

		// Insert networks.
		for n := 0; n < numIPs; n++ {
			trie.Insert(GenLeafIPNet(GenIPV4()), emptyV)
		}
		t.Logf("Inserted All (%d networks)", trie.Len())
		assert.Less(t, 0, trie.Len(), "Len should > 0")
		assert.LessOrEqualf(t, trie.Len(), numIPs, "Len should <= %d", numIPs)

		allNetworks, err := trie.CoveredNetworks(getAllByVersion(rnet.IPv4))
		assert.Nil(t, err)
		assert.Equal(t, len(allNetworks), trie.Len(), "trie size should match")

		// Remove networks.
		all := netip.MustParsePrefix("0.0.0.0/0")
		ll, _ := trie.CoveredNetworks(all)
		for i := 0; i < len(ll); i++ {
			trie.Remove(ll[i].Network)
		}
		t.Logf("Removed All (%d networks)", len(ll))
		assert.Equal(t, 0, trie.Len(), "Len after removal should == 0")

		// Perform GC
		runtime.GC()

		// Get HeapAlloc stats.
		heapAlloc := GetHeapAllocation()
		totalHeapAllocOverRuns += heapAlloc
		if i == 0 {
			baseLineHeap = heapAlloc
		}
	}

	// Assert that heap allocation from first loop is within set threshold of avg over all runs.
	assert.Less(t, uint64(0), baseLineHeap)
	assert.LessOrEqual(t, float64(baseLineHeap), float64(totalHeapAllocOverRuns/uint64(runs))*thresh)
}

func GenLeafIPNet(ip netip.Addr) netip.Prefix {
	return netip.PrefixFrom(ip, 32)
}

// GenIPV4 generates an IPV4 address
func GenIPV4() netip.Addr {
	nn := rand.Uint32()
	if nn < math.MaxUint32 {
		nn++
	}
	sl := make([]byte, 4)
	binary.BigEndian.PutUint32(sl, uint32(nn))
	ip, _ := netip.AddrFromSlice(sl)
	return ip
}

func GetHeapAllocation() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// newEmptyRangerEntry returns a basic RangerEntry that only stores the network
// itself.
func newEmptyRangerEntry(ipNet netip.Prefix) RangerEntry[empty] {
	return RangerEntry[empty]{
		Network: ipNet,
	}
}

// dummy empty type and instance
type empty struct{}

var emptyV = empty{}
