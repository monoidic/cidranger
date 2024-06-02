/*
Example of how to extend github.com/yl2chen/cidranger

	This adds ASN as a string field, along with methods to get the ASN and the CIDR as strings

Thank you to yl2chen for his assistance and work on this library
*/
package main

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/monoidic/cidranger/v2"
)

// entry point
func main() {
	// instantiate NewPCTrieRanger
	ranger := cidranger.NewPCTrieRanger[string]()

	// Load sample data using our custom function
	ranger.Insert(netip.MustParsePrefix("192.168.1.0/24"), "0001")
	ranger.Insert(netip.MustParsePrefix("128.168.1.0/24"), "0002")

	// Check if IP is contained within ranger
	contains, err := ranger.Contains(netip.MustParseAddr("128.168.1.7"))
	if err != nil {
		fmt.Println("ranger.Contains()", err.Error())
		os.Exit(1)
	}
	fmt.Println("Contains:", contains)

	// request networks containing this IP
	ip := "192.168.1.42"
	entries, err := ranger.ContainingNetworks(netip.MustParseAddr(ip))
	if err != nil {
		fmt.Println("ranger.ContainingNetworks()", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Entries for %s:\n", ip)
	for net, s := range entries {
		// Display
		fmt.Println("\t", net, s)
	}
}
