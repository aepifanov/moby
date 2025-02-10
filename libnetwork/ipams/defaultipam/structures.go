package defaultipam

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/docker/docker/libnetwork/internal/addrset"
	"github.com/docker/docker/libnetwork/types"
	"lukechampine.com/uint128"
)

// PoolID is the pointer to the configured pools in each address space
type PoolID struct {
	AddressSpace string
	SubnetKey
}

// PoolData contains the configured pool data
type PoolData struct {
	addrs    *addrset.AddrSet
	children map[netip.Prefix]struct{}

	availableRange uint128.Uint128

	// Whether to implicitly release the pool once it no longer has any children.
	autoRelease bool
}

// SubnetKey is the composite key to an address pool within an address space.
type SubnetKey struct {
	Subnet, ChildSubnet netip.Prefix
}

func (k SubnetKey) Is6() bool {
	return k.Subnet.Addr().Is6()
}

// PoolIDFromString creates a new PoolID and populates the SubnetKey object
// reading it from the given string.
func PoolIDFromString(str string) (pID PoolID, err error) {
	if str == "" {
		return pID, types.InvalidParameterErrorf("invalid string form for subnetkey: %s", str)
	}

	p := strings.Split(str, "/")
	if len(p) != 3 && len(p) != 5 {
		return pID, types.InvalidParameterErrorf("invalid string form for subnetkey: %s", str)
	}
	pID.AddressSpace = p[0]
	pID.Subnet, err = netip.ParsePrefix(p[1] + "/" + p[2])
	if err != nil {
		return pID, types.InvalidParameterErrorf("invalid string form for subnetkey: %s", str)
	}
	if len(p) == 5 {
		pID.ChildSubnet, err = netip.ParsePrefix(p[3] + "/" + p[4])
		if err != nil {
			return pID, types.InvalidParameterErrorf("invalid string form for subnetkey: %s", str)
		}
	}

	return pID, nil
}

// String returns the string form of the SubnetKey object
func (s *PoolID) String() string {
	if s.ChildSubnet == (netip.Prefix{}) {
		return s.AddressSpace + "/" + s.Subnet.String()
	} else {
		return s.AddressSpace + "/" + s.Subnet.String() + "/" + s.ChildSubnet.String()
	}
}

// String returns the string form of the PoolData object
func (p *PoolData) String() string {
	return fmt.Sprintf("PoolData[Children: %d]", len(p.children))
}

// subnetCapacity returns the number of IP addresses in the given subnet.
func subnetCapacity(subnet netip.Prefix) uint128.Uint128 {
	capacity := uint128.From64(1)
	// Calculate the number of host bits
	hostBits := uint(subnet.Addr().BitLen() - subnet.Bits())
	// The number of IP addresses is 2^hostBits
	return capacity.Lsh(hostBits)
}

func (p *PoolData) capacityRange() (capacity uint128.Uint128) {
	if len(p.children) == 0 {
		return subnetCapacity(p.addrs.Pool())
	}

	for child, _ := range p.children {
		capacity = capacity.Add(subnetCapacity(child))
	}

	return
}

func (p *PoolData) AvailableAddrs() (availableSubnet uint64, availableRange uint64) {
	availableSubnet = p.addrs.Unselected()
	if p.availableRange.Cmp(uint128.New(0, 1)) > 0 {
		availableRange = addrset.MaxUint64
	} else {
		availableRange = p.availableRange.Lo
	}
	availableSubnet = p.addrs.Unselected()
	return
}

// mergeIter is used to iterate on both 'a' and 'b' at the same time while
// maintaining the total order that would arise if both were merged and then
// sorted. Both 'a' and 'b' have to be sorted beforehand.
type mergeIter struct {
	a, b   []netip.Prefix
	ia, ib int
	cmp    func(a, b netip.Prefix) int
	lastA  bool
}

func newMergeIter(a, b []netip.Prefix, cmp func(a, b netip.Prefix) int) *mergeIter {
	iter := &mergeIter{
		a:   a,
		b:   b,
		cmp: cmp,
	}
	iter.lastA = iter.nextA()

	return iter
}

func (it *mergeIter) Get() netip.Prefix {
	if it.ia+it.ib >= len(it.a)+len(it.b) {
		return netip.Prefix{}
	}

	if it.lastA {
		return it.a[it.ia]
	}

	return it.b[it.ib]
}

func (it *mergeIter) Inc() {
	if it.lastA {
		it.ia++
	} else {
		it.ib++
	}

	it.lastA = it.nextA()
}

func (it *mergeIter) nextA() bool {
	if it.ia < len(it.a) && it.ib < len(it.b) && it.cmp(it.a[it.ia], it.b[it.ib]) <= 0 {
		return true
	} else if it.ia < len(it.a) && it.ib >= len(it.b) {
		return true
	}

	return false
}
