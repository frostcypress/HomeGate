package access

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
)

// parseDelegatedChina reads the official RIR statistics format. Country codes
// describe the holder's registration economy, not an endpoint's geolocation.
// Validate counts across the entire file before accepting any CN allocation:
// a truncated HTTP 200 response must never replace a working access cache.
func parseDelegatedChina(r io.Reader) ([]netip.Prefix, int, int, error) {
	limited := &io.LimitedReader{R: r, N: maxRegionBytes + 1}
	s := bufio.NewScanner(limited)
	s.Buffer(make([]byte, 4096), 1<<20)
	header := false
	expected, records := 0, 0
	counts := map[string]int{}
	summaries := map[string]int{}
	var cidrs strings.Builder
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "|")
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if !header {
			if len(f) != 7 || f[0] != "2" || f[1] != "apnic" {
				return nil, 0, 0, fmt.Errorf("invalid APNIC statistics header")
			}
			n, err := strconv.Atoi(f[3])
			if err != nil || n <= 0 {
				return nil, 0, 0, fmt.Errorf("invalid APNIC record count")
			}
			expected, header = n, true
			continue
		}
		if len(f) == 6 && f[1] == "*" && f[3] == "*" && f[5] == "summary" {
			n, err := strconv.Atoi(f[4])
			_, duplicate := summaries[f[2]]
			if f[0] != "apnic" || err != nil || n < 0 || duplicate {
				return nil, 0, 0, fmt.Errorf("invalid APNIC summary")
			}
			summaries[f[2]] = n
			continue
		}
		if len(f) < 7 || f[0] != "apnic" || (f[2] != "asn" && f[2] != "ipv4" && f[2] != "ipv6") {
			return nil, 0, 0, fmt.Errorf("invalid APNIC record")
		}
		records++
		counts[f[2]]++
		if f[1] != "CN" || (f[6] != "allocated" && f[6] != "assigned") || f[2] == "asn" {
			continue
		}
		a, err := netip.ParseAddr(f[3])
		if err != nil {
			return nil, 0, 0, fmt.Errorf("invalid CN allocation address")
		}
		if f[2] == "ipv6" {
			n, err := strconv.Atoi(f[4])
			if err != nil || !a.Is6() || a.Is4In6() || n <= 0 || n > 128 {
				return nil, 0, 0, fmt.Errorf("invalid CN IPv6 allocation")
			}
			p := netip.PrefixFrom(a, n)
			if p != p.Masked() {
				return nil, 0, 0, fmt.Errorf("unaligned CN IPv6 allocation")
			}
			fmt.Fprintln(&cidrs, p)
		} else {
			n, err := strconv.ParseUint(f[4], 10, 64)
			if err != nil || !a.Is4() || n == 0 {
				return nil, 0, 0, fmt.Errorf("invalid CN IPv4 allocation")
			}
			raw := a.As4()
			start := uint64(binary.BigEndian.Uint32(raw[:]))
			if n >= 1<<32 || start+n > 1<<32 {
				return nil, 0, 0, fmt.Errorf("CN IPv4 allocation overflows")
			}
			// RIR IPv4 counts need not be powers of two. Split the exact range
			// without allowing adjacent addresses outside the allocation.
			for n > 0 {
				power := bits.TrailingZeros32(uint32(start))
				if max := bits.Len64(n) - 1; power > max {
					power = max
				}
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], uint32(start))
				fmt.Fprintln(&cidrs, netip.PrefixFrom(netip.AddrFrom4(b), 32-power))
				step := uint64(1) << power
				start, n = start+step, n-step
			}
		}
		if cidrs.Len() > maxRegionBytes {
			return nil, 0, 0, fmt.Errorf("expanded CN prefix list exceeds %d bytes", maxRegionBytes)
		}
	}
	if err := s.Err(); err != nil {
		return nil, 0, 0, err
	}
	if limited.N <= 0 {
		return nil, 0, 0, fmt.Errorf("APNIC statistics exceed %d bytes", maxRegionBytes)
	}
	if !header || records != expected {
		return nil, 0, 0, fmt.Errorf("incomplete APNIC statistics: got %d records, expected %d", records, expected)
	}
	for kind, count := range counts {
		if n, ok := summaries[kind]; !ok || n != count {
			return nil, 0, 0, fmt.Errorf("incomplete APNIC %s summary", kind)
		}
	}
	for kind, count := range summaries {
		if counts[kind] != count {
			return nil, 0, 0, fmt.Errorf("incomplete APNIC %s records", kind)
		}
	}
	return parsePrefixReader(strings.NewReader(cidrs.String()))
}
