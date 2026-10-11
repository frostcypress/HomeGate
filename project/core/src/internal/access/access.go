package access

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/runtimefile"
)

const (
	DefaultRecentPath  = "/var/run/homegate/access.json"
	defaultRecentLimit = 64
	recorderFlushDelay = 100 * time.Millisecond
	maxRegionBytes     = 24 << 20
	regionRefreshAge   = 7 * 24 * time.Hour
)

type Region struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Path  string `json:"-"`
}

// Legacy province metadata is retained only for reading historical cache and
// access records. New downloads and configuration support CN exclusively.
var Regions = []Region{
	{Key: "CN", Label: "China / Mainland", Path: "cn_all.txt"},
	{Key: "CN-AH", Label: "China / Anhui", Path: "provinces/anhui.txt"},
	{Key: "CN-BJ", Label: "China / Beijing", Path: "provinces/beijing.txt"},
	{Key: "CN-CQ", Label: "China / Chongqing", Path: "provinces/chongqing.txt"},
	{Key: "CN-FJ", Label: "China / Fujian", Path: "provinces/fujian.txt"},
	{Key: "CN-GD", Label: "China / Guangdong", Path: "provinces/guangdong.txt"},
	{Key: "CN-GX", Label: "China / Guangxi", Path: "provinces/guangxi.txt"},
	{Key: "CN-GZ", Label: "China / Guizhou", Path: "provinces/guizhou.txt"},
	{Key: "CN-HI", Label: "China / Hainan", Path: "provinces/hainan.txt"},
	{Key: "CN-HE", Label: "China / Hebei", Path: "provinces/hebei.txt"},
	{Key: "CN-HL", Label: "China / Heilongjiang", Path: "provinces/heilongjiang.txt"},
	{Key: "CN-HA", Label: "China / Henan", Path: "provinces/henan.txt"},
	{Key: "CN-HB", Label: "China / Hubei", Path: "provinces/hubei.txt"},
	{Key: "CN-HN", Label: "China / Hunan", Path: "provinces/hunan.txt"},
	{Key: "CN-JS", Label: "China / Jiangsu", Path: "provinces/jiangsu.txt"},
	{Key: "CN-JX", Label: "China / Jiangxi", Path: "provinces/jiangxi.txt"},
	{Key: "CN-JL", Label: "China / Jilin", Path: "provinces/jilin.txt"},
	{Key: "CN-LN", Label: "China / Liaoning", Path: "provinces/liaoning.txt"},
	{Key: "CN-NM", Label: "China / Inner Mongolia", Path: "provinces/neimenggu.txt"},
	{Key: "CN-NX", Label: "China / Ningxia", Path: "provinces/ningxia.txt"},
	{Key: "CN-QH", Label: "China / Qinghai", Path: "provinces/qinghai.txt"},
	{Key: "CN-SD", Label: "China / Shandong", Path: "provinces/shandong.txt"},
	{Key: "CN-SH", Label: "China / Shanghai", Path: "provinces/shanghai.txt"},
	{Key: "CN-SC", Label: "China / Sichuan", Path: "provinces/sichuan.txt"},
	{Key: "CN-TJ", Label: "China / Tianjin", Path: "provinces/tianjin.txt"},
	{Key: "CN-XJ", Label: "China / Xinjiang", Path: "provinces/xinjiang.txt"},
	{Key: "CN-XZ", Label: "China / Tibet", Path: "provinces/xizang.txt"},
	{Key: "CN-YN", Label: "China / Yunnan", Path: "provinces/yunnan.txt"},
	{Key: "CN-ZJ", Label: "China / Zhejiang", Path: "provinces/zhejiang.txt"},
}

func regionByKey(key string) (Region, bool) {
	key = strings.ToUpper(strings.TrimSpace(key))
	for _, r := range Regions {
		if r.Key == key {
			return r, true
		}
	}
	return Region{}, false
}

func RegionLabel(key string) string {
	if r, ok := regionByKey(key); ok {
		return r.Label
	}
	return ""
}

func splitTokens(raw string) []string {
	raw = strings.NewReplacer("\r", ",", "\n", ",", ";", ",", "\t", ",", " ", ",").Replace(raw)
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func ParseAllow(raw string) ([]netip.Prefix, error) {
	seen := map[string]bool{}
	out := make([]netip.Prefix, 0)
	for _, token := range splitTokens(raw) {
		var p netip.Prefix
		var err error
		if strings.Contains(token, "/") {
			p, err = netip.ParsePrefix(token)
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(token)
			if err == nil {
				bits := 128
				if a.Is4() {
					bits = 32
				}
				p = netip.PrefixFrom(a, bits)
			}
		}
		if err != nil || !p.IsValid() {
			return nil, fmt.Errorf("invalid IP or CIDR %q", token)
		}
		p = p.Masked()
		k := p.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

func NormalizeAllow(raw string) (string, error) {
	prefixes, err := ParseAllow(raw)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if p.Bits() == 32 || p.Bits() == 128 {
			parts = append(parts, p.Addr().String())
		} else {
			parts = append(parts, p.String())
		}
	}
	return strings.Join(parts, ", "), nil
}

type Policy struct {
	Enabled       bool
	Manual        []netip.Prefix
	Deny          []netip.Prefix
	RegionKey     string
	RegionLabel   string
	Region        []netip.Prefix // retained for direct/test policies; loaded region caches use RegionCount + matcher only
	RegionCount   int
	manualMatcher *prefixMatcher
	denyMatcher   *prefixMatcher
	regionMatcher *prefixMatcher
}

type addrInterval struct {
	start netip.Addr
	end   netip.Addr
}

type prefixMatcher struct {
	v4 []addrInterval
	v6 []addrInterval
}

func prefixEnd(p netip.Prefix) netip.Addr {
	p = p.Masked()
	start := p.Addr()
	if start.Is4() {
		b := start.As4()
		n := binary.BigEndian.Uint32(b[:])
		host := 32 - p.Bits()
		var fill uint32
		if host >= 32 {
			fill = ^uint32(0)
		} else if host > 0 {
			fill = (uint32(1) << host) - 1
		}
		n |= fill
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], n)
		return netip.AddrFrom4(out)
	}
	b := start.As16()
	for bit := p.Bits(); bit < 128; bit++ {
		byteIndex := bit / 8
		bitIndex := 7 - uint(bit%8)
		b[byteIndex] |= byte(1 << bitIndex)
	}
	return netip.AddrFrom16(b)
}

func mergeIntervals(in []addrInterval) []addrInterval {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i].start.Compare(in[j].start) < 0 })
	out := make([]addrInterval, 0, len(in))
	cur := in[0]
	for _, next := range in[1:] {
		adjacent := cur.end.Next().IsValid() && cur.end.Next() == next.start
		if next.start.Compare(cur.end) <= 0 || adjacent {
			if next.end.Compare(cur.end) > 0 {
				cur.end = next.end
			}
			continue
		}
		out = append(out, cur)
		cur = next
	}
	return append(out, cur)
}

func newPrefixMatcher(prefixes []netip.Prefix) *prefixMatcher {
	m := &prefixMatcher{}
	for _, p := range prefixes {
		iv := addrInterval{start: p.Masked().Addr(), end: prefixEnd(p)}
		if iv.start.Is4() {
			m.v4 = append(m.v4, iv)
		} else {
			m.v6 = append(m.v6, iv)
		}
	}
	m.v4 = mergeIntervals(m.v4)
	m.v6 = mergeIntervals(m.v6)
	return m
}

func (m *prefixMatcher) Contains(addr netip.Addr) bool {
	if m == nil || !addr.IsValid() {
		return false
	}
	list := m.v6
	if addr.Is4() {
		list = m.v4
	}
	i := sort.Search(len(list), func(i int) bool { return list[i].start.Compare(addr) > 0 })
	if i == 0 {
		return false
	}
	return addr.Compare(list[i-1].end) <= 0
}

type Decision struct {
	Allowed    bool
	Reason     string
	Region     string
	PolicyMode string
}

func (p *Policy) Mode() string {
	if p == nil || !p.Enabled {
		return "disabled"
	}
	if strings.TrimSpace(p.RegionKey) != "" {
		return "region"
	}
	return "manual"
}

func (p *Policy) Evaluate(addr netip.Addr) Decision {
	if addr.IsValid() {
		addr = addr.Unmap()
	}
	if p == nil {
		return Decision{Allowed: true, Reason: "disabled", PolicyMode: "disabled"}
	}
	mode := p.Mode()
	if !addr.IsValid() {
		if p.Enabled {
			return Decision{Allowed: false, Reason: "invalid-source", PolicyMode: mode}
		}
		return Decision{Allowed: true, Reason: "disabled", PolicyMode: mode}
	}
	// Explicit deny is the highest-priority override, including No Restriction
	// mode. This is what makes the Access Management "Deny Access" action
	// meaningful for an otherwise unrestricted source.
	if p.denyMatcher != nil {
		if p.denyMatcher.Contains(addr) {
			return Decision{Allowed: false, Reason: "manual-deny", PolicyMode: mode}
		}
	} else {
		for _, prefix := range p.Deny {
			if prefix.Contains(addr) {
				return Decision{Allowed: false, Reason: "manual-deny", PolicyMode: mode}
			}
		}
	}
	if !p.Enabled {
		return Decision{Allowed: true, Reason: "disabled", PolicyMode: mode}
	}
	if p.manualMatcher != nil {
		if p.manualMatcher.Contains(addr) {
			return Decision{Allowed: true, Reason: "ip", PolicyMode: mode}
		}
	} else {
		for _, prefix := range p.Manual {
			if prefix.Contains(addr) {
				return Decision{Allowed: true, Reason: "ip", PolicyMode: mode}
			}
		}
	}
	if p.regionMatcher != nil {
		if p.regionMatcher.Contains(addr) {
			return Decision{Allowed: true, Reason: "region", Region: p.RegionLabel, PolicyMode: mode}
		}
	} else {
		for _, prefix := range p.Region {
			if prefix.Contains(addr) {
				return Decision{Allowed: true, Reason: "region", Region: p.RegionLabel, PolicyMode: mode}
			}
		}
	}
	return Decision{Allowed: false, Reason: "denied", PolicyMode: mode}
}

func cachePath(homeDir, key string) string {
	return filepath.Join(homeDir, "access", "regions", strings.ToUpper(strings.TrimSpace(key))+".cidr")
}

// parsedRegionCache keeps one immutable parse+matcher snapshot per region file
// fingerprint. Access status, policy load and daemon refresh paths often touch
// the same validated CIDR file back-to-back; reparsing and rebuilding the same
// matcher is pure duplicate work. The cache is process-local only: CLI calls
// remain isolated, while the long-lived daemon benefits across reload cycles.
type parsedRegionCache struct {
	size     int64
	modNano  int64
	info     os.FileInfo
	prefixes []netip.Prefix
	v4       int
	v6       int
	matcher  *prefixMatcher
}

var regionParseCache = struct {
	sync.Mutex
	byPath map[string]parsedRegionCache
}{byPath: make(map[string]parsedRegionCache)}

func invalidateRegionParseCache(path string) {
	regionParseCache.Lock()
	delete(regionParseCache.byPath, path)
	regionParseCache.Unlock()
}

func loadParsedRegionFile(path string) (parsedRegionCache, error) {
	for attempt := 0; attempt < 2; attempt++ {
		st, err := os.Stat(path)
		if err != nil {
			invalidateRegionParseCache(path)
			return parsedRegionCache{}, err
		}
		size, modNano := st.Size(), st.ModTime().UnixNano()

		regionParseCache.Lock()
		if cached, ok := regionParseCache.byPath[path]; ok {
			if cached.size == size && cached.modNano == modNano && cached.info != nil && os.SameFile(cached.info, st) {
				regionParseCache.Unlock()
				return cached, nil
			}
			delete(regionParseCache.byPath, path)
		}
		regionParseCache.Unlock()

		f, err := os.Open(path)
		if err != nil {
			return parsedRegionCache{}, err
		}
		prefixes, v4, v6, parseErr := parsePrefixReader(f)
		_ = f.Close()
		if parseErr != nil {
			return parsedRegionCache{}, parseErr
		}

		// Re-stat after parsing. Atomic cache replacement can occur while the old
		// inode is still open; never publish a parse under the new file's fingerprint.
		after, statErr := os.Stat(path)
		if statErr != nil {
			return parsedRegionCache{}, statErr
		}
		if after.Size() != size || after.ModTime().UnixNano() != modNano || !os.SameFile(st, after) {
			invalidateRegionParseCache(path)
			continue
		}

		parsed := parsedRegionCache{
			size: size, modNano: modNano, info: after,
			prefixes: prefixes, v4: v4, v6: v6,
			matcher: newPrefixMatcher(prefixes),
		}
		regionParseCache.Lock()
		regionParseCache.byPath[path] = parsed
		regionParseCache.Unlock()
		return parsed, nil
	}
	return parsedRegionCache{}, errors.New("region cache changed repeatedly while parsing")
}

func readPrefixFile(path string) ([]netip.Prefix, int, int, error) {
	parsed, err := loadParsedRegionFile(path)
	if err != nil {
		return nil, 0, 0, err
	}
	return parsed.prefixes, parsed.v4, parsed.v6, nil
}

func parsePrefixReader(r io.Reader) ([]netip.Prefix, int, int, error) {
	limited := &io.LimitedReader{R: r, N: maxRegionBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	seen := map[string]bool{}
	prefixes := make([]netip.Prefix, 0, 1024)
	v4, v6 := 0, 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		token := fields[0]
		p, err := netip.ParsePrefix(token)
		if err != nil || !p.IsValid() {
			return nil, 0, 0, fmt.Errorf("invalid region CIDR %q", token)
		}
		p = p.Masked()
		k := p.String()
		if seen[k] {
			continue
		}
		seen[k] = true
		prefixes = append(prefixes, p)
		if p.Addr().Is4() {
			v4++
		} else {
			v6++
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, 0, err
	}
	if limited.N <= 0 {
		return nil, 0, 0, fmt.Errorf("region list exceeds %d bytes", maxRegionBytes)
	}
	if len(prefixes) == 0 {
		return nil, 0, 0, errors.New("region list is empty")
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
	return prefixes, v4, v6, nil
}

func LoadPolicy(main config.Main, homeDir string) (*Policy, error) {
	manual, err := ParseAllow(main.AccessAllow)
	if err != nil {
		return nil, err
	}
	deny, err := ParseAllow(main.AccessDeny)
	if err != nil {
		return nil, err
	}
	p := &Policy{Enabled: main.AccessEnabled, Manual: manual, Deny: deny, RegionKey: strings.ToUpper(strings.TrimSpace(main.AccessRegion)), manualMatcher: newPrefixMatcher(manual), denyMatcher: newPrefixMatcher(deny)}
	if !p.Enabled {
		return p, nil
	}
	if p.RegionKey != "" {
		region, ok := regionByKey(p.RegionKey)
		if !ok {
			return nil, fmt.Errorf("unsupported access region %q", p.RegionKey)
		}
		parsed, err := loadParsedRegionFile(cachePath(homeDir, p.RegionKey))
		if err != nil {
			return nil, fmt.Errorf("load access region %s: %w", p.RegionKey, err)
		}
		if parsed.v4 == 0 || parsed.v6 == 0 {
			return nil, fmt.Errorf("access region %s does not contain both IPv4 and IPv6 ranges", p.RegionKey)
		}
		p.RegionCount = len(parsed.prefixes)
		p.RegionLabel = region.Label
		p.regionMatcher = parsed.matcher
	}
	return p, nil
}

func ClientAddr(remoteAddr string) (netip.Addr, error) {
	host := strings.TrimSpace(remoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if zone := strings.LastIndexByte(host, '%'); zone > 0 {
		host = host[:zone]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap(), nil
}

type UpdateReport struct {
	APIVersion int    `json:"api_version"`
	OK         bool   `json:"ok"`
	Phase      string `json:"phase"`
	Region     string `json:"region"`
	Label      string `json:"label,omitempty"`
	IPv4       int    `json:"ipv4,omitempty"`
	IPv6       int    `json:"ipv6,omitempty"`
	Source     string `json:"source,omitempty"`
	Error      string `json:"error,omitempty"`
	Warning    string `json:"warning,omitempty"`
}

func sourceURLs(path string) []string {
	return []string{
		"https://ftp.apnic.net/stats/apnic/delegated-apnic-latest",
		"https://ftp.ripe.net/pub/stats/apnic/delegated-apnic-latest",
	}
}

// These indirections keep production behavior fixed while allowing deterministic
// region refresh tests without depending on the public Internet.
var accessRegionSourceURLs = sourceURLs
var accessRegionHTTPClient = func() *http.Client {
	return &http.Client{Timeout: 25 * time.Second}
}

func writeRegionCache(path string, region Region, source string, prefixes []netip.Prefix) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	w := bufio.NewWriter(f)
	if _, err := fmt.Fprintf(w, "# HomeGate access region cache\n# region=%s\n# source=%s\n# updated=%s\n", region.Key, source, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	for _, prefix := range prefixes {
		if _, err := fmt.Fprintln(w, prefix.String()); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// The file is replaced atomically, so drop any process-local parse snapshot
	// immediately even if a filesystem happens to preserve size/mtime granularity.
	invalidateRegionParseCache(path)
	ok = true
	return nil
}

func updateRegion(ctx context.Context, homeDir, key string, force bool) (UpdateReport, error) {
	region, ok := regionByKey(key)
	if !ok || region.Key != "CN" {
		err := fmt.Errorf("unsupported access region %q", key)
		return UpdateReport{APIVersion: 1, OK: false, Phase: "access", Region: key, Error: err.Error()}, err
	}
	path := cachePath(homeDir, region.Key)
	var cachedPrefixes []netip.Prefix
	var cachedV4, cachedV6 int
	if prefixes, v4, v6, err := readPrefixFile(path); err == nil && v4 > 0 && v6 > 0 {
		cachedPrefixes, cachedV4, cachedV6 = prefixes, v4, v6
		if !force {
			if st, statErr := os.Stat(path); statErr == nil && time.Since(st.ModTime()) <= regionRefreshAge {
				return UpdateReport{APIVersion: 1, OK: true, Phase: "access", Region: region.Key, Label: region.Label, IPv4: v4, IPv6: v6, Source: "cache"}, nil
			}
		}
	}
	client := accessRegionHTTPClient()
	var lastErr error
	for _, source := range accessRegionSourceURLs(region.Path) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "HomeGate access-region-updater")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		prefixes, v4, v6, parseErr := parseDelegatedChina(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		if v4 == 0 || v6 == 0 {
			lastErr = fmt.Errorf("downloaded region list is not dual-stack (ipv4=%d ipv6=%d)", v4, v6)
			continue
		}
		if err := writeRegionCache(path, region, source, prefixes); err != nil {
			lastErr = err
			continue
		}
		return UpdateReport{APIVersion: 1, OK: true, Phase: "access", Region: region.Key, Label: region.Label, IPv4: v4, IPv6: v6, Source: source}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("unable to download region list")
	}
	if len(cachedPrefixes) > 0 && cachedV4 > 0 && cachedV6 > 0 {
		return UpdateReport{APIVersion: 1, OK: true, Phase: "access", Region: region.Key, Label: region.Label, IPv4: cachedV4, IPv6: cachedV6, Source: "stale-cache", Warning: lastErr.Error()}, nil
	}
	r := UpdateReport{APIVersion: 1, OK: false, Phase: "access", Region: region.Key, Label: region.Label, Error: lastErr.Error()}
	return r, lastErr
}

// UpdateRegion refreshes a selected region only when its validated cache is stale.
func UpdateRegion(ctx context.Context, homeDir, key string) (UpdateReport, error) {
	return updateRegion(ctx, homeDir, key, false)
}

// RefreshRegion forces an upstream refresh while keeping the last validated
// dual-stack cache as a safe fallback if the download fails.
func RefreshRegion(ctx context.Context, homeDir, key string) (UpdateReport, error) {
	report, err := updateRegion(ctx, homeDir, key, true)
	if err == nil && report.Warning != "" {
		return report, errors.New(report.Warning)
	}
	return report, err
}

type Status struct {
	APIVersion     int    `json:"api_version"`
	OK             bool   `json:"ok"`
	Phase          string `json:"phase"`
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode"`
	ManualPrefixes int    `json:"manual_prefixes"`
	DenyPrefixes   int    `json:"deny_prefixes"`
	Region         string `json:"region,omitempty"`
	RetiredRegion  string `json:"retired_region,omitempty"`
	RegionLabel    string `json:"region_label,omitempty"`
	RegionPrefixes int    `json:"region_prefixes,omitempty"`
	CacheValid     bool   `json:"cache_valid"`
	CacheUpdated   string `json:"cache_updated,omitempty"`
	CacheStale     bool   `json:"cache_stale"`
	CacheIPv4      int    `json:"cache_ipv4,omitempty"`
	CacheIPv6      int    `json:"cache_ipv6,omitempty"`
	Error          string `json:"error,omitempty"`
}

type regionCacheStatus struct {
	valid    bool
	updated  time.Time
	stale    bool
	ipv4     int
	ipv6     int
	prefixes int
}

func inspectRegionCache(homeDir, key string) regionCacheStatus {
	key = strings.ToUpper(strings.TrimSpace(key))
	if key == "" {
		return regionCacheStatus{}
	}
	prefixes, v4, v6, err := readPrefixFile(cachePath(homeDir, key))
	if err != nil || v4 == 0 || v6 == 0 {
		return regionCacheStatus{}
	}
	st, err := os.Stat(cachePath(homeDir, key))
	if err != nil {
		return regionCacheStatus{}
	}
	return regionCacheStatus{
		valid:    true,
		updated:  st.ModTime().UTC(),
		stale:    time.Since(st.ModTime()) > regionRefreshAge,
		ipv4:     v4,
		ipv6:     v6,
		prefixes: len(prefixes),
	}
}

func accessMode(main config.Main) string {
	if !main.AccessEnabled {
		return "disabled"
	}
	if strings.TrimSpace(main.AccessRegion) != "" {
		return "region"
	}
	return "manual"
}

func BuildStatus(main config.Main, homeDir string) Status {
	regionKey := strings.ToUpper(strings.TrimSpace(main.AccessRegion))
	cache := inspectRegionCache(homeDir, regionKey)
	status := Status{
		APIVersion:     1,
		Phase:          "access",
		Enabled:        main.AccessEnabled,
		Mode:           accessMode(main),
		Region:         regionKey,
		RetiredRegion:  main.RetiredAccessRegion,
		RegionLabel:    RegionLabel(regionKey),
		CacheValid:     cache.valid,
		CacheStale:     cache.stale,
		CacheIPv4:      cache.ipv4,
		CacheIPv6:      cache.ipv6,
		RegionPrefixes: cache.prefixes,
	}
	if cache.valid {
		status.CacheUpdated = cache.updated.Format(time.RFC3339)
	}
	p, err := LoadPolicy(main, homeDir)
	if err != nil {
		status.OK = false
		status.Error = err.Error()
		if manual, parseErr := ParseAllow(main.AccessAllow); parseErr == nil {
			status.ManualPrefixes = len(manual)
		}
		if deny, parseErr := ParseAllow(main.AccessDeny); parseErr == nil {
			status.DenyPrefixes = len(deny)
		}
		return status
	}
	status.OK = true
	status.Enabled = p.Enabled
	status.ManualPrefixes = len(p.Manual)
	status.DenyPrefixes = len(p.Deny)
	if p.RegionLabel != "" {
		status.RegionLabel = p.RegionLabel
	}
	if p.RegionCount > 0 {
		status.RegionPrefixes = p.RegionCount
	} else if len(p.Region) > 0 {
		status.RegionPrefixes = len(p.Region)
	}
	return status
}

type Event struct {
	Time              string `json:"time"`
	IP                string `json:"ip"`
	Host              string `json:"host"`
	Allowed           bool   `json:"allowed"`
	Reason            string `json:"reason"`
	Region            string `json:"region,omitempty"`
	PolicyMode        string `json:"policy_mode,omitempty"`
	Geo               string `json:"geo,omitempty"`
	CurrentAllowed    *bool  `json:"current_allowed,omitempty"`
	CurrentReason     string `json:"current_reason,omitempty"`
	CurrentRegion     string `json:"current_region,omitempty"`
	CurrentPolicyMode string `json:"current_policy_mode,omitempty"`
	Count             int    `json:"count"`
}

type RecentReport struct {
	APIVersion int     `json:"api_version"`
	OK         bool    `json:"ok"`
	Phase      string  `json:"phase"`
	Entries    []Event `json:"entries"`
	Error      string  `json:"error,omitempty"`
}

func eventKey(event Event) string {
	return strings.ToLower(strings.TrimSpace(event.IP)) + "\x00" + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(event.Host), "."))
}

func eventTime(event Event) time.Time {
	t, _ := time.Parse(time.RFC3339, event.Time)
	return t
}

// summarizeEvents turns the runtime stream into one current observation per
// source IP + host. access.json is an operational recent-source snapshot, not
// an audit log; keeping only the latest state avoids duplicate IPv6 rows while
// preserving a cumulative request count for diagnostics.
func summarizeEvents(in []Event, limit int) []Event {
	if limit <= 0 {
		limit = defaultRecentLimit
	}
	byKey := map[string]Event{}
	for _, event := range in {
		event.Host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(event.Host), "."))
		if event.Count <= 0 {
			event.Count = 1
		}
		key := eventKey(event)
		if previous, ok := byKey[key]; ok {
			total := previous.Count + event.Count
			if eventTime(previous).After(eventTime(event)) {
				previous.Count = total
				byKey[key] = previous
			} else {
				event.Count = total
				byKey[key] = event
			}
			continue
		}
		byKey[key] = event
	}
	out := make([]Event, 0, len(byKey))
	for _, event := range byKey {
		out = append(out, event)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := eventTime(out[i]), eventTime(out[j])
		if ti.Equal(tj) {
			return eventKey(out[i]) < eventKey(out[j])
		}
		return ti.Before(tj)
	})
	if len(out) > limit {
		out = append([]Event(nil), out[len(out)-limit:]...)
	}
	return out
}

type GeoResolver struct {
	chinaValid bool
	china      *prefixMatcher
	provinces  []struct {
		key     string
		matcher *prefixMatcher
	}
}

// GeoFingerprint is deliberately metadata-only. It lets the long-lived daemon
// notice region-cache changes without reparsing CIDR files on every Access UI
// request. The expensive parsing happens only when this fingerprint changes.
func GeoFingerprint(homeDir string) string {
	parts := make([]string, 0, len(Regions))
	for _, region := range Regions {
		path := cachePath(homeDir, region.Key)
		st, err := os.Stat(path)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d:%d", region.Key, st.Size(), st.ModTime().UnixNano()))
	}
	return strings.Join(parts, "|")
}

func LoadGeoResolver(homeDir string) *GeoResolver {
	g := &GeoResolver{}
	for _, region := range Regions {
		path := cachePath(homeDir, region.Key)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		parsed, err := loadParsedRegionFile(path)
		if err != nil || parsed.v4 == 0 || parsed.v6 == 0 {
			continue
		}
		if region.Key == "CN" {
			g.chinaValid = true
			g.china = parsed.matcher
			continue
		}
		g.provinces = append(g.provinces, struct {
			key     string
			matcher *prefixMatcher
		}{key: region.Key, matcher: parsed.matcher})
	}
	return g
}

func (g *GeoResolver) Lookup(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.IsValid() {
		return "UNKNOWN"
	}
	addr = addr.Unmap()
	for _, province := range g.provinces {
		if province.matcher.Contains(addr) {
			return province.key
		}
	}
	if g.chinaValid {
		if g.china.Contains(addr) {
			return "CN"
		}
		return "FOREIGN"
	}
	return "UNKNOWN"
}

func AnnotateRecentGeo(report RecentReport, homeDir string) RecentReport {
	if !report.OK || len(report.Entries) == 0 {
		return report
	}
	geo := LoadGeoResolver(homeDir)
	for i := range report.Entries {
		report.Entries[i].Geo = geo.Lookup(report.Entries[i].IP)
	}
	return report
}

// AnnotateRecentCurrent evaluates each observed source against the currently
// loaded policy. The historical event fields remain untouched; current_* is
// explicitly a management-state view used by LuCI.
func AnnotateRecentCurrent(report RecentReport, p *Policy) RecentReport {
	if !report.OK || p == nil {
		return report
	}
	for i := range report.Entries {
		addr, err := netip.ParseAddr(strings.TrimSpace(report.Entries[i].IP))
		if err != nil || !addr.IsValid() {
			continue
		}
		d := p.Evaluate(addr.Unmap())
		allowed := d.Allowed
		report.Entries[i].CurrentAllowed = &allowed
		report.Entries[i].CurrentReason = d.Reason
		report.Entries[i].CurrentRegion = d.Region
		report.Entries[i].CurrentPolicyMode = d.PolicyMode
	}
	return report
}

type Recorder struct {
	mu         sync.Mutex
	Path       string
	Limit      int
	loaded     bool
	fileInfo   os.FileInfo
	events     []Event
	geo        *GeoResolver
	dirty      bool
	flushTimer *time.Timer
	flushDelay time.Duration
}

func resolveRecentPath(path string) string {
	if strings.TrimSpace(path) != "" {
		return path
	}
	if env := strings.TrimSpace(os.Getenv("HOMEGATE_ACCESS_RECENT")); env != "" {
		return env
	}
	return DefaultRecentPath
}

func NewRecorder(path string) *Recorder {
	return &Recorder{Path: resolveRecentPath(path), Limit: defaultRecentLimit, flushDelay: recorderFlushDelay}
}

func recentFileInfoEqual(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func lockRecentFile(path string) (func(), error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "."+filepath.Base(path)+".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// loadLocked refreshes the bounded in-memory recorder snapshot when another
// HomeGate process atomically replaced access.json (for example LuCI/CLI clear).
// The file identity check keeps the request path from reparsing JSON unless the
// on-disk snapshot actually changed. Callers that mutate recent state hold the
// sidecar flock, so the refresh and following atomic replacement are one
// cross-process read/modify/write transaction.
func (r *Recorder) loadLocked() bool {
	info, statErr := os.Stat(r.Path)
	if r.loaded {
		switch {
		case statErr == nil && recentFileInfoEqual(r.fileInfo, info):
			return false
		case errors.Is(statErr, os.ErrNotExist) && r.fileInfo == nil:
			return false
		}
	}
	wasLoaded := r.loaded
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			r.loaded = true
			r.fileInfo = nil
			r.events = nil
			return wasLoaded
		}
		return false
	}
	b, err := os.ReadFile(r.Path)
	if err != nil {
		return false
	}
	var report RecentReport
	if err := json.Unmarshal(b, &report); err != nil {
		return false
	}
	r.events = summarizeEvents(report.Entries, r.Limit)
	r.fileInfo = info
	r.loaded = true
	return wasLoaded
}

func (r *Recorder) cancelFlushTimerLocked() {
	if r.flushTimer == nil {
		return
	}
	r.flushTimer.Stop()
	r.flushTimer = nil
}

func (r *Recorder) scheduleFlushLocked() {
	r.dirty = true
	if r.flushTimer != nil {
		return
	}
	delay := r.flushDelay
	if delay <= 0 {
		delay = recorderFlushDelay
	}
	r.flushTimer = time.AfterFunc(delay, r.flushPending)
}

func (r *Recorder) flushPending() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.flushTimer = nil
	r.flushLocked()
	r.mu.Unlock()
}

func (r *Recorder) flushLocked() {
	if !r.dirty {
		return
	}
	unlock := r.lockFileLocked()
	defer unlock()
	if r.loadLocked() {
		// An external clear/replacement wins over unflushed duplicate-count
		// updates so an old daemon snapshot can never resurrect removed rows.
		r.dirty = false
		return
	}
	if r.writeLocked() {
		r.dirty = false
	}
}

// Flush persists any coalesced duplicate-count updates immediately. It is
// primarily used at lifecycle boundaries and in tests; ordinary request traffic
// is flushed automatically after a short bounded delay.
func (r *Recorder) Flush() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.cancelFlushTimerLocked()
	r.flushLocked()
	r.mu.Unlock()
}

func (r *Recorder) lockFileLocked() func() {
	unlock, err := lockRecentFile(r.Path)
	if err != nil {
		// Recent recording is intentionally best-effort. If the sidecar lock cannot
		// be opened, preserve the historical behavior instead of failing requests.
		return func() {}
	}
	return unlock
}

func applyCurrent(event *Event, d Decision) {
	allowed := d.Allowed
	event.CurrentAllowed = &allowed
	event.CurrentReason = d.Reason
	event.CurrentRegion = d.Region
	event.CurrentPolicyMode = d.PolicyMode
}

// SetGeoResolver attaches an already-built immutable resolver and backfills
// existing recent-source rows in one bounded pass. The resolver is built by
// the daemon outside request handling, so Record() never performs CIDR I/O.
func (r *Recorder) SetGeoResolver(g *GeoResolver) {
	if r == nil || g == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	unlock := r.lockFileLocked()
	defer unlock()
	r.loadLocked()
	r.geo = g
	changed := false
	for i := range r.events {
		geo := g.Lookup(r.events[i].IP)
		if r.events[i].Geo != geo {
			r.events[i].Geo = geo
			changed = true
		}
	}
	if changed {
		_ = r.writeLocked()
	}
}

// ReevaluateCurrent updates only the management-state current_* fields using
// the policy already loaded by the long-lived proxy. This keeps access-recent
// a cheap runtime-file read even in region mode.
func (r *Recorder) ReevaluateCurrent(p *Policy) {
	if r == nil || p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	unlock := r.lockFileLocked()
	defer unlock()
	r.loadLocked()
	changed := false
	for i := range r.events {
		addr, err := netip.ParseAddr(strings.TrimSpace(r.events[i].IP))
		if err != nil || !addr.IsValid() {
			continue
		}
		d := p.Evaluate(addr.Unmap())
		beforeAllowed := r.events[i].CurrentAllowed
		beforeReason := r.events[i].CurrentReason
		beforeRegion := r.events[i].CurrentRegion
		beforeMode := r.events[i].CurrentPolicyMode
		applyCurrent(&r.events[i], d)
		if beforeAllowed == nil || *beforeAllowed != d.Allowed || beforeReason != d.Reason || beforeRegion != d.Region || beforeMode != d.PolicyMode {
			changed = true
		}
	}
	if changed {
		_ = r.writeLocked()
	}
}

func (r *Recorder) Record(ip, host string, d Decision) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	unlock := r.lockFileLocked()
	defer unlock()
	if r.loadLocked() {
		// The external snapshot changed while duplicate-count updates were
		// pending. Adopt it before recording this request and cancel the stale
		// timer so a clear operation cannot be undone later.
		r.dirty = false
		r.cancelFlushTimerLocked()
	}
	now := time.Now().UTC()
	ip = strings.TrimSpace(ip)
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	key := strings.ToLower(ip) + "\x00" + host
	count := 1
	matched := false
	stateChanged := false
	kept := make([]Event, 0, len(r.events)+1)
	for _, event := range r.events {
		if eventKey(event) == key {
			matched = true
			if event.Count > 0 {
				count += event.Count
			} else {
				count++
			}
			geo := "UNKNOWN"
			if r.geo != nil {
				geo = r.geo.Lookup(ip)
			}
			stateChanged = event.Allowed != d.Allowed || event.Reason != d.Reason || event.Region != d.Region || event.PolicyMode != d.PolicyMode || event.Geo != geo
			continue
		}
		kept = append(kept, event)
	}
	event := Event{
		Time: now.Format(time.RFC3339), IP: ip, Host: host,
		Allowed: d.Allowed, Reason: d.Reason, Region: d.Region,
		PolicyMode: d.PolicyMode, Count: count, Geo: "UNKNOWN",
	}
	if r.geo != nil {
		event.Geo = r.geo.Lookup(ip)
	}
	applyCurrent(&event, d)
	kept = append(kept, event)
	limit := r.Limit
	if limit <= 0 {
		limit = defaultRecentLimit
	}
	if len(kept) > limit {
		kept = append([]Event(nil), kept[len(kept)-limit:]...)
	}
	r.events = kept

	// New sources and policy-state transitions remain immediately visible.
	// Repeated hits for the same source/host/state only change time/count, so
	// coalesce their fsync+rename churn into a bounded 100ms runtime-file flush.
	if !matched || stateChanged {
		r.cancelFlushTimerLocked()
		r.dirty = false
		if !r.writeLocked() {
			r.scheduleFlushLocked()
		}
		return
	}
	r.scheduleFlushLocked()
}

func (r *Recorder) writeLocked() bool {
	report := RecentReport{APIVersion: 1, OK: true, Phase: "access", Entries: r.events}
	if err := runtimefile.WriteJSONAtomic(r.Path, report, 0o600); err != nil {
		return false
	}
	if info, err := os.Stat(r.Path); err == nil {
		r.fileInfo = info
		r.loaded = true
	}
	return true
}

func writeRecentReport(path string, report RecentReport) error {
	return runtimefile.WriteJSONAtomic(path, report, 0o600)
}

func ReadRecent(path string) RecentReport {
	path = resolveRecentPath(path)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return RecentReport{APIVersion: 1, OK: true, Phase: "access", Entries: []Event{}}
		}
		return RecentReport{APIVersion: 1, OK: false, Phase: "access", Entries: []Event{}, Error: err.Error()}
	}
	var report RecentReport
	if err := json.Unmarshal(b, &report); err != nil {
		return RecentReport{APIVersion: 1, OK: false, Phase: "access", Entries: []Event{}, Error: err.Error()}
	}
	report.APIVersion = 1
	report.Phase = "access"
	if report.Entries == nil {
		report.Entries = []Event{}
	}
	report.Entries = summarizeEvents(report.Entries, defaultRecentLimit)
	return report
}

func ReadRecentWithGeo(path, homeDir string) RecentReport {
	return AnnotateRecentGeo(ReadRecent(path), homeDir)
}

// ClearDeniedRecent removes only denied runtime entries. Allowed observations
// remain available for troubleshooting and exact-allow management.
func ClearDeniedRecent(path string) (RecentReport, error) {
	path = resolveRecentPath(path)
	unlock, err := lockRecentFile(path)
	if err != nil {
		return RecentReport{APIVersion: 1, OK: false, Phase: "access", Entries: []Event{}, Error: err.Error()}, err
	}
	defer unlock()
	report := ReadRecent(path)
	if !report.OK {
		err := errors.New(report.Error)
		if report.Error == "" {
			err = errors.New("unable to read recent access")
		}
		return report, err
	}
	kept := make([]Event, 0, len(report.Entries))
	for _, event := range report.Entries {
		if event.Allowed {
			kept = append(kept, event)
		}
	}
	report.Entries = kept
	if err := writeRecentReport(path, report); err != nil {
		return RecentReport{APIVersion: 1, OK: false, Phase: "access", Entries: []Event{}, Error: err.Error()}, err
	}
	return report, nil
}

// ClearRecent removes all runtime recent-access observations. It never touches
// the persisted access allow list or the selected region policy.
func ClearRecent(path string) (RecentReport, error) {
	path = resolveRecentPath(path)
	unlock, err := lockRecentFile(path)
	if err != nil {
		return RecentReport{APIVersion: 1, OK: false, Phase: "access", Entries: []Event{}, Error: err.Error()}, err
	}
	defer unlock()
	report := RecentReport{APIVersion: 1, OK: true, Phase: "access", Entries: []Event{}}
	if err := writeRecentReport(path, report); err != nil {
		return RecentReport{APIVersion: 1, OK: false, Phase: "access", Entries: []Event{}, Error: err.Error()}, err
	}
	return report, nil
}

// ClearRecentEntry removes one source+host observation from the runtime recent
// source list. It never changes allow/deny policy.
func ClearRecentEntry(path, ip, host string) (RecentReport, error) {
	path = resolveRecentPath(path)
	unlock, lockErr := lockRecentFile(path)
	if lockErr != nil {
		return RecentReport{APIVersion: 1, OK: false, Phase: "access", Entries: []Event{}, Error: lockErr.Error()}, lockErr
	}
	defer unlock()
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.IsValid() {
		return RecentReport{APIVersion: 1, OK: false, Phase: "access", Entries: []Event{}, Error: "invalid access source IP"}, errors.New("invalid access source IP")
	}
	ip = addr.Unmap().String()
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || strings.ContainsAny(host, "\r\n\t ") {
		return RecentReport{APIVersion: 1, OK: false, Phase: "access", Entries: []Event{}, Error: "invalid access source host"}, errors.New("invalid access source host")
	}
	report := ReadRecent(path)
	if !report.OK {
		err := errors.New(report.Error)
		if report.Error == "" {
			err = errors.New("unable to read recent access")
		}
		return report, err
	}
	needle := eventKey(Event{IP: ip, Host: host})
	kept := make([]Event, 0, len(report.Entries))
	for _, event := range report.Entries {
		if eventKey(event) != needle {
			kept = append(kept, event)
		}
	}
	report.Entries = kept
	if err := writeRecentReport(path, report); err != nil {
		return RecentReport{APIVersion: 1, OK: false, Phase: "access", Entries: []Event{}, Error: err.Error()}, err
	}
	return report, nil
}
