package main

// Platform independent logic: what is protected (TCP ports, UDP ports and
// programs), which countries may connect, the country lists, and the
// operations the window calls. The PowerShell scripts are in scripts.go,
// reading the firewall state in status.go.
//
// Where the state lives: the chosen ports/programs and countries in
// data\ports.txt and data\countries.txt next to the program; everything else
// (which old rules this program switched off, the result of the last list
// update, the countries the monthly update downloads ...) is kept as
// [TAG=value] pieces in the Description of the first rule of each rule set
// ("CountryIPFilter-TCP-01" ...). So moving or copying the program never
// loses anything, and the monthly update (a PowerShell script stored inside
// the scheduled task, run as SYSTEM) never has to run or write anything in
// the program folder.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	AppName    = "Country IP Filter"
	RuleGroup  = "Country IP Filter"
	RulePrefix = "CountryIPFilter-"
	TaskName   = "Country IP Filter Update"
	// version 3 of this program ("Iran IP Filter") used these names
	OldGroup = "Iran IP Filter"
	OldTask  = "Iran IP Filter Update"

	ripeBase    = "https://stat.ripe.net/data/country-resource-list/data.json?v4_format=prefix&resource="
	chunkSize   = 400
	maxAddr     = 3_000_000_000 // more than any group of countries has (the whole IPv4 space is 4.3 billion)
	maxDownload = 64 << 20
	ruleDesc    = "Country IP Filter: opens the listed ports or programs only for IP ranges of the chosen countries. Managed by CountryIPFilter.exe - do not edit."

	SourceDownload = "download"
	SourceFile     = "file"
)

// RipeURL: the list of one country (all regional registries, not only RIPE).
func RipeURL(cc string) string { return ripeBase + cc }

// Runner runs a PowerShell script and returns everything it printed.
type Runner func(name, script string) (string, error)

type Core struct {
	Dir    string // the "data" folder next to the program
	ExeDir string // folder of the running exe
	Run    Runner
	HTTP   *http.Client
	Log    func(string)
}

func (c *Core) logf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	c.fileLog(msg)
	if c.Log != nil {
		c.Log(msg)
	}
}

// fileLog appends to log.txt (kept below ~1 MB).
func (c *Core) fileLog(msg string) {
	p := filepath.Join(c.Dir, "log.txt")
	if st, err := os.Stat(p); err == nil && st.Size() > 1<<20 {
		os.Remove(p + ".old")
		os.Rename(p, p+".old")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	msg = strings.NewReplacer("\u202A", "", "\u202C", "", "\r", " ", "\n", " ").Replace(msg)
	fmt.Fprintf(f, "%s  %s\r\n", time.Now().Format("2006-01-02 15:04:05"), msg)
}

// ---------------------------------------------------------------- what is protected

const (
	KindTCP = "TCP"
	KindUDP = "UDP"
	KindApp = "APP"
)

// Entry is one thing that is opened only for the chosen countries: a TCP
// port, a UDP port, or a program (on every port it uses).
type Entry struct {
	Kind string
	Port int
	Path string
}

func TCP(p int) Entry { return Entry{Kind: KindTCP, Port: p} }
func UDP(p int) Entry { return Entry{Kind: KindUDP, Port: p} }
func AppEntry(p string) Entry {
	return Entry{Kind: KindApp, Path: strings.TrimSpace(p)}
}

// Key identifies the entry. A TCP port is just its number (as in version 3,
// so the records of rules switched off by version 3 still match).
func (e Entry) Key() string {
	switch e.Kind {
	case KindUDP:
		return "udp:" + strconv.Itoa(e.Port)
	case KindApp:
		return "app:" + strings.ToLower(normPath(e.Path))
	}
	return strconv.Itoa(e.Port)
}

// line: how the entry is written in ports.txt.
func (e Entry) line() string {
	switch e.Kind {
	case KindUDP:
		return "UDP " + strconv.Itoa(e.Port)
	case KindApp:
		return "APP " + e.Path
	}
	return "TCP " + strconv.Itoa(e.Port)
}

// Label: the first column of the table ("TCP 808", "UDP 1194", "Program").
func (e Entry) Label() string {
	if e.Kind == KindApp {
		return T("برنامه")
	}
	return e.Kind + " " + strconv.Itoa(e.Port)
}

// Short: the entry inside a sentence ("808", "UDP 1194", "RevitServer.exe").
func (e Entry) Short() string {
	switch e.Kind {
	case KindUDP:
		return ltr("UDP " + strconv.Itoa(e.Port))
	case KindApp:
		return ltr(baseName(e.Path))
	}
	return strconv.Itoa(e.Port)
}

// ParseEntry reads "808", "TCP 808", "udp 53" or "APP C:\path\app.exe".
func ParseEntry(s string) (Entry, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "\uFEFF"))
	if s == "" {
		return Entry{}, false
	}
	kind, rest := KindTCP, s
	if f := strings.Fields(s); len(f) > 0 {
		switch strings.ToUpper(f[0]) {
		case "TCP", "UDP":
			kind = strings.ToUpper(f[0])
			rest = strings.TrimSpace(s[len(f[0]):])
		case "APP":
			p := strings.TrimSpace(s[len(f[0]):])
			if p == "" {
				return Entry{}, false
			}
			return AppEntry(p), true
		}
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != rest {
		return Entry{}, false
	}
	return Entry{Kind: kind, Port: n}, true
}

// sortEntries: TCP ports, then UDP ports, then programs; no duplicates.
func sortEntries(in []Entry) []Entry {
	seen := map[string]bool{}
	var out []Entry
	for _, e := range in {
		if k := e.Key(); !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	rank := map[string]int{KindTCP: 0, KindUDP: 1, KindApp: 2}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Kind != b.Kind {
			return rank[a.Kind] < rank[b.Kind]
		}
		if a.Kind == KindApp {
			return strings.ToLower(a.Path) < strings.ToLower(b.Path)
		}
		return a.Port < b.Port
	})
	return out
}

func entryKeys(list []Entry) []string {
	var out []string
	for _, e := range list {
		out = append(out, e.Key())
	}
	return out
}

func hasEntry(list []Entry, key string) bool {
	for _, e := range list {
		if e.Key() == key {
			return true
		}
	}
	return false
}

// portsOf: the ports of one protocol.
func portsOf(list []Entry, kind string) []int {
	var out []int
	for _, e := range list {
		if e.Kind == kind {
			out = append(out, e.Port)
		}
	}
	return uniqInts(out)
}

func appsOf(list []Entry) []Entry {
	var out []Entry
	for _, e := range list {
		if e.Kind == KindApp {
			out = append(out, e)
		}
	}
	return out
}

// normPath: %SystemRoot% and friends expanded, backslashes.
func normPath(p string) string {
	p = strings.TrimSpace(strings.Trim(strings.TrimSpace(p), `"`))
	p = envRe.ReplaceAllStringFunc(p, func(m string) string {
		if v := os.Getenv(m[1 : len(m)-1]); v != "" {
			return v
		}
		switch strings.ToLower(m) {
		case "%systemroot%", "%windir%":
			return `C:\Windows`
		case "%programfiles%":
			return `C:\Program Files`
		case "%systemdrive%":
			return `C:`
		}
		return m
	})
	return strings.ReplaceAll(p, "/", `\`)
}

var envRe = regexp.MustCompile(`%[A-Za-z0-9_()]+%`)

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.EqualFold(normPath(a), normPath(b))
}

func (c *Core) portsPath() string     { return filepath.Join(c.Dir, "ports.txt") }
func (c *Core) countriesPath() string { return filepath.Join(c.Dir, "countries.txt") }

func (c *Core) HasPortsFile() bool {
	_, err := os.Stat(c.portsPath())
	return err == nil
}

func (c *Core) HasCountriesFile() bool {
	_, err := os.Stat(c.countriesPath())
	return err == nil
}

// LoadEntries: the ports and programs to protect (version 3 wrote one port
// number per line, which still reads as TCP).
func (c *Core) LoadEntries() []Entry {
	b, _ := os.ReadFile(c.portsPath())
	var out []Entry
	for _, l := range strings.Split(strings.TrimPrefix(string(b), "\uFEFF"), "\n") {
		if e, ok := ParseEntry(l); ok {
			out = append(out, e)
		}
	}
	return sortEntries(out)
}

func (c *Core) SaveEntries(list []Entry) error {
	var lines []string
	for _, e := range sortEntries(list) {
		lines = append(lines, e.line())
	}
	return writeFileAtomic(c.portsPath(), []byte(strings.Join(lines, "\r\n")+"\r\n"))
}

// LoadCountries: the chosen country codes, sorted.
func (c *Core) LoadCountries() []string {
	b, _ := os.ReadFile(c.countriesPath())
	return cleanCountries(strings.Fields(strings.TrimPrefix(string(b), "\uFEFF")))
}

func (c *Core) SaveCountries(list []string) error {
	return writeFileAtomic(c.countriesPath(), []byte(strings.Join(cleanCountries(list), "\r\n")+"\r\n"))
}

// cleanCountries keeps known codes, upper case, sorted, once each.
func cleanCountries(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		x = strings.ToUpper(strings.TrimSpace(x))
		if _, ok := countryByCode(x); ok && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func countryByCode(code string) (Country, bool) {
	i := sort.Search(len(countries), func(i int) bool { return countries[i].Code >= code })
	if i < len(countries) && countries[i].Code == code {
		return countries[i], true
	}
	return Country{}, false
}

// CountryName in the window's language.
func CountryName(code string) string {
	c, ok := countryByCode(code)
	if !ok {
		return code
	}
	if lang == "en" {
		return c.EN
	}
	return c.FA
}

// countryLabel: "Iran (IR)".
func countryLabel(code string) string { return CountryName(code) + " (" + ltr(code) + ")" }

// countryLabelPlain: "Iran (IR)" for the list boxes (no direction marks).
func countryLabelPlain(code string) string { return CountryName(code) + " (" + code + ")" }

// countriesText: the chosen countries inside a sentence.
func countriesText(codes []string) string {
	if len(codes) == 0 {
		return T("هیچ کشوری")
	}
	var names []string
	for i, c := range codes {
		if i == 4 && len(codes) > 5 {
			names = append(names, T("و %d کشور دیگر", len(codes)-4))
			break
		}
		names = append(names, CountryName(c))
	}
	return strings.Join(names, listSep())
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func uniqInts(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, n := range in {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ---------------------------------------------------------------- rules turned off by this program

// OffRule is a rule this program switched off, with the entries (keys) it opened.
type OffRule struct {
	Name   string
	Covers []string
}

func encodeOff(list []OffRule) string {
	var lines []string
	for _, r := range list {
		lines = append(lines, r.Name+"\t"+strings.Join(r.Covers, "|"))
	}
	if len(lines) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
}

func decodeOff(s string) []OffRule {
	if s == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return parseOffLines(string(b))
}

var digitsComma = regexp.MustCompile(`^[0-9,]*$`)

func parseOffLines(s string) []OffRule {
	var out []OffRule
	seen := map[string]bool{}
	for _, l := range strings.Split(strings.TrimPrefix(s, "\uFEFF"), "\n") {
		l = strings.TrimRight(l, "\r ")
		name, keys, _ := strings.Cut(l, "\t")
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		r := OffRule{Name: name}
		sep := "|"
		if digitsComma.MatchString(keys) {
			sep = "," // version 3: TCP port numbers
		}
		for _, k := range strings.Split(keys, sep) {
			if k = strings.TrimSpace(k); k != "" {
				r.Covers = append(r.Covers, k)
			}
		}
		out = append(out, r)
	}
	return out
}

// ---------------------------------------------------------------- IP ranges

// prefix is one IPv4 network.
type prefix struct {
	start uint32
	bits  int
}

func (p prefix) size() uint64 { return 1 << (32 - p.bits) }

func (p prefix) String() string {
	s := p.start
	return fmt.Sprintf("%d.%d.%d.%d/%d", s>>24, s>>16&255, s>>8&255, s&255, p.bits)
}

func (p prefix) contains(q prefix) bool {
	return q.bits >= p.bits && uint64(q.start) >= uint64(p.start) && uint64(q.start) < uint64(p.start)+p.size()
}

func ip4(s string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(s)).To4()
	if ip == nil {
		return 0, false
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]), true
}

// parsePrefix reads 1.2.3.0/24, 1.2.3.0/255.255.255.0 (how Windows shows
// them) or a single address; host bits are cleared.
func parsePrefix(s string) (prefix, bool) {
	s = strings.TrimSpace(s)
	addr, mask, found := strings.Cut(s, "/")
	v, ok := ip4(addr)
	if !ok {
		return prefix{}, false
	}
	bits := 32
	if found {
		if m := net.ParseIP(mask); m != nil && m.To4() != nil {
			ones, total := net.IPMask(m.To4()).Size()
			if total != 32 {
				return prefix{}, false // not a contiguous mask
			}
			bits = ones
		} else if n, err := strconv.Atoi(mask); err == nil && n >= 0 && n <= 32 && strconv.Itoa(n) == mask {
			bits = n
		} else {
			return prefix{}, false
		}
	}
	p := prefix{bits: bits}
	if bits > 0 {
		p.start = v &^ uint32(p.size()-1)
	}
	return p, true
}

// reserved: networks that are never part of a country list (private,
// loopback, multicast ...). The monthly task leaves out the same ones.
var reserved = []prefix{
	{0 << 24, 8}, {10 << 24, 8}, {100<<24 | 64<<16, 10}, {127 << 24, 8},
	{169<<24 | 254<<16, 16}, {172<<24 | 16<<16, 12}, {192<<24 | 168<<16, 16}, {224 << 24, 3},
}

// reservedOverlap: the network touches a reserved network anywhere.
func reservedOverlap(p prefix) bool {
	lo, hi := uint64(p.start), uint64(p.start)+p.size()
	for _, r := range reserved {
		if lo < uint64(r.start)+r.size() && hi > uint64(r.start) {
			return true
		}
	}
	return false
}

func reservedV4(v uint32) bool { return reservedOverlap(prefix{start: v, bits: 32}) }

// Aggregate merges the ranges into as few networks as possible (never
// larger than a /8): fewer Windows Firewall rules for the same addresses.
// The monthly task does exactly the same in PowerShell.
func Aggregate(list []string) []string {
	var ps []prefix
	for _, s := range list {
		if p, ok := parsePrefix(s); ok && p.bits >= 8 && !reservedOverlap(p) {
			ps = append(ps, p)
		}
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].start != ps[j].start {
			return ps[i].start < ps[j].start
		}
		return ps[i].bits < ps[j].bits
	})
	var out []prefix
	for _, p := range ps {
		if n := len(out); n > 0 && out[n-1].contains(p) {
			continue
		}
		out = append(out, p)
		for n := len(out); n >= 2; n = len(out) {
			a, b := out[n-2], out[n-1]
			if a.bits != b.bits || a.bits <= 8 || uint64(a.start)%(a.size()*2) != 0 || uint64(b.start) != uint64(a.start)+a.size() {
				break
			}
			out = append(out[:n-2], prefix{start: a.start, bits: a.bits - 1})
		}
	}
	res := make([]string, len(out))
	for i, p := range out {
		res[i] = p.String()
	}
	return res
}

// addrTotal: how many addresses the list holds (ranges as Windows shows them too).
func addrTotal(list []string) uint64 {
	var t uint64
	for _, s := range list {
		if lo, hi, ok := strings.Cut(s, "-"); ok {
			l, ok1 := ip4(lo)
			h, ok2 := ip4(hi)
			if ok1 && ok2 && h >= l {
				t += uint64(h-l) + 1
			}
			continue
		}
		if p, ok := parsePrefix(s); ok {
			t += p.size()
		}
	}
	return t
}

var cidrRe = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b`)

// ParseRanges accepts the RIPE JSON of one country, or any text with the
// ranges in it (also the page saved as HTML). Refuses empty lists.
func ParseRanges(raw []byte) ([]string, error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(raw), "\uFEFF"))
	var items []string
	var j struct {
		Data struct {
			Resources struct {
				IPv4 []string `json:"ipv4"`
			} `json:"resources"`
		} `json:"data"`
	}
	if strings.HasPrefix(s, "{") && json.Unmarshal([]byte(s), &j) == nil && len(j.Data.Resources.IPv4) > 0 {
		items = j.Data.Resources.IPv4
	} else {
		items = cidrRe.FindAllString(s, -1)
	}
	var valid []string
	for _, it := range items {
		if strings.Contains(it, "-") {
			continue
		}
		valid = append(valid, it)
	}
	out := Aggregate(valid)
	if len(out) == 0 {
		return nil, errors.New(T("در لیست هیچ IP range قابل استفاده‌ای نبود"))
	}
	return out, nil
}

// parseRIPE is for downloads: only the RIPEstat answer itself is accepted
// (not a page a proxy put in its place), and it must have the IPv4 list.
func parseRIPE(raw []byte) ([]string, error) {
	var j struct {
		Data struct {
			Resources struct {
				IPv4 *[]string `json:"ipv4"`
			} `json:"resources"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &j); err != nil || j.Data.Resources.IPv4 == nil {
		return nil, errors.New(T("جواب سرور لیست IP نبود (شاید یک Proxy یا Firewall جلوی آن را گرفته)"))
	}
	var valid []string
	for _, it := range *j.Data.Resources.IPv4 {
		if !strings.Contains(it, "-") {
			valid = append(valid, it)
		}
	}
	out := Aggregate(valid)
	if len(out) == 0 {
		return nil, errors.New(T("در لیست هیچ IP range قابل استفاده‌ای نبود"))
	}
	return out, nil
}

// checkTotal refuses a list that covers most of the internet.
func checkTotal(list []string) error {
	if t := addrTotal(list); t > maxAddr {
		return errors.New(T("لیست %.0f میلیون IP دارد؛ بیشتر از همه‌ی کشورهای انتخاب‌شده است", float64(t)/1e6))
	}
	return nil
}

// Lists: the merged ranges of the chosen countries, and how many
// addresses each country has (so a small country cannot quietly vanish
// behind a big one).
type Lists struct {
	Ranges []string
	Per    map[string]uint64
}

// perText: the CCN tag, "DE:179200,IR:2013184".
func (l Lists) perText() string {
	var parts []string
	for _, cc := range sortedKeys(l.Per) {
		parts = append(parts, fmt.Sprintf("%s:%d", cc, l.Per[cc]))
	}
	return strings.Join(parts, ",")
}

func sortedKeys(m map[string]uint64) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// combine merges the lists of single countries.
func combine(per map[string][]string) (Lists, error) {
	l := Lists{Per: map[string]uint64{}}
	var all []string
	for cc, r := range per {
		l.Per[cc] = addrTotal(r)
		all = append(all, r...)
	}
	l.Ranges = Aggregate(all)
	if len(l.Ranges) == 0 {
		return l, errors.New(T("در لیست هیچ IP range قابل استفاده‌ای نبود"))
	}
	return l, checkTotal(l.Ranges)
}

// FetchRanges downloads the list of every chosen country (first directly,
// then through PowerShell, which uses the proxy settings of Windows) and
// merges them.
func (c *Core) FetchRanges(ctx context.Context, codes []string) (Lists, error) {
	if len(codes) == 0 {
		return Lists{}, errors.New(T("هیچ کشوری انتخاب نشده"))
	}
	per := map[string][]string{}
	for _, cc := range codes {
		r, err := c.fetchOne(ctx, cc)
		if err != nil {
			return Lists{}, fmt.Errorf("%s: %v", ltr(cc), err)
		}
		per[cc] = r
	}
	return combine(per)
}

func (c *Core) fetchOne(ctx context.Context, cc string) ([]string, error) {
	var errs []string
	if c.HTTP != nil {
		r, err := c.download(ctx, cc)
		if err == nil {
			return r, nil
		}
		errs = append(errs, err.Error())
	}
	if c.Run != nil {
		out, err := c.Run("download", DownloadScript(cc))
		if err == nil {
			err = errors.New("no data")
			for _, l := range outLines(out) {
				if strings.HasPrefix(l, "DATA|") && len(l) > maxDownload*4/3+16 {
					err = errors.New(T("جواب سرور خیلی بزرگ بود"))
				} else if strings.HasPrefix(l, "DATA|") {
					r, e := parseRIPE([]byte(unb64(strings.TrimPrefix(l, "DATA|"))))
					if e == nil {
						return r, nil
					}
					err = e
				}
			}
		}
		errs = append(errs, "PowerShell: "+err.Error())
	}
	return nil, errors.New(strings.Join(errs, " / "))
}

func (c *Core) download(ctx context.Context, cc string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", RipeURL(cc), nil)
	req.Header.Set("User-Agent", "CountryIPFilter/"+Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDownload {
		return nil, errors.New(T("جواب سرور خیلی بزرگ بود"))
	}
	return parseRIPE(b)
}

// ---------------------------------------------------------------- rule sets

// ruleSet: the rules of one kind of entry. Every set holds the same IP
// ranges, split into rules of 400: "CountryIPFilter-TCP-01" ... for all TCP
// ports, "CountryIPFilter-UDP-01" ... for all UDP ports, and
// "CountryIPFilter-APP-1a2b3c4d-01" ... for each program.
type ruleSet struct {
	ID    string
	Proto string // TCP, UDP or Any (programs)
	Ports []int
	Prog  string
}

func appID(path string) string {
	h := fnv.New32a()
	h.Write([]byte(strings.ToLower(normPath(path))))
	return fmt.Sprintf("APP-%08x", h.Sum32())
}

func setsFor(list []Entry) []ruleSet {
	var out []ruleSet
	if p := portsOf(list, KindTCP); len(p) > 0 {
		out = append(out, ruleSet{ID: "TCP", Proto: "TCP", Ports: p})
	}
	if p := portsOf(list, KindUDP); len(p) > 0 {
		out = append(out, ruleSet{ID: "UDP", Proto: "UDP", Ports: p})
	}
	for _, e := range appsOf(list) {
		out = append(out, ruleSet{ID: appID(e.Path), Proto: "Any", Prog: e.Path})
	}
	return out
}

// splitRuleName: "CountryIPFilter-TCP-03" -> "TCP", 3.
func splitRuleName(name string) (set string, index int, ok bool) {
	rest, found := strings.CutPrefix(name, RulePrefix)
	if !found {
		return "", 0, false
	}
	i := strings.LastIndexByte(rest, '-')
	if i <= 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(rest[i+1:])
	if err != nil || n < 1 || len(rest[i+1:]) < 2 {
		return "", 0, false
	}
	return rest[:i], n, true
}

// ---------------------------------------------------------------- operations

func (c *Core) Status(entries []Entry) (Status, error) {
	out, err := c.Run("status", StatusScript())
	if err != nil {
		return Status{}, err
	}
	return ParseStatus(out, entries)
}

func (c *Core) run(name, script string) error {
	out, err := c.Run(name, script)
	if err != nil {
		return err
	}
	return checkOK(out)
}

// ApplyRules writes the rules for a freshly downloaded (or picked) list.
func (c *Core) ApplyRules(l Lists, entries []Entry, codes []string, source string) error {
	if len(l.Ranges) == 0 || len(entries) == 0 || len(codes) == 0 {
		return errors.New(T("لیست IP، کشورها یا پورت‌ها خالی است"))
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	return c.run("apply", ApplyScript(l.Ranges, entries, map[string]string{
		"OK":   fmt.Sprintf("%s,%d,%d", ts, len(l.Ranges), addrTotal(l.Ranges)),
		"LAST": ts + ",OK," + source,
		"CC":   strings.Join(codes, ","),
		"CCN":  l.perText(),
	}))
}

// RepairRules writes all rules again with the IP ranges they hold now (no
// download): after a port was added or removed, or someone changed them.
func (c *Core) RepairRules(ranges []string, entries []Entry) error {
	if len(ranges) == 0 || len(entries) == 0 {
		return errors.New(T("لیست IP، کشورها یا پورت‌ها خالی است"))
	}
	return c.run("apply", ApplyScript(ranges, entries, nil))
}

// Migrate writes the rules of version 3 ("Iran IP Filter") under the new
// names, with all their records, then removes the old rules and task.
func (c *Core) Migrate(ranges []string, entries []Entry, tags map[string]string) error {
	if err := c.run("apply", ApplyScript(ranges, entries, tags)); err != nil {
		return err
	}
	return c.run("remove-old", RemoveOldScript())
}

func (c *Core) RemoveOld() error                     { return c.run("remove-old", RemoveOldScript()) }
func (c *Core) SetTags(tags map[string]string) error { return c.run("tags", TagScript(tags)) }
func (c *Core) EnableFirewall() error                { return c.run("firewall", EnableFirewallScript()) }
func (c *Core) RemoveRules() error                   { return c.run("remove", RemoveScript()) }
func (c *Core) RunUpdate() error                     { return c.run("update", UpdateScript()) }

func (c *Core) Schedule(on bool) error {
	if on {
		return c.run("task", ScheduleScript())
	}
	return c.run("task", UnscheduleScript())
}

// SetRules turns rules on or off. gone: rules that no longer exist.
func (c *Core) SetRules(names []string, enable bool) (done, gone []string, failed map[string]string, err error) {
	failed = map[string]string{}
	if len(names) == 0 {
		return nil, nil, failed, nil
	}
	out, err := c.Run("rules", setRulesScript(names, enable))
	if err != nil {
		return nil, nil, failed, err
	}
	if err := checkOK(out); err != nil {
		return nil, nil, failed, err
	}
	for _, line := range outLines(out) {
		switch {
		case strings.HasPrefix(line, "DONE|"):
			done = append(done, unb64(strings.TrimPrefix(line, "DONE|")))
		case strings.HasPrefix(line, "GONE|"):
			gone = append(gone, unb64(strings.TrimPrefix(line, "GONE|")))
		case strings.HasPrefix(line, "FAIL|"):
			f := strings.SplitN(line, "|", 3)
			if len(f) == 3 {
				failed[unb64(f[1])] = unb64(f[2])
			}
		}
	}
	return done, gone, failed, nil
}

// ---------------------------------------------------------------- small helpers

func checkOK(out string) error {
	if !strings.Contains(out, "IPF-OK") {
		return errors.New(T("PowerShell کار را تمام نکرد: %s", lastLines(out, 4)))
	}
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return strings.Join(lines, " / ")
}

func unb64(s string) string {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return s
	}
	return string(b)
}

func outLines(out string) []string {
	out = strings.ReplaceAll(out, "\uFEFF", "")
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		lines = append(lines, strings.TrimRight(l, "\r "))
	}
	return lines
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func containsInt(l []int, x int) bool {
	for _, n := range l {
		if n == x {
			return true
		}
	}
	return false
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func baseName(p string) string { return filepath.Base(strings.ReplaceAll(p, `\`, "/")) }

type Level int

const (
	LevelGrey Level = iota
	LevelGreen
	LevelOrange
	LevelRed
)

// FolderShared: the program does not sit in a folder of its own (for
// example it was started straight from the Desktop or Downloads). Only a
// folder of its own is locked so that just Administrators can change it.
func FolderShared(dir string) bool {
	if dir == "" {
		return true
	}
	clean := filepath.Clean(dir)
	if filepath.Dir(clean) == clean || strings.HasSuffix(clean, `:\`) || strings.HasSuffix(clean, ":") {
		return true // a drive root
	}
	switch strings.ToLower(filepath.Base(clean)) {
	case "desktop", "downloads", "documents", "windows", "system32", "program files", "program files (x86)", "users", "temp", "public":
		return true
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		return true
	}
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		switch {
		case n == "data" && e.IsDir():
		case (strings.HasPrefix(n, "countryipfilter") || strings.HasPrefix(n, "iranipfilter")) && !e.IsDir():
		case strings.HasSuffix(n, ".html") && !e.IsDir():
		case n == "desktop.ini" || n == "thumbs.db":
		default:
			return true
		}
	}
	return false
}
