package main

// A fake Windows Firewall: it understands the scripts this program writes
// well enough to keep a state and print what the real status script prints.

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

type fakeRule struct {
	name, display, source string
	open, enabled         bool
	ports                 string // default "808"
	proto                 string // default "TCP"
	program               string // default "Any"
	block                 bool   // an inbound Block rule
	profile               string // default "Any"
	ifType, ifAlias       string // interface type (default "Any") and adapter name
	group                 string // DisplayGroup
}

type fakeOur struct {
	set     string
	index   int
	proto   string
	ports   []int
	prog    string
	addrs   []string
	enabled bool
}

type fakeOld struct {
	name  string
	ports []int
	addrs []string
}

type fakeFW struct {
	ours       map[string]*fakeOur
	oursBlock  bool   // someone changed our rules to Block
	oursAddr   string // someone added this address to our rules
	inboundOff bool   // "Block all incoming connections"
	rulesLost  bool   // the rules script is killed after switching the rules
	desc       string // Description of the first rules (the tags)
	others     []*fakeRule
	task       bool
	taskArgs   string
	fwOff      bool
	active     string // active profiles ("" = not printed)
	failApply  bool
	failStatus bool
	failRules  bool
	failTags   bool
	updateFail bool
	listen     map[int]string // TCP port -> program
	listenU    map[int]string // UDP port -> program
	old        []fakeOld      // rules of version 3
	oldDesc    string
	oldTask    bool
	psLists    map[string]string // what the PowerShell download gets (nil: it fails)
	scripts    []string
}

var (
	reSets   = regexp.MustCompile(`@\{Id='([^']*)'; Proto='([^']*)'; Ports=@\(([^)]*)\); Prog='((?:[^']|'')*)'\}`)
	reA      = regexp.MustCompile(`(?s)\$a = @\(\r\n(.*?)\)\r\n`)
	reList   = regexp.MustCompile(`foreach \(\$n in @\(([^)]*)\)\)`)
	reSetTag = regexp.MustCompile(`(?m)^SetTag '([A-Z]+)' '((?:[^']|'')*)'`)
)

func parseList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		x = strings.Trim(strings.TrimSpace(x), "'")
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func (f *fakeFW) setTag(k, v string) {
	if len(f.ours) == 0 {
		return
	}
	f.desc = regexp.MustCompile(`\s*\[`+k+`=[^\]]*\]`).ReplaceAllString(f.desc, "")
	if v != "" {
		f.desc += " [" + k + "=" + v + "]"
	}
}

func (f *fakeFW) tags(script string) {
	for _, m := range reSetTag.FindAllStringSubmatch(script, -1) {
		f.setTag(m[1], strings.ReplaceAll(m[2], "''", "'"))
	}
}

func (f *fakeFW) off() []OffRule { return parseTags(f.desc).Off }

// names of our rules, sorted
func (f *fakeFW) names() []string {
	var out []string
	for n := range f.ours {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// set returns the rules of one set, by index
func (f *fakeFW) set(id string) []*fakeOur {
	var out []*fakeOur
	for _, n := range f.names() {
		if f.ours[n].set == id {
			out = append(out, f.ours[n])
		}
	}
	return out
}

// total: IP ranges in one set
func (f *fakeFW) total(id string) int {
	t := 0
	for _, r := range f.set(id) {
		t += len(r.addrs)
	}
	return t
}

func (f *fakeFW) setIDs() []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range f.names() {
		if s := f.ours[n].set; !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// tcpPorts: the ports of the TCP rule set
func (f *fakeFW) tcpPorts() string {
	s := f.set("TCP")
	if len(s) == 0 {
		return "[]"
	}
	return fmt.Sprint(s[0].ports)
}

// mask: Windows shows prefixes with a mask
func mask(cidr string) string {
	p, ok := parsePrefix(cidr)
	if !ok {
		return cidr
	}
	m := uint32(0xFFFFFFFF) << (32 - p.bits)
	if p.bits == 0 {
		m = 0
	}
	s := p.start
	return fmt.Sprintf("%d.%d.%d.%d/%d.%d.%d.%d", s>>24, s>>16&255, s>>8&255, s&255, m>>24, m>>16&255, m>>8&255, m&255)
}

func (f *fakeFW) oursLine(tag, name string, enabled bool, ports []int, proto, prog string, addrs []string, desc string) string {
	act := "Allow"
	if f.oursBlock && tag == "OURS" {
		act = "Block"
	}
	var shown []string
	for _, a := range addrs {
		shown = append(shown, mask(a))
	}
	if f.oursAddr != "" && tag == "OURS" {
		shown = append(shown, f.oursAddr)
	}
	if prog == "" {
		prog = "Any"
	}
	ps := strings.Join(portList(ports), ",")
	if proto == "Any" {
		ps = "Any"
	}
	d := ""
	if strings.HasSuffix(name, "-01") || strings.HasSuffix(name, "-02") {
		d = desc
	}
	return fmt.Sprintf("%s|%s|%s|%s|%d|False|%s|%s|%s|Inbound|Any|%s|%s|%s|Any|%s|Any\r\n", tag, name, boolPS(enabled), ps, len(shown), proto, b64(d), act, b64(""), b64(prog), b64("Any"), b64(strings.Join(shown, ",")))
}

func (f *fakeFW) run(name, script string) (string, error) {
	f.scripts = append(f.scripts, name)
	var b strings.Builder
	switch name {
	case "status":
		if f.failStatus {
			return "Get-NetFirewallProfile : The service cannot be started", fmt.Errorf("exit status 1: The service cannot be started")
		}
		if f.active != "" {
			fmt.Fprintf(&b, "ACTIVE|%s\r\n", f.active)
		}
		for _, p := range []string{"Domain", "Private", "Public"} {
			en := "True"
			if f.fwOff {
				en = "False"
			}
			fmt.Fprintf(&b, "PROFILE|%s|%s|Block|NotConfigured|%s\r\n", p, en, boolPS(!f.inboundOff))
		}
		for _, n := range f.names() {
			r := f.ours[n]
			b.WriteString(f.oursLine("OURS", n, r.enabled, r.ports, r.proto, r.prog, r.addrs, f.desc))
		}
		for _, o := range f.old {
			b.WriteString(f.oursLine("OLD", o.name, true, o.ports, "TCP", "", o.addrs, f.oldDesc))
		}
		for p, prog := range f.listen {
			fmt.Fprintf(&b, "LISTEN|%d|%s|%s\r\n", p, b64(prog), b64(""))
		}
		for p, prog := range f.listenU {
			fmt.Fprintf(&b, "LISTENU|%d|%s|%s\r\n", p, b64(prog), b64(""))
		}
		for _, r := range f.others {
			if r.block && !r.enabled {
				continue // the real script lists only disabled Allow rules
			}
			remote := "10.1.2.3"
			if r.open {
				remote = "Any"
			}
			ports, prog, prof, proto := r.ports, r.program, r.profile, r.proto
			if ports == "" {
				ports = "808"
			}
			if prog == "" {
				prog = "Any"
			}
			if prof == "" {
				prof = "Any"
			}
			if proto == "" {
				proto = "TCP"
			}
			act := "Allow"
			if r.block {
				act = "Block"
			}
			it := r.ifType
			if it == "" {
				it = "Any"
			}
			fmt.Fprintf(&b, "RULE|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\r\n", b64(r.name), r.source, boolPS(r.enabled), proto, ports, remote, b64(prog), b64("Any"), b64(r.display), it, b64(r.ifAlias), act, prof, b64(r.group))
		}
		// a rule on other ports never matters
		fmt.Fprintf(&b, "RULE|%s|Local|True|UDP|5353|Any|%s|%s|%s\r\n", b64("mdns"), b64("Any"), b64("Any"), b64("mDNS"))
		fmt.Fprintf(&b, "TASK|%s\r\n", boolPS(f.task))
		if f.task {
			fmt.Fprintf(&b, "TASKARGS|%s\r\n", b64(f.taskArgs))
		}
		fmt.Fprintf(&b, "OLDTASK|%s\r\n", boolPS(f.oldTask))
		b.WriteString("IPF-OK\r\n")
	case "apply":
		if f.failApply {
			return "Set-NetFirewallRule : Access is denied", fmt.Errorf("exit status 1: Set-NetFirewallRule : Access is denied")
		}
		all := parseList(strings.ReplaceAll(reA.FindStringSubmatch(script)[1], "\r\n", ""))
		if len(f.ours) == 0 {
			f.desc = ruleDesc
		}
		keep := map[string]bool{}
		if f.ours == nil {
			f.ours = map[string]*fakeOur{}
		}
		for _, m := range reSets.FindAllStringSubmatch(script, -1) {
			var ports []int
			for _, p := range parseList(m[3]) {
				var n int
				fmt.Sscan(p, &n)
				ports = append(ports, n)
			}
			for i, k := 0, 1; i < len(all); i, k = i+400, k+1 {
				n := fmt.Sprintf("CountryIPFilter-%s-%02d", m[1], k)
				f.ours[n] = &fakeOur{set: m[1], index: k, proto: m[2], ports: ports, prog: strings.ReplaceAll(m[4], "''", "'"), addrs: all[i:min(i+400, len(all))], enabled: true}
				keep[n] = true
			}
		}
		for n := range f.ours {
			if !keep[n] {
				delete(f.ours, n)
			}
		}
		f.oursBlock, f.oursAddr = false, ""
		f.tags(script)
		b.WriteString("IPF-OK\r\n")
	case "tags":
		if f.failTags || len(f.ours) == 0 {
			return "protection rules not found", fmt.Errorf("exit status 1: protection rules not found")
		}
		f.tags(script)
		b.WriteString("IPF-OK\r\n")
	case "rules":
		if f.failRules {
			return "Access is denied", fmt.Errorf("exit status 1: Access is denied")
		}
		enable := strings.Contains(script, "Enable-NetFirewallRule")
		for _, n := range parseList(reList.FindStringSubmatch(script)[1]) {
			found := false
			for _, r := range f.others {
				// only rules stored on this computer can be found (PersistentStore)
				if r.name == n && (r.source == "Local" || r.source == "") {
					r.enabled = enable
					found = true
				}
			}
			if found {
				fmt.Fprintf(&b, "DONE|%s\r\n", b64(n))
			} else {
				fmt.Fprintf(&b, "GONE|%s\r\n", b64(n))
			}
		}
		if f.rulesLost && !enable {
			return "killed after 5 minutes", fmt.Errorf("timeout")
		}
		b.WriteString("IPF-OK\r\n")
	case "firewall":
		f.fwOff, f.inboundOff = false, false
		f.tags(script)
		b.WriteString("IPF-OK\r\n")
	case "remove":
		f.ours = nil
		f.desc = ""
		b.WriteString("IPF-OK\r\n")
	case "remove-old":
		f.old, f.oldDesc, f.oldTask = nil, "", false
		b.WriteString("IPF-OK\r\n")
	case "task":
		if strings.Contains(script, "Unregister") {
			f.task = false
		} else {
			f.task = true
			f.taskArgs = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe ` + TaskArguments()
		}
		b.WriteString("IPF-OK\r\n")
	case "update":
		if len(f.ours) > 0 {
			if f.updateFail {
				f.setTag("LAST", time.Now().UTC().Format(time.RFC3339)+",FAIL,download")
			} else {
				f.setTag("LAST", time.Now().UTC().Format(time.RFC3339)+",OK,task")
			}
		}
		b.WriteString("IPF-OK\r\n")
	case "download":
		for cc, body := range f.psLists {
			if strings.Contains(script, "resource="+cc+"'") {
				fmt.Fprintf(&b, "DATA|%s\r\nIPF-OK\r\n", b64(body))
				return b.String(), nil
			}
		}
		return "Invoke-WebRequest : Unable to connect to the remote server", fmt.Errorf("exit status 1")
	}
	return b.String(), nil
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func boolPS(v bool) string {
	if v {
		return "True"
	}
	return "False"
}

// ---------- fake UI ----------

type fakeUI struct {
	logs    []string
	asked   []string
	answers []bool // consumed in order; when empty, answer is used
	answer  bool
	told    []string
	view    View
	opened  []string
	pick    []string // files picked, in order ("" = cancel)
}

func (u *fakeUI) Log(s string)      { u.logs = append(u.logs, s) }
func (u *fakeUI) Progress(s string) {}
func (u *fakeUI) Ask(t string, w bool) bool {
	u.asked = append(u.asked, t)
	if len(u.answers) > 0 {
		a := u.answers[0]
		u.answers = u.answers[1:]
		return a
	}
	return u.answer
}
func (u *fakeUI) Tell(t string, l Level) { u.told = append(u.told, t) }
func (u *fakeUI) Show(v View)            { u.view = v }
func (u *fakeUI) OpenURL(s string) bool  { u.opened = append(u.opened, s); return true }
func (u *fakeUI) PickFile(program bool) string {
	if len(u.pick) == 0 {
		return ""
	}
	p := u.pick[0]
	u.pick = u.pick[1:]
	return p
}

func (u *fakeUI) problem(kind FixKind) (Problem, bool) {
	for _, p := range u.view.Problems {
		if p.Kind == kind {
			return p, true
		}
	}
	return Problem{}, false
}

func (u *fakeUI) lastAsk() string {
	if len(u.asked) == 0 {
		return ""
	}
	return u.asked[len(u.asked)-1]
}

func (u *fakeUI) lastTell() string {
	if len(u.told) == 0 {
		return ""
	}
	return u.told[len(u.told)-1]
}

// ---------- helpers ----------

// ripeJSON: n ranges that cannot be merged, starting at first octet base.
func ripeJSON(n, base int) string {
	var items []string
	for i := 0; i < n; i++ {
		items = append(items, fmt.Sprintf(`"%d.%d.0.0/22"`, base+i/250, i%250))
	}
	items = append(items, `"0.0.0.0/0"`, `"2001:db8::/32"`, `"bad"`, `"10.0.0.0/8"`)
	return `{"data":{"resources":{"ipv4":[` + strings.Join(items, ",") + `]}}}`
}

// lists: the default countries of the tests (Iran: 1966 ranges, Germany: 700)
var lists = map[string]string{"IR": ripeJSON(1966, 2), "DE": ripeJSON(700, 80), "AE": ripeJSON(120, 90)}

func newCore(t *testing.T, fw *fakeFW) *Core {
	return &Core{Dir: t.TempDir(), ExeDir: t.TempDir(), Run: fw.run}
}

// newTestApp: a fresh program folder with Iran and TCP 808 chosen.
func newTestApp(t *testing.T, fw *fakeFW) (*App, *fakeUI, *Core) {
	c := newCore(t, fw)
	c.SaveCountries([]string{"IR"})
	c.SaveEntries([]Entry{TCP(808)})
	return startApp(t, c, lists)
}

func startApp(t *testing.T, c *Core, data map[string]string) (*App, *fakeUI, *Core) {
	ui := &fakeUI{answer: true}
	c.Log = ui.Log
	c.HTTP = clientFor(withRipe(t, data, 200))
	a := &App{core: c, ui: ui}
	a.Refresh()
	return a, ui, c
}

// withRipe answers like RIPEstat: the list of the country in ?resource=.
func withRipe(t *testing.T, data map[string]string, code int) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := data[r.URL.Query().Get("resource")]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(code)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// redirect RipeURL to the test server
type rewrite struct {
	base string
	rt   http.RoundTripper
}

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.Scheme = "https"
	u.Host = strings.TrimPrefix(r.base, "https://")
	req = req.Clone(req.Context())
	req.URL = &u
	req.Host = u.Host
	return r.rt.RoundTrip(req)
}

func clientFor(srv *httptest.Server) *http.Client {
	c := srv.Client()
	c.Transport = rewrite{base: srv.URL, rt: c.Transport}
	return c
}

func offline(t *testing.T, c *Core) { c.HTTP = clientFor(withRipe(t, nil, 500)) }
