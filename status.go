package main

// Reading what the status script printed, and deciding which rules of
// Windows Firewall matter for the chosen ports and programs.

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Profile struct {
	Name         string
	Enabled      bool
	Inbound      string
	AllowLocal   string
	AllowInbound string // "False": "Block all incoming connections" is on
}

// OurRule is one rule this program wrote.
type OurRule struct {
	Name    string
	Set     string // TCP, UDP, APP-xxxxxxxx ("" for rules of version 3)
	Index   int    // 1 for ...-01
	Enabled bool
	Ports   []int
	Count   int // number of remote address entries
	Addrs   []string
	Wide    bool // someone changed it to allow every address (or more than was written)
	Proto   string
	Program string
	Odd     bool // action, direction, profile, service ... are not what this program wrote
	Desc    string
}

// FwRule is one inbound rule that is not ours.
type FwRule struct {
	Enabled                                           bool
	Block                                             bool // an inbound Block rule
	Name, Source, Protocol, Program, Service, Display string
	IfType, IfAlias, Profile, Group                   string
	Ports                                             []string // LocalPort values
	Remote                                            []string // RemoteAddress values
}

type Conflict struct {
	Name     string
	Display  string
	Source   string
	Program  string // set when the rule is limited to one program
	Group    string // DisplayGroup: set for rules that come with Windows or a program
	Enabled  bool
	Covers   []string // keys of our entries it opens (or shuts)
	Open     bool     // reachable from the whole internet
	Broad    bool     // also opens things that are not in our list (disabling it could cut RDP etc.)
	CanClose bool     // on, open, local and not broad: safe to turn off automatically
	Tech     string   // raw values for the details view
	Local    bool     // stored on this computer (can be switched on/off here)
}

// Listener is a program listening on a port.
type Listener struct {
	Program  string
	Services []string
}

// Tags: what the program keeps in the Description of the first rules.
type Tags struct {
	ListDate  time.Time // last successful list update
	ListCount int       // ranges written
	ListAddr  uint64    // addresses written (0: not recorded, version 3)
	LastWhen  time.Time // last update attempt
	LastOK    bool
	LastWhy   string // on failure: download, list, old, apply, lock, ports; on success: download, file, task
	Countries []string
	Per       map[string]uint64 // addresses of each country when written
	Off       []OffRule
	FwOn      bool // this program switched the Windows Firewall on
	Seen      map[string][]string
	Raw       map[string]string
}

type Status struct {
	Active    []string // active firewall profiles (Domain, Private, Public)
	Profiles  []Profile
	Ours      []OurRule
	Tags      Tags
	Old       []OurRule // rules of version 3 ("Iran IP Filter")
	OldTags   Tags
	OldTask   bool
	Rules     []FwRule
	Conflicts []Conflict         // allow rules that open our entries
	Blocks    []Conflict         // enabled block rules that shut our entries for everyone
	Listeners map[int][]Listener // TCP
	UDP       map[int][]Listener
	Task      bool
	TaskArgs  string    // "program arguments" of the scheduled task
	TaskFile  string    // SHA-256 of update.ps1 ("" when it is missing)
	TaskCode  int64     // result of the task's last run (0 = fine)
	TaskRun   time.Time // when it last ran
	Proxy     string    // proxy Windows uses for the list download ("" = none)
	entries   []Entry
}

func (s Status) Dangerous() []Conflict {
	var out []Conflict
	for _, c := range s.Conflicts {
		if c.Open && c.Enabled {
			out = append(out, c)
		}
	}
	return out
}

// ---------------------------------------------------------------- firewall profiles

// isActive: the profile is in use right now (unknown: assume yes).
func (s Status) isActive(name string) bool {
	if len(s.Active) == 0 {
		return true
	}
	return containsFold(s.Active, name)
}

// ruleActive: the rule applies to a profile in use.
func (s Status) ruleActive(profile string) bool {
	if profile == "" || strings.EqualFold(profile, "Any") || len(s.Active) == 0 {
		return true
	}
	for _, p := range splitList(profile) {
		if s.isActive(p) {
			return true
		}
	}
	return false
}

func (s Status) FirewallProblem() bool {
	for _, p := range s.Profiles {
		if s.isActive(p.Name) && (!p.Enabled || strings.EqualFold(p.Inbound, "Allow")) {
			return true
		}
	}
	return s.LocalRulesBlocked()
}

// InactiveOff: profiles not in use now whose firewall is off or lets
// everything in (they matter when the network type changes).
func (s Status) InactiveOff() []string {
	var out []string
	for _, p := range s.Profiles {
		if !s.isActive(p.Name) && (!p.Enabled || strings.EqualFold(p.Inbound, "Allow")) {
			out = append(out, p.Name)
		}
	}
	return out
}

// FirewallOff: the firewall itself is off (not just "allow everything").
func (s Status) FirewallOff() bool {
	for _, p := range s.Profiles {
		if s.isActive(p.Name) && !p.Enabled {
			return true
		}
	}
	return false
}

// InboundBlocked: "Block all incoming connections" is on, so no allow rule
// (ours neither) has any effect.
func (s Status) InboundBlocked() bool {
	for _, p := range s.Profiles {
		if s.isActive(p.Name) && strings.EqualFold(p.AllowInbound, "False") {
			return true
		}
	}
	return false
}

// LocalRulesBlocked: Group Policy ignores rules made on this computer.
func (s Status) LocalRulesBlocked() bool {
	for _, p := range s.Profiles {
		if s.isActive(p.Name) && strings.EqualFold(p.AllowLocal, "False") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- sensitive entries

// sensitive ports: closing them from outside can lock the admin out
var sensitivePorts = map[string]string{"3389": "Remote Desktop", "22": "SSH", "5985": "WinRM", "5986": "WinRM", "udp:3389": "Remote Desktop"}

// Sensitive: remote-management entries, by number, by what listens on them
// (Remote Desktop, SSH or WinRM moved to another port), or by program.
func (s Status) Sensitive(keys []string) []string {
	var out []string
	for _, k := range keys {
		if s.SensitiveName(k) != "" {
			out = append(out, k)
		}
	}
	return out
}

func (s Status) SensitiveName(key string) string {
	if n, ok := sensitivePorts[key]; ok {
		return n
	}
	if path, ok := strings.CutPrefix(key, "app:"); ok {
		if strings.EqualFold(baseName(path), "sshd.exe") {
			return "SSH"
		}
		return ""
	}
	ls := s.Listeners
	num := key
	if p, ok := strings.CutPrefix(key, "udp:"); ok {
		ls, num = s.UDP, p
	}
	port, err := strconv.Atoi(num)
	if err != nil {
		return ""
	}
	for _, l := range ls[port] {
		for _, svc := range l.Services {
			switch strings.ToLower(svc) {
			case "termservice":
				return "Remote Desktop"
			case "sshd":
				return "SSH"
			case "winrm":
				return "WinRM"
			}
		}
		if strings.EqualFold(baseName(l.Program), "sshd.exe") {
			return "SSH"
		}
	}
	return ""
}

func (s Status) sensitiveNames(keys []string) string {
	var out []string
	for _, k := range keys {
		if x := s.SensitiveName(k); x != "" && !containsStr(out, x) {
			out = append(out, x)
		}
	}
	return strings.Join(out, listSep())
}

// ---------------------------------------------------------------- our rules

// ListenerName: a short name for what listens on a TCP or UDP port.
func (s Status) ListenerName(kind string, p int) string {
	ls := s.Listeners[p]
	if kind == KindUDP {
		ls = s.UDP[p]
	}
	for _, l := range ls {
		if len(l.Services) > 0 {
			return strings.Join(l.Services, ", ")
		}
		if l.Program != "" {
			return baseName(l.Program)
		}
	}
	return ""
}

// appPorts: the ports (of one protocol) a program listens on now.
func appPorts(path string, ls map[int][]Listener) []int {
	var out []int
	for p, list := range ls {
		for _, l := range list {
			if samePath(l.Program, path) {
				out = append(out, p)
			}
		}
	}
	return uniqInts(out)
}

// sets: our rules grouped by rule set, each sorted by index.
func (s Status) sets() map[string][]OurRule {
	m := map[string][]OurRule{}
	for _, r := range s.Ours {
		m[r.Set] = append(m[r.Set], r)
	}
	for k := range m {
		list := m[k]
		sort.Slice(list, func(i, j int) bool { return list[i].Index < list[j].Index })
	}
	return m
}

// ourTotal: the number of IP ranges in our rules (one rule set).
func (s Status) ourTotal() int {
	src, ok := s.sourceSet()
	if ok {
		t := 0
		for _, r := range src {
			t += r.Count
		}
		return t
	}
	best := 0
	for _, list := range s.sets() {
		t := 0
		for _, r := range list {
			t += r.Count
		}
		best = max(best, t)
	}
	return best
}

// complete: rules 01..NN all there, none emptied or opened up, and (when it
// is recorded) exactly as many ranges as were written.
func (s Status) complete(list []OurRule) bool {
	if len(list) == 0 {
		return false
	}
	total := 0
	for i, r := range list {
		if r.Index != i+1 || r.Wide || r.Count == 0 {
			return false
		}
		total += r.Count
	}
	return s.Tags.ListCount == 0 || total == s.Tags.ListCount
}

// sourceSet: a complete rule set whose IP ranges can be copied to the others.
func (s Status) sourceSet() ([]OurRule, bool) {
	m := s.sets()
	var ids []string
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if id != "" && s.complete(m[id]) {
			return m[id], true
		}
	}
	return nil, false
}

// Repairable: one rule set still holds all its IP ranges, so every rule can
// be written again without a download.
func (s Status) Repairable() bool {
	_, ok := s.sourceSet()
	return ok
}

// SourceRanges: the IP ranges our rules hold now.
func (s Status) SourceRanges() []string {
	src, ok := s.sourceSet()
	if !ok {
		return nil
	}
	var out []string
	for _, r := range src {
		out = append(out, r.Addrs...)
	}
	return Aggregate(out)
}

// RulesMatch: there is exactly one complete, unchanged rule set for each
// kind of entry, with the right ports or program, and nothing else.
func (s Status) RulesMatch(entries []Entry) bool {
	if !s.Repairable() || len(entries) == 0 {
		return false
	}
	have := s.sets()
	want := setsFor(entries)
	if len(have) != len(want) {
		return false
	}
	for _, w := range want {
		list := have[w.ID]
		if !s.complete(list) {
			return false
		}
		for _, r := range list {
			if !r.Enabled || r.Odd {
				return false
			}
			if w.Prog != "" {
				if !samePath(r.Program, w.Prog) || !strings.EqualFold(r.Proto, "Any") {
					return false
				}
			} else if !equalInts(uniqInts(r.Ports), w.Ports) || !protoIs(r.Proto, w.Proto) {
				return false
			}
		}
	}
	return true
}

func protoIs(got, want string) bool {
	switch strings.ToUpper(got) {
	case "":
		return true // not printed (older status output)
	case "6":
		got = "TCP"
	case "17":
		got = "UDP"
	}
	return strings.EqualFold(got, want)
}

// OurEntries: the ports and programs our rules open (to rebuild ports.txt).
func (s Status) OurEntries() []Entry {
	var out []Entry
	for id, list := range s.sets() {
		if len(list) == 0 {
			continue
		}
		r := list[0]
		switch {
		case id == "TCP":
			for _, p := range r.Ports {
				out = append(out, TCP(p))
			}
		case id == "UDP":
			for _, p := range r.Ports {
				out = append(out, UDP(p))
			}
		case strings.HasPrefix(id, "APP-") && r.Program != "" && !strings.EqualFold(r.Program, "Any"):
			out = append(out, AppEntry(r.Program))
		}
	}
	return sortEntries(out)
}

// covers: the rules for entry e are all on, limited to the countries and
// include it.
func (s Status) covers(e Entry) bool {
	list := s.setOf(e)
	if !s.complete(list) {
		return false
	}
	for _, r := range list {
		if !r.Enabled || r.Odd {
			return false
		}
		if e.Kind == KindApp {
			if !samePath(r.Program, e.Path) || !strings.EqualFold(r.Proto, "Any") {
				return false
			}
		} else if !containsInt(r.Ports, e.Port) || !protoIs(r.Proto, e.Kind) {
			return false
		}
	}
	return true
}

// wideFor: someone changed one of the rules for e to allow everyone.
func (s Status) wideFor(e Entry) bool {
	for _, r := range s.setOf(e) {
		if r.Enabled && r.Wide && (e.Kind == KindApp || containsInt(r.Ports, e.Port)) {
			return true
		}
	}
	return false
}

func (s Status) setOf(e Entry) []OurRule {
	id := e.Kind
	if e.Kind == KindApp {
		id = appID(e.Path)
	}
	return s.sets()[id]
}

// TaskFailed: the task ran (in this century) and Windows reports an error,
// e.g. Group Policy forbids PowerShell script files. 0x41300-0x41306 are
// "ready / running / not yet run" and the like, not errors.
func (s Status) TaskFailed() bool {
	if !s.Task || s.TaskCode == 0 || s.TaskRun.Year() < 2000 {
		return false
	}
	// the list was updated (by hand) after that run: nothing to say now
	if s.Tags.LastOK && s.Tags.LastWhen.After(s.TaskRun) {
		return false
	}
	switch s.TaskCode {
	case 0x41325, 0x8004131F: // queued, already running
		return false
	}
	return s.TaskCode < 0x41300 || s.TaskCode > 0x41306
}

// TaskCurrent: the scheduled task runs the update script of this version
// (its file unchanged), with the PowerShell of Windows itself.
func (s Status) TaskCurrent() bool {
	return s.Task && strings.HasSuffix(strings.ToLower(s.TaskArgs), strings.ToLower(`\System32\WindowsPowerShell\v1.0\powershell.exe `+TaskArguments())) &&
		strings.EqualFold(s.TaskFile, taskFileHash())
}

// plainRange: an IPv4 address or network the way this program writes them
// (Windows may show the mask instead of the prefix length).
func plainRange(a string) bool {
	p, ok := parsePrefix(a)
	return ok && p.bits >= 8
}

// ---------------------------------------------------------------- parsing

var tagRe = regexp.MustCompile(`\[([A-Z]+)=([^\]]*)\]`)

func parseTags(desc string) Tags {
	t := Tags{Raw: map[string]string{}}
	for _, m := range tagRe.FindAllStringSubmatch(desc, -1) {
		t.Raw[m[1]] = m[2]
	}
	if v, ok := t.Raw["OK"]; ok {
		f := strings.Split(v, ",")
		t.ListDate, _ = time.Parse(time.RFC3339, f[0])
		if len(f) > 1 {
			t.ListCount, _ = strconv.Atoi(f[1])
		}
		if len(f) > 2 {
			t.ListAddr, _ = strconv.ParseUint(f[2], 10, 64)
		}
	}
	if v, ok := t.Raw["LAST"]; ok {
		f := strings.Split(v, ",")
		t.LastWhen, _ = time.Parse(time.RFC3339, f[0])
		if len(f) > 1 {
			t.LastOK = f[1] == "OK"
		}
		if len(f) > 2 {
			t.LastWhy = f[2]
		}
	}
	t.Countries = cleanCountries(splitList(t.Raw["CC"]))
	for _, p := range splitList(t.Raw["CCN"]) {
		if cc, n, ok := strings.Cut(p, ":"); ok {
			if v, err := strconv.ParseUint(n, 10, 64); err == nil {
				if t.Per == nil {
					t.Per = map[string]uint64{}
				}
				t.Per[cc] = v
			}
		}
	}
	t.Off = decodeOff(t.Raw["OFF"])
	t.FwOn = t.Raw["FWON"] == "1"
	if v := t.Raw["SEEN"]; v != "" {
		t.Seen = map[string][]string{}
		for _, part := range strings.Split(unb64(v), "\n") {
			k, prog, ok := strings.Cut(part, "\t")
			if ok && k != "" && prog != "" {
				t.Seen[k] = append(t.Seen[k], prog)
			}
		}
	}
	return t
}

func encodeSeen(m map[string][]string) string {
	var lines []string
	for k, progs := range m {
		for _, x := range progs {
			lines = append(lines, k+"\t"+x)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	sort.Strings(lines)
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
}

// parseOurs reads one OURS or OLD line.
func parseOurs(f []string) (OurRule, bool) {
	if len(f) < 5 {
		return OurRule{}, false
	}
	r := OurRule{Name: f[1], Enabled: f[2] == "True"}
	r.Set, r.Index, _ = splitRuleName(r.Name)
	if len(f) >= 7 {
		r.Wide = f[5] == "True"
		r.Proto = f[6]
	}
	if len(f) >= 8 {
		r.Desc = unb64(f[7])
	}
	if len(f) >= 15 {
		any := func(x string) bool { x = strings.TrimSpace(x); return x == "" || strings.EqualFold(x, "Any") }
		r.Program = strings.TrimSpace(unb64(f[12]))
		r.Odd = !strings.EqualFold(f[8], "Allow") || !strings.EqualFold(f[9], "Inbound") || !any(f[10]) ||
			!any(unb64(f[11])) || !any(unb64(f[13])) || !any(f[14])
		if !strings.HasPrefix(r.Set, "APP-") && !any(r.Program) {
			r.Odd = true // a port rule limited to one program
		}
		if any(r.Program) {
			r.Program = ""
		}
	}
	if len(f) >= 17 {
		// every address must be one IPv4 network, nothing like "Internet"
		r.Addrs = splitList(unb64(f[15]))
		for _, a := range r.Addrs {
			if !plainRange(a) {
				r.Wide = true
			}
		}
		if p := strings.TrimSpace(f[16]); p != "" && !strings.EqualFold(p, "Any") {
			r.Odd = true
		}
	}
	for _, p := range splitList(f[3]) {
		if n, err := strconv.Atoi(p); err == nil {
			r.Ports = append(r.Ports, n)
		}
	}
	r.Count, _ = strconv.Atoi(strings.TrimSpace(f[4]))
	return r, true
}

// firstTags: the tags of the first rule (by name) that has any.
func firstTags(list []OurRule) Tags {
	sorted := append([]OurRule(nil), list...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, r := range sorted {
		if t := parseTags(r.Desc); len(t.Raw) > 0 {
			return t
		}
	}
	return Tags{Raw: map[string]string{}}
}

func ParseStatus(out string, entries []Entry) (Status, error) {
	var st Status
	if err := checkOK(out); err != nil {
		return st, err
	}
	st.entries = entries
	for _, line := range outLines(out) {
		switch {
		case strings.HasPrefix(line, "ACTIVE|"):
			for _, p := range splitList(strings.TrimPrefix(line, "ACTIVE|")) {
				switch strings.ToLower(p) {
				case "domain", "private", "public":
					st.Active = append(st.Active, p)
				}
			}
		case strings.HasPrefix(line, "PROFILE|"):
			f := strings.Split(line, "|")
			if len(f) >= 4 {
				p := Profile{Name: f[1], Enabled: f[2] == "True", Inbound: f[3]}
				if len(f) >= 5 {
					p.AllowLocal = f[4]
				}
				if len(f) >= 6 {
					p.AllowInbound = f[5]
				}
				st.Profiles = append(st.Profiles, p)
			}
		case strings.HasPrefix(line, "OURS|"):
			if r, ok := parseOurs(strings.Split(line, "|")); ok && r.Set != "" {
				st.Ours = append(st.Ours, r)
			}
		case strings.HasPrefix(line, "OLD|"):
			if r, ok := parseOurs(strings.Split(line, "|")); ok {
				st.Old = append(st.Old, r)
			}
		case strings.HasPrefix(line, "RULE|"):
			f := strings.Split(line, "|")
			if len(f) >= 10 {
				r := FwRule{
					Name: unb64(f[1]), Source: f[2], Enabled: f[3] == "True", Protocol: f[4],
					Ports: splitList(f[5]), Remote: splitList(f[6]),
					Program: unb64(f[7]), Service: unb64(f[8]), Display: unb64(f[9]),
				}
				if len(f) >= 12 {
					r.IfType, r.IfAlias = f[10], unb64(f[11])
				}
				if len(f) >= 13 {
					r.Block = f[12] == "Block"
				}
				if len(f) >= 14 {
					r.Profile = f[13]
				}
				if len(f) >= 15 {
					r.Group = unb64(f[14])
				}
				// an empty value means "not restricted"
				if len(r.Ports) == 0 {
					r.Ports = []string{"Any"}
				}
				if len(r.Remote) == 0 {
					r.Remote = []string{"Any"}
				}
				if r.Protocol == "" {
					r.Protocol = "Any"
				}
				st.Rules = append(st.Rules, r)
			}
		case strings.HasPrefix(line, "LISTEN|"), strings.HasPrefix(line, "LISTENU|"):
			f := strings.Split(line, "|")
			if len(f) == 4 {
				p, _ := strconv.Atoi(f[1])
				l := Listener{Program: unb64(f[2]), Services: splitList(unb64(f[3]))}
				if f[0] == "LISTENU" {
					if st.UDP == nil {
						st.UDP = map[int][]Listener{}
					}
					st.UDP[p] = append(st.UDP[p], l)
				} else {
					if st.Listeners == nil {
						st.Listeners = map[int][]Listener{}
					}
					st.Listeners[p] = append(st.Listeners[p], l)
				}
			}
		case strings.HasPrefix(line, "TASK|"):
			st.Task = strings.TrimSpace(strings.TrimPrefix(line, "TASK|")) == "True"
		case strings.HasPrefix(line, "OLDTASK|"):
			st.OldTask = strings.TrimSpace(strings.TrimPrefix(line, "OLDTASK|")) == "True"
		case strings.HasPrefix(line, "PROXY|"):
			st.Proxy = strings.TrimSpace(strings.TrimPrefix(line, "PROXY|"))
		case strings.HasPrefix(line, "TASKRESULT|"):
			f := strings.Split(line, "|")
			if len(f) >= 3 {
				st.TaskCode, _ = strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64)
				st.TaskRun, _ = time.Parse(time.RFC3339, strings.TrimSpace(f[2]))
			}
		case strings.HasPrefix(line, "TASKFILE|"):
			st.TaskFile = strings.TrimSpace(strings.TrimPrefix(line, "TASKFILE|"))
		case strings.HasPrefix(line, "TASKARGS|"):
			st.TaskArgs = unb64(strings.TrimPrefix(line, "TASKARGS|"))
		}
	}
	st.Tags = firstTags(st.Ours)
	st.OldTags = firstTags(st.Old)
	// a rule set that holds more addresses than were written was opened up
	if st.Tags.ListAddr > 0 {
		for id, list := range st.sets() {
			var all []string
			for _, r := range list {
				all = append(all, r.Addrs...)
			}
			if addrTotal(all) > st.Tags.ListAddr {
				for i := range st.Ours {
					if st.Ours[i].Set == id {
						st.Ours[i].Wide = true
					}
				}
			}
		}
	}
	// programs seen earlier on our ports still count while they are stopped
	tcp, udp := copyListeners(st.Listeners), copyListeners(st.UDP)
	for k, progs := range st.Tags.Seen {
		m, num := tcp, k
		if p, ok := strings.CutPrefix(k, "udp:"); ok {
			m, num = udp, p
		}
		if n, err := strconv.Atoi(num); err == nil {
			for _, x := range progs {
				m[n] = append(m[n], Listener{Program: x})
			}
		}
	}
	for _, r := range st.Rules {
		if !st.ruleActive(r.Profile) {
			continue
		}
		c, ok := Classify(r, entries, tcp, udp)
		if !ok {
			continue
		}
		if r.Block {
			if c.Open && c.Enabled {
				st.Blocks = append(st.Blocks, c)
			}
			continue
		}
		st.Conflicts = append(st.Conflicts, c)
	}
	return st, nil
}

func copyListeners(m map[int][]Listener) map[int][]Listener {
	out := map[int][]Listener{}
	for p, ls := range m {
		out[p] = append(out[p], ls...)
	}
	return out
}

// ---------------------------------------------------------------- deciding which rules matter

// servesPortX: does a rule scoped to a program and/or service belong to
// whatever is (or was) listening on the port? unknown may count a listener
// whose program Windows did not name as a match (only for "could this open
// the port" questions).
func servesPortX(r FwRule, ls []Listener, unknown bool) bool {
	progAny := strings.EqualFold(r.Program, "Any") || r.Program == ""
	svcAny := strings.EqualFold(r.Service, "Any") || r.Service == "" || r.Service == "*"
	for _, l := range ls {
		progOK := progAny || (unknown && l.Program == "") || samePath(r.Program, l.Program) || strings.EqualFold(r.Program, l.Program)
		svcOK := svcAny
		for _, s := range l.Services {
			if strings.EqualFold(s, r.Service) {
				svcOK = true
			}
		}
		if progOK && svcOK {
			return true
		}
	}
	return false
}

// coversPort: does a LocalPort list cover port p?
func coversPort(spec []string, p int) bool {
	for _, x := range spec {
		if strings.EqualFold(x, "Any") {
			return true
		}
		if n, err := strconv.Atoi(x); err == nil && n == p {
			return true
		}
		if lo, hi, ok := parseRange(x); ok && p >= lo && p <= hi {
			return true
		}
	}
	return false
}

func parseRange(x string) (int, int, bool) {
	i := strings.IndexByte(x, '-')
	if i <= 0 {
		return 0, 0, false
	}
	lo, e1 := strconv.Atoi(strings.TrimSpace(x[:i]))
	hi, e2 := strconv.Atoi(strings.TrimSpace(x[i+1:]))
	if e1 != nil || e2 != nil || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

// coversOthers: does the spec open any port that is not in ours?
func coversOthers(spec []string, ours []int) bool {
	in := map[int]bool{}
	for _, p := range ours {
		in[p] = true
	}
	for _, x := range spec {
		if strings.EqualFold(x, "Any") {
			return true
		}
		if n, err := strconv.Atoi(x); err == nil {
			if !in[n] {
				return true
			}
			continue
		}
		if lo, hi, ok := parseRange(x); ok {
			for p := lo; p <= hi; p++ {
				if !in[p] {
					return true
				}
			}
			continue
		}
		// keywords like RPC, RPCEPMap, IPHTTPSIn: other ports
		return true
	}
	return false
}

// OpenToInternet: Any/Internet, an address block of 16 million or more, or
// any keyword we do not know (unknown means "assume open").
func OpenToInternet(remote []string) bool {
	for _, a := range remote {
		switch strings.ToLower(a) {
		case "localsubnet", "localsubnet4", "localsubnet6", "dns", "dhcp", "wins", "defaultgateway",
			"defaultgateway4", "defaultgateway6", "dns4", "dns6", "dhcp4", "dhcp6", "wins4", "wins6",
			"intranet", "intranet4", "intranet6", "rmtintranet", "rmtintranet4", "rmtintranet6":
			continue
		}
		if privateAddr(a) {
			continue // office network or VPN, not the internet
		}
		if !isAddress(a) || hugeBlock(a) {
			return true
		}
	}
	return false
}

var privateNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// privateAddr: the address or range lies completely inside a private network.
func privateAddr(a string) bool {
	first, last := a, a
	if i := strings.IndexByte(a, '-'); i > 0 {
		first, last = a[:i], a[i+1:]
	} else if i := strings.IndexByte(a, '/'); i > 0 {
		ip := net.ParseIP(a[:i])
		if ip == nil {
			return false
		}
		var n *net.IPNet
		if m := net.ParseIP(a[i+1:]); m != nil && m.To4() != nil && ip.To4() != nil {
			n = &net.IPNet{IP: ip.To4().Mask(net.IPMask(m.To4())), Mask: net.IPMask(m.To4())}
		} else if _, nn, err := net.ParseCIDR(a); err == nil {
			n = nn
		} else {
			return false
		}
		first = n.IP.String()
		lastIP := make(net.IP, len(n.IP))
		for k := range n.IP {
			lastIP[k] = n.IP[k] | ^n.Mask[k]
		}
		last = lastIP.String()
	}
	f, l := net.ParseIP(first), net.ParseIP(last)
	if f == nil || l == nil {
		return false
	}
	for _, n := range privateNets {
		if n.Contains(f) && n.Contains(l) {
			return true
		}
	}
	return false
}

// isAddress: a single IP, IP/prefix, IP/mask or IP-IP.
func isAddress(a string) bool {
	if i := strings.IndexAny(a, "/-"); i > 0 {
		return net.ParseIP(a[:i]) != nil
	}
	return net.ParseIP(a) != nil
}

func hugeBlock(a string) bool {
	if i := strings.IndexByte(a, '/'); i > 0 {
		ip := net.ParseIP(a[:i])
		if ip == nil {
			return false
		}
		mask := a[i+1:]
		ones := -1
		if m := net.ParseIP(mask); m != nil && m.To4() != nil {
			ones, _ = net.IPMask(m.To4()).Size()
		} else if n, err := strconv.Atoi(mask); err == nil {
			ones = n
		}
		if ones < 0 {
			return false
		}
		if ip.To4() != nil {
			return ones <= 8
		}
		return ones <= 32
	}
	if i := strings.IndexByte(a, '-'); i > 0 {
		lo, hi := net.ParseIP(a[:i]), net.ParseIP(a[i+1:])
		if lo == nil || hi == nil {
			return false
		}
		if l4, h4 := lo.To4(), hi.To4(); l4 != nil && h4 != nil {
			l := uint64(l4[0])<<24 | uint64(l4[1])<<16 | uint64(l4[2])<<8 | uint64(l4[3])
			h := uint64(h4[0])<<24 | uint64(h4[1])<<16 | uint64(h4[2])<<8 | uint64(h4[3])
			return h >= l && h-l+1 >= 1<<24
		}
		l16, h16 := lo.To16(), hi.To16()
		for k := 0; k < 4; k++ {
			if l16[k] != h16[k] {
				return true
			}
		}
	}
	return false
}

// ownPorts: every port (of one protocol) our entries stand for: the port
// entries and the ports our programs listen on.
func ownPorts(entries []Entry, kind string, ls map[int][]Listener) []int {
	out := portsOf(entries, kind)
	for _, e := range appsOf(entries) {
		out = append(out, appPorts(e.Path, ls)...)
	}
	return uniqInts(out)
}

// Classify decides if a rule opens (or, for block rules, shuts) one of our
// entries. tcp/udp tell which program serves each port.
func Classify(r FwRule, entries []Entry, tcp, udp map[int][]Listener) (Conflict, bool) {
	return classify(r, entries, tcp, udp, !r.Block)
}

// classify: unknown says whether a listener whose program Windows did not
// name may count as the rule's program.
func classify(r FwRule, entries []Entry, tcp, udp map[int][]Listener, unknown bool) (Conflict, bool) {
	proto := strings.ToUpper(r.Protocol)
	isTCP, isUDP := proto == "TCP" || proto == "6", proto == "UDP" || proto == "17"
	isAny := proto == "ANY" || proto == ""
	if !isTCP && !isUDP && !isAny {
		return Conflict{}, false // ICMP and the like
	}
	anyPort := false
	for _, x := range r.Ports {
		if strings.EqualFold(x, "Any") {
			anyPort = true
		}
	}
	// only for VPN connections: not reachable from the internet side
	if strings.EqualFold(r.IfType, "RemoteAccess") {
		return Conflict{}, false
	}
	// "all ports" rules tied to one named network adapter (Wi-Fi Direct and similar)
	if anyPort && r.IfAlias != "" && !strings.EqualFold(r.IfAlias, "Any") && r.Group != "" {
		return Conflict{}, false
	}
	progAny := strings.EqualFold(r.Program, "Any") || r.Program == ""
	svcAny := strings.EqualFold(r.Service, "Any") || r.Service == ""
	var covers []string
	broad := false
	for _, e := range entries {
		switch e.Kind {
		case KindTCP, KindUDP:
			if (e.Kind == KindTCP && !isTCP && !isAny) || (e.Kind == KindUDP && !isUDP && !isAny) {
				continue
			}
			ls := tcp[e.Port]
			if e.Kind == KindUDP {
				ls = udp[e.Port]
			}
			if anyPort {
				// all ports: of everything, or of one program/service that serves our port
				if progAny && svcAny || servesPortX(r, ls, unknown) {
					covers = append(covers, e.Key())
					broad = broad || !forOurApp(r, entries)
				}
				continue
			}
			// this port only: unless it is for another program than the one serving it
			if coversPort(r.Ports, e.Port) && (progAny && svcAny || len(ls) == 0 || servesPortX(r, ls, unknown)) {
				covers = append(covers, e.Key())
				own := ownPorts(entries, e.Kind, tcp)
				if e.Kind == KindUDP {
					own = ownPorts(entries, e.Kind, udp)
				}
				broad = broad || coversOthers(r.Ports, own)
			}
		case KindApp:
			if !progAny {
				// a rule for this very program (any port, any protocol)
				if samePath(r.Program, e.Path) && svcAny {
					covers = append(covers, e.Key())
				}
				continue
			}
			if !svcAny {
				continue
			}
			// a rule for every program on a port this program uses
			hit := false
			for _, m := range []struct {
				on bool
				ls map[int][]Listener
				k  string
			}{{isTCP || isAny, tcp, KindTCP}, {isUDP || isAny, udp, KindUDP}} {
				if !m.on {
					continue
				}
				for _, p := range appPorts(e.Path, m.ls) {
					if anyPort || coversPort(r.Ports, p) {
						hit = true
						broad = broad || anyPort || coversOthers(r.Ports, ownPorts(entries, m.k, m.ls))
					}
				}
			}
			if hit {
				covers = append(covers, e.Key())
			}
		}
	}
	if len(covers) == 0 {
		return Conflict{}, false
	}
	c := Conflict{Name: r.Name, Display: r.Display, Source: r.Source, Enabled: r.Enabled, Covers: covers,
		Open: OpenToInternet(r.Remote), Broad: broad,
		Tech: fmt.Sprintf("protocol=%s ports=%s program=%s service=%s iface=%s profile=%s", r.Protocol, strings.Join(r.Ports, ","), r.Program, r.Service, r.IfType, r.Profile)}
	if !progAny {
		c.Program = r.Program
	}
	c.Group = r.Group
	if c.Display == "" {
		c.Display = r.Name
	}
	c.Local = r.Source == "Local" || r.Source == ""
	c.CanClose = c.Enabled && c.Open && !c.Broad && c.Local
	return c, true
}

// forOurApp: the rule is limited to a program that is one of our entries
// (so switching it off only affects that program, which we open ourselves).
func forOurApp(r FwRule, entries []Entry) bool {
	for _, e := range appsOf(entries) {
		if samePath(r.Program, e.Path) {
			return true
		}
	}
	return false
}

// Uncovered lists listening TCP ports (other than ours) that no enabled allow
// rule opens: they stop working from outside when the firewall is switched on.
func (s Status) Uncovered(entries []Entry) []int {
	ours := ownPorts(entries, KindTCP, s.Listeners)
	var out []int
	for p, ls := range s.Listeners {
		if containsInt(ours, p) {
			continue
		}
		covered, blocked := false, false
		probe := []Entry{TCP(p)}
		for _, r := range s.Rules {
			if !r.Enabled || !s.ruleActive(r.Profile) {
				continue
			}
			// an unnamed program is not taken as "covered" (that would hide a warning)
			c, ok := classify(r, probe, map[int][]Listener{p: ls}, nil, r.Block)
			switch {
			case ok && r.Block && c.Open:
				blocked = true // Block wins over Allow once the firewall is on
			case ok && !r.Block && c.Open: // a rule only for the office network does not help clients from outside
				covered = true
			}
		}
		if !covered || blocked {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// OpenedByInbound: enabled allow rules open to the internet that start to
// work again when "Block all incoming connections" is switched off
// (display names, for the warning).
func (s Status) OpenedByInbound(entries []Entry) []string {
	var out []string
	for _, r := range s.Rules {
		if !r.Enabled || r.Block || !s.ruleActive(r.Profile) || !OpenToInternet(r.Remote) {
			continue
		}
		p := strings.ToUpper(r.Protocol)
		if p != "TCP" && p != "ANY" && p != "6" && p != "UDP" && p != "17" {
			continue
		}
		if forOurApp(r, entries) {
			continue // one of our programs: ours to decide
		}
		kind, ls := KindTCP, s.Listeners
		if p == "UDP" || p == "17" {
			kind, ls = KindUDP, s.UDP
		}
		if p != "ANY" && !coversOthers(r.Ports, ownPorts(entries, kind, ls)) {
			continue // only our ports: those are ours to decide
		}
		out = append(out, fmt.Sprintf("%s  (%s %s)", short(r.Display, 45), r.Protocol, short(strings.Join(r.Ports, ","), 20)))
	}
	sort.Strings(out)
	return out
}
