package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---------- entries, countries, ranges ----------

func TestEntries(t *testing.T) {
	cases := map[string]string{"808": "808", "TCP 808": "808", "udp 53": "udp:53", "APP C:\\A B\\x.exe": `app:c:\a b\x.exe`}
	for in, key := range cases {
		e, ok := ParseEntry(in)
		if !ok || e.Key() != key {
			t.Errorf("%q: %v %q", in, ok, e.Key())
		}
	}
	for _, bad := range []string{"", "0", "65536", "08", "TCP", "APP", "udp x", "1.5"} {
		if _, ok := ParseEntry(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	c := &Core{Dir: t.TempDir()}
	// version 3 wrote bare numbers
	os.WriteFile(c.portsPath(), []byte("\uFEFF808\r\n22\r\n"), 0o644)
	if got := entryKeys(c.LoadEntries()); fmt.Sprint(got) != "[22 808]" {
		t.Fatal(got)
	}
	c.SaveEntries([]Entry{AppEntry(`C:\Revit\RevitServer.exe`), UDP(1194), TCP(808), TCP(808)})
	got := c.LoadEntries()
	if len(got) != 3 || got[0].Kind != KindTCP || got[1].Kind != KindUDP || got[2].Path != `C:\Revit\RevitServer.exe` {
		t.Fatalf("%+v", got)
	}
	c.SaveCountries([]string{"de", "IR", "XX", "IR"})
	if fmt.Sprint(c.LoadCountries()) != "[DE IR]" {
		t.Fatal(c.LoadCountries())
	}
	if appID(`C:\X\a.exe`) != appID(`c:/x/A.EXE`) || !strings.HasPrefix(appID("a"), "APP-") || len(appID("a")) != 12 {
		t.Fatal("app ids")
	}
	if s, i, ok := splitRuleName("CountryIPFilter-APP-0a1b2c3d-03"); !ok || s != "APP-0a1b2c3d" || i != 3 {
		t.Fatal(s, i, ok)
	}
	// old records of version 3 (port numbers with commas) still read
	off := parseOffLines("wcf\t808,443\nx\tudp:53|app:c:\\a,b.exe")
	if fmt.Sprint(off[0].Covers) != "[808 443]" || fmt.Sprint(off[1].Covers) != `[udp:53 app:c:\a,b.exe]` {
		t.Fatalf("%+v", off)
	}
	if len(countries) < 240 {
		t.Fatal("country list")
	}
	for i := 1; i < len(countries); i++ {
		if countries[i-1].Code >= countries[i].Code || countries[i].EN == "" || countries[i].FA == "" {
			t.Fatalf("country table not sorted or empty: %v", countries[i])
		}
	}
}

func TestAggregate(t *testing.T) {
	got := Aggregate([]string{"1.2.0.0/24", "1.2.1.0/24", "1.2.2.0/23", "1.2.3.0/24", "5.5.5.5/16", "10.1.0.0/16", "8.0.0.0/8", "9.0.0.0/8", "1.2.4.0/255.255.255.0", "bad"})
	want := "[1.2.0.0/22 1.2.4.0/24 5.5.0.0/16 8.0.0.0/8 9.0.0.0/8]"
	if fmt.Sprint(got) != want {
		t.Fatalf("got %v", got)
	}
	// a network that only starts outside a private one still touches it
	if got := Aggregate([]string{"172.20.5.0/10", "192.0.0.0/8", "100.0.0.0/8", "223.0.0.0/7", "11.0.0.0/8"}); fmt.Sprint(got) != "[11.0.0.0/8]" {
		t.Fatalf("reserved overlap: %v", got)
	}
	// random lists: exactly the same addresses, nothing overlapping, nothing above /8
	r := rand.New(rand.NewSource(1))
	for round := 0; round < 200; round++ {
		var in []string
		for i := 0; i < 50; i++ {
			bits := 8 + r.Intn(25)
			in = append(in, prefix{start: uint32(r.Intn(4)+20)<<24 | uint32(r.Intn(1<<24)), bits: bits}.String())
		}
		out := Aggregate(in)
		inSet, outSet := cover(in), cover(out)
		if inSet != outSet {
			t.Fatalf("addresses changed: %v -> %v", in, out)
		}
		for i := 1; i < len(out); i++ {
			a, _ := parsePrefix(out[i-1])
			b, _ := parsePrefix(out[i])
			if uint64(a.start)+a.size() > uint64(b.start) {
				t.Fatalf("overlap %v %v", a, b)
			}
		}
	}
}

// cover: a fingerprint of the addresses (merged intervals as text).
func cover(list []string) string {
	type iv struct{ lo, hi uint64 }
	var ivs []iv
	for _, s := range list {
		if p, ok := parsePrefix(s); ok && p.bits >= 8 && !reservedOverlap(p) {
			ivs = append(ivs, iv{uint64(p.start), uint64(p.start) + p.size()})
		}
	}
	sort.Slice(ivs, func(i, j int) bool { return ivs[i].lo < ivs[j].lo })
	var out []iv
	for _, x := range ivs {
		if n := len(out); n > 0 && x.lo <= out[n-1].hi {
			out[n-1].hi = max(out[n-1].hi, x.hi)
			continue
		}
		out = append(out, x)
	}
	return fmt.Sprint(out)
}

func TestParseRanges(t *testing.T) {
	r, err := ParseRanges([]byte(ripeJSON(600, 2)))
	if err != nil || len(r) != 600 {
		t.Fatalf("got %d %v", len(r), err)
	}
	for _, x := range r {
		if x == "0.0.0.0/0" || strings.Contains(x, ":") || strings.HasPrefix(x, "10.") {
			t.Fatal("dangerous, private or ipv6 entry accepted")
		}
	}
	if _, err := ParseRanges([]byte(`{"data":{"resources":{"ipv4":[]}}}`)); err == nil {
		t.Fatal("an empty list must be refused")
	}
	// a small country is fine
	if r, err := ParseRanges([]byte(`{"data":{"resources":{"ipv4":["194.1.2.0/24"]}}}`)); err != nil || len(r) != 1 {
		t.Fatal(r, err)
	}
	// plain list with BOM and CRLF, host bits cleared
	r, err = ParseRanges([]byte("\uFEFF11.0.0.5/24\r\n11.0.2.0/24\r\n"))
	if err != nil || r[0] != "11.0.0.0/24" {
		t.Fatalf("plain list: %v %v", r, err)
	}
	html := "<html><pre>" + ripeJSON(600, 2) + "</pre></html>"
	if r, err := ParseRanges([]byte(html)); err != nil || len(r) != 600 {
		t.Fatalf("page saved as HTML: %d %v", len(r), err)
	}
	var big []string
	for i := 1; i < 224; i++ {
		if i != 10 && i != 127 {
			big = append(big, fmt.Sprintf("%d.0.0.0/8", i))
		}
	}
	if checkTotal(Aggregate(big)) == nil {
		t.Fatal("a list of almost the whole internet must be refused")
	}
}

func TestScriptsShape(t *testing.T) {
	var r []string
	for i := 0; i < 1966; i++ {
		r = append(r, fmt.Sprintf("5.%d.%d.0/24", i/250, i%250))
	}
	s := ApplyScript(r, []Entry{TCP(808), TCP(22), UDP(1194), AppEntry(`C:\it's\a.exe`)}, map[string]string{"CC": "IR"})
	for _, want := range []string{"@{Id='TCP'; Proto='TCP'; Ports=@('22','808'); Prog=''}", "@{Id='UDP'; Proto='UDP'; Ports=@('1194'); Prog=''}", "Proto='Any'; Ports=@(); Prog='C:\\it''s\\a.exe'}", "SetTag 'CC' 'IR'"} {
		if !strings.Contains(s, want) {
			t.Fatalf("apply script lacks %s", want)
		}
	}
	if strings.Count(s, "'5.") != 1966 || strings.Contains(s, "SetTag 'OK'") {
		t.Fatal("apply script")
	}
	st := StatusScript()
	for _, want := range []string{"$pkg -ne", "RULE|", "TASK|", "IPF-OK", "-PolicyStore ActiveStore", "AllowLocalFirewallRules", "LISTEN|", "LISTENU|", "ACTIVE|", "TASKARGS|", "$r.Profile", "OLDTASK|", "'OLD'"} {
		if !strings.Contains(st, want) {
			t.Fatalf("status script lacks %s", want)
		}
	}
	if q := psQuote("it's"); q != "'it''s'" {
		t.Fatal(q)
	}
	p, _ := ParseStatus("\uFEFFPROFILE|Public|True|Block|NotConfigured\r\nOURS|CountryIPFilter-TCP-01|True|808|400\r\nRULE|"+b64("n1")+"|Local|True|TCP|808|Any|"+b64("Any")+"|"+b64("Any")+"|"+b64("نام | با خط")+"\r\nTASK|False\r\nIPF-OK\r\n", []Entry{TCP(808)})
	if len(p.Conflicts) != 1 || p.Conflicts[0].Display != "نام | با خط" || !p.Conflicts[0].CanClose || !p.RulesMatch([]Entry{TCP(808)}) || len(p.Profiles) != 1 {
		t.Fatalf("parse %+v", p)
	}
	if _, err := ParseStatus("garbage", nil); err == nil {
		t.Fatal("missing marker must fail")
	}
}

func TestClassify(t *testing.T) {
	ours := []Entry{TCP(808)}
	ls := map[int][]Listener{808: {{Program: `C:\revit\revitserver.exe`, Services: []string{"NetTcpActivator"}}}}
	cases := []struct {
		name                  string
		r                     FwRule
		hit, open, broad, can bool
	}{
		{"exact port open", FwRule{Enabled: true, Protocol: "TCP", Ports: []string{"808"}, Remote: []string{"Any"}, Program: "Any", Service: "Any", Source: "Local"}, true, true, false, true},
		{"protocol number", FwRule{Protocol: "6", Ports: []string{"808"}, Remote: []string{"Any"}, Source: "Local"}, true, true, false, true},
		{"udp ignored for a tcp port", FwRule{Protocol: "UDP", Ports: []string{"808"}, Remote: []string{"Any"}}, false, false, false, false},
		{"limited ips", FwRule{Protocol: "TCP", Ports: []string{"808"}, Remote: []string{"5.5.5.5"}, Source: "Local"}, true, false, false, false},
		{"huge range", FwRule{Protocol: "TCP", Ports: []string{"808"}, Remote: []string{"0.0.0.0-255.255.255.255"}, Source: "Local"}, true, true, false, true},
		{"slash 8", FwRule{Protocol: "TCP", Ports: []string{"808"}, Remote: []string{"1.0.0.0/255.0.0.0"}, Source: "Local"}, true, true, false, true},
		{"808 and 3389", FwRule{Protocol: "TCP", Ports: []string{"808", "3389"}, Remote: []string{"Any"}, Source: "Local"}, true, true, true, false},
		{"range 1-65535", FwRule{Protocol: "TCP", Ports: []string{"1-65535"}, Remote: []string{"Any"}, Source: "Local"}, true, true, true, false},
		{"all open", FwRule{Protocol: "Any", Ports: []string{"Any"}, Remote: []string{"Any"}, Program: "Any", Service: "Any", Source: "Local"}, true, true, true, false},
		{"System any port", FwRule{Protocol: "TCP", Ports: []string{"Any"}, Remote: []string{"Any"}, Program: "System", Service: "Any", Source: "Local"}, false, false, false, false},
		{"other program any port", FwRule{Protocol: "TCP", Ports: []string{"Any"}, Remote: []string{"Any"}, Program: `C:\app\x.exe`, Service: "Any"}, false, false, false, false},
		{"service scoped", FwRule{Protocol: "TCP", Ports: []string{"Any"}, Remote: []string{"Any"}, Program: `%SystemRoot%\system32\svchost.exe`, Service: "Dnscache"}, false, false, false, false},
		{"gpo", FwRule{Protocol: "TCP", Ports: []string{"808"}, Remote: []string{"Any"}, Source: "GroupPolicy"}, true, true, false, false},
		{"other port", FwRule{Protocol: "TCP", Ports: []string{"443"}, Remote: []string{"Any"}}, false, false, false, false},
		{"local subnet", FwRule{Protocol: "TCP", Ports: []string{"808"}, Remote: []string{"LocalSubnet"}, Source: "Local"}, true, false, false, false},
		{"unknown keyword", FwRule{Protocol: "TCP", Ports: []string{"808"}, Remote: []string{"PlayToDevice"}, Source: "Local"}, true, true, false, true},
		{"intranet keyword", FwRule{Protocol: "TCP", Ports: []string{"808"}, Remote: []string{"Intranet4"}, Source: "Local"}, true, false, false, false},
		{"office network 10/8", FwRule{Protocol: "TCP", Ports: []string{"808"}, Remote: []string{"10.0.0.0/255.0.0.0"}, Source: "Local"}, true, false, false, false},
		{"public /8", FwRule{Protocol: "TCP", Ports: []string{"808"}, Remote: []string{"11.0.0.0/8"}, Source: "Local"}, true, true, false, true},
		{"nettcp service, not serving 808", FwRule{Protocol: "TCP", Ports: []string{"Any"}, Remote: []string{"Any"}, Program: "Any", Service: "NetTcpPortSharing", Source: "Local"}, false, false, false, false},
		{"nettcp service serving 808", FwRule{Protocol: "TCP", Ports: []string{"Any"}, Remote: []string{"Any"}, Program: "Any", Service: "NetTcpActivator", Source: "Local"}, true, true, true, false},
		{"revit program serving 808", FwRule{Protocol: "TCP", Ports: []string{"Any"}, Remote: []string{"Any"}, Program: `C:\Revit\RevitServer.exe`, Service: "Any", Source: "Local"}, true, true, true, false},
	}
	for _, c := range cases {
		c.r.Enabled = true
		got, hit := Classify(c.r, ours, ls, nil)
		if hit != c.hit || got.Open != c.open || got.Broad != c.broad || got.CanClose != c.can {
			t.Errorf("%s: hit=%v open=%v broad=%v can=%v", c.name, hit, got.Open, got.Broad, got.CanClose)
		}
	}
}

func TestClassifyUDPAndPrograms(t *testing.T) {
	revit := `C:\Revit\RevitServer.exe`
	entries := []Entry{UDP(1194), AppEntry(revit)}
	tcp := map[int][]Listener{808: {{Program: revit}}, 9000: {{Program: revit}}}
	udp := map[int][]Listener{1194: {{Program: `C:\OpenVPN\openvpn.exe`}}}
	open := []string{"Any"}
	cases := []struct {
		name                  string
		r                     FwRule
		covers                string
		open, broad, can, hit bool
	}{
		{"tcp rule on the udp port", FwRule{Protocol: "TCP", Ports: []string{"1194"}, Remote: open, Source: "Local"}, "", false, false, false, false},
		{"udp rule on the udp port", FwRule{Protocol: "UDP", Ports: []string{"1194"}, Remote: open, Source: "Local"}, "[udp:1194]", true, false, true, true},
		{"udp rule, more ports", FwRule{Protocol: "17", Ports: []string{"1194", "53"}, Remote: open, Source: "Local"}, "[udp:1194]", true, true, false, true},
		{"rule for the program", FwRule{Protocol: "Any", Ports: []string{"Any"}, Program: revit, Remote: open, Source: "Local"}, "[app:" + strings.ToLower(revit) + "]", true, false, true, true},
		{"rule for the program, other spelling", FwRule{Protocol: "TCP", Ports: []string{"808"}, Program: `c:\revit\revitserver.exe`, Remote: open, Source: "Local"}, "[app:" + strings.ToLower(revit) + "]", true, false, true, true},
		{"port rule on a port the program uses", FwRule{Protocol: "TCP", Ports: []string{"9000"}, Remote: open, Source: "Local"}, "[app:" + strings.ToLower(revit) + "]", true, false, true, true},
		{"port rule on more ports", FwRule{Protocol: "TCP", Ports: []string{"9000", "3389"}, Remote: open, Source: "Local"}, "[app:" + strings.ToLower(revit) + "]", true, true, false, true},
		{"everything open", FwRule{Protocol: "Any", Ports: []string{"Any"}, Remote: open, Source: "Local"}, "[udp:1194 app:" + strings.ToLower(revit) + "]", true, true, false, true},
		{"another program", FwRule{Protocol: "Any", Ports: []string{"Any"}, Program: `C:\x.exe`, Remote: open}, "", false, false, false, false},
		{"port the program does not use", FwRule{Protocol: "TCP", Ports: []string{"443"}, Remote: open}, "", false, false, false, false},
	}
	for _, c := range cases {
		c.r.Enabled = true
		got, hit := Classify(c.r, entries, tcp, udp)
		cov := ""
		if hit {
			cov = fmt.Sprint(got.Covers)
		}
		if hit != c.hit || cov != c.covers || got.Open != c.open || got.Broad != c.broad || got.CanClose != c.can {
			t.Errorf("%s: hit=%v covers=%s open=%v broad=%v can=%v", c.name, hit, cov, got.Open, got.Broad, got.CanClose)
		}
	}
	// a program's own "all ports" rule is not broad when the program is ours
	got, _ := Classify(FwRule{Enabled: true, Protocol: "TCP", Ports: []string{"Any"}, Program: revit, Remote: open, Source: "Local"}, []Entry{TCP(808), AppEntry(revit)}, tcp, nil)
	if got.Broad || !got.CanClose || len(got.Covers) != 2 {
		t.Fatalf("own program rule: %+v", got)
	}
}

// ---------- whole stories ----------

func TestStory(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{
		{name: "wcf", display: "Net.TCP", source: "Local", open: true, enabled: true},
		{name: "psu", display: "user 1", source: "Local", open: false, enabled: true},
		{name: "gpo", display: "From policy", source: "GroupPolicy", open: true, enabled: false},
	}}
	a, ui, c := newTestApp(t, fw)
	if ui.view.On || ui.view.Level != LevelOrange || ui.view.Main != MainOn {
		t.Fatalf("start: %+v", ui.view)
	}
	if ui.view.Rows[0].State != OpenState || ui.view.Rows[0].Service != "Revit Server" || ui.view.Rows[0].Item != "TCP 808" {
		t.Fatal(ui.view.Rows)
	}

	// user says no to the confirmation: nothing happens
	ui.answer = false
	a.Main()
	if len(fw.ours) != 0 {
		t.Fatal("changed without confirmation")
	}
	ui.answer = true

	// turn on: rules written, safe old rule closed automatically, task on, green
	a.Main()
	if len(fw.ours) != 5 || fw.others[0].enabled || !fw.others[1].enabled || !fw.task {
		t.Fatalf("turn on: ours=%d wcf=%v psu=%v task=%v", len(fw.ours), fw.others[0].enabled, fw.others[1].enabled, fw.task)
	}
	if ui.view.Level != LevelGreen || !ui.view.On || ui.view.Rows[0].State != GreenState {
		t.Fatalf("after on: %+v", ui.view)
	}
	tags := parseTags(fw.desc)
	if fmt.Sprint(tags.Countries) != "[IR]" || tags.ListCount != 1966 || tags.ListAddr != 1966*1024 {
		t.Fatalf("tags: %+v", tags)
	}

	// someone opens the old rule again: red with a close button that works
	fw.others[0].enabled = true
	a.Refresh()
	p, ok := ui.problem(FixCloseRule)
	if ui.view.Level != LevelRed || !ok || ui.view.Rows[0].State != OpenState {
		t.Fatalf("reopened: %+v", ui.view)
	}
	a.Fix(p)
	if fw.others[0].enabled || ui.view.Level != LevelGreen {
		t.Fatal("close rule fix failed")
	}

	// add a port while on: applied at once (Persian digits are fine)
	a.AddPort("۲۲", "TCP")
	if fw.tcpPorts() != "[22 808]" || ui.view.Level != LevelGreen {
		t.Fatalf("add port: %v %v %+v", fw.tcpPorts(), ui.view.Level, ui.view.Problems)
	}
	told := len(ui.told)
	a.AddPort("abc", "TCP")
	a.AddPort("22", "TCP")
	if len(ui.told) != told+2 {
		t.Fatal("bad ports must be refused")
	}
	a.RemoveEntry("22")
	if fw.tcpPorts() != "[808]" {
		t.Fatal("remove port")
	}
	a.RemoveEntry("808")
	if fmt.Sprint(entryKeys(c.LoadEntries())) != "[808]" {
		t.Fatal("last entry must stay while on")
	}

	// turn off: everything back
	a.TurnOff()
	if len(fw.ours) != 0 || !fw.others[0].enabled || fw.task || fw.desc != "" {
		t.Fatalf("turn off: ours=%d wcf=%v task=%v", len(fw.ours), fw.others[0].enabled, fw.task)
	}
	if ui.view.On || ui.view.Level != LevelOrange || ui.view.Main != MainOn {
		t.Fatalf("view after off: %+v", ui.view)
	}
	// off: the last entry may go
	a.RemoveEntry("808")
	if len(c.LoadEntries()) != 0 {
		t.Fatal("remove while off")
	}
}

func TestNeedsCountryAndPort(t *testing.T) {
	fw := &fakeFW{}
	c := newCore(t, fw)
	a, ui, _ := startApp(t, c, lists)
	if ui.view.Action != ActTurnOn || !strings.Contains(ui.view.Desc, "کشور") {
		t.Fatalf("fresh: %+v", ui.view)
	}
	a.Main()
	if len(fw.ours) != 0 || !strings.Contains(ui.lastTell(), "کشور") {
		t.Fatal("must ask for a country first")
	}
	a.AddCountry("IR")
	a.Main()
	if len(fw.ours) != 0 || !strings.Contains(ui.lastTell(), "پورت") {
		t.Fatal("must ask for a port first")
	}
	a.AddPort("443", "TCP")
	a.Main()
	if len(fw.ours) != 5 || ui.view.Level != LevelGreen {
		t.Fatalf("on: %d %+v", len(fw.ours), ui.view)
	}
	if a.AddCountry("ZZ") || a.AddCountry("IR") {
		t.Fatal("unknown or doubled country accepted")
	}
}

func TestMultipleCountries(t *testing.T) {
	fw := &fakeFW{}
	a, ui, c := newTestApp(t, fw)
	a.Main()
	if fw.total("TCP") != 1966 {
		t.Fatal(fw.total("TCP"))
	}
	// add Germany while on: both lists, written at once
	a.AddCountry("DE")
	if fw.total("TCP") != 1966+700 || fmt.Sprint(parseTags(fw.desc).Countries) != "[DE IR]" || ui.view.Level != LevelGreen {
		t.Fatalf("add country: %d %s %+v", fw.total("TCP"), fw.desc, ui.view.Problems)
	}
	if !strings.Contains(ui.lastTell(), CountryName("DE")) {
		t.Fatal("the user must be told")
	}
	// remove Iran: Germany only
	a.RemoveCountry("IR")
	if fw.total("TCP") != 700 || fmt.Sprint(c.LoadCountries()) != "[DE]" {
		t.Fatal("remove country")
	}
	// the last country cannot go while on
	a.RemoveCountry("DE")
	if fmt.Sprint(c.LoadCountries()) != "[DE]" {
		t.Fatal("last country removed")
	}
	// adding fails when the list cannot be downloaded: everything stays
	offline(t, c)
	if a.AddCountry("IR") || fmt.Sprint(c.LoadCountries()) != "[DE]" || fw.total("TCP") != 700 {
		t.Fatal("failed add must be undone")
	}
	// a country with no list on the server fails too
	c.HTTP = clientFor(withRipe(t, lists, 200))
	if a.AddCountry("FR") || fmt.Sprint(c.LoadCountries()) != "[DE]" {
		t.Fatal("country without a list")
	}
	// the countries file changed by hand: the rules no longer match
	c.SaveCountries([]string{"DE", "IR"})
	a.Refresh()
	p, ok := ui.problem(FixUpdateList)
	if !ok || !strings.Contains(p.Text, CountryName("IR")) {
		t.Fatalf("mismatch must show: %+v", ui.view.Problems)
	}
	a.Fix(p)
	if fw.total("TCP") != 2666 || ui.view.Level != LevelGreen {
		t.Fatal("update after a hand change")
	}
}

func TestUDPAndProgram(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "RevitServer.exe")
	os.WriteFile(exe, []byte("MZ"), 0o644)
	fw := &fakeFW{listen: map[int]string{9000: exe}}
	a, ui, _ := newTestApp(t, fw)
	a.Main()
	a.AddPort("1194", "UDP")
	a.AddPort("UDP 53", "TCP")
	if !a.AddProgram(exe) {
		t.Fatalf("program: %v", ui.told)
	}
	ids := fw.setIDs()
	if len(ids) != 3 || ids[0] != appID(exe) || ids[1] != "TCP" || ids[2] != "UDP" || fmt.Sprint(fw.set("UDP")[0].ports) != "[53 1194]" || fw.set(appID(exe))[0].prog != exe {
		t.Fatalf("sets: %v", ids)
	}
	if ui.view.Level != LevelGreen || len(ui.view.Rows) != 4 || ui.view.Rows[3].Item != "برنامه" || ui.view.Rows[3].Service != "RevitServer.exe" {
		t.Fatalf("view: %+v", ui.view)
	}
	// refused programs
	for _, bad := range []string{`C:\Windows\System32\svchost.exe`, filepath.Join(t.TempDir(), "x.txt"), filepath.Join(t.TempDir(), "missing.exe"), exe} {
		if a.AddProgram(bad) {
			t.Errorf("%s accepted", bad)
		}
	}
	// someone opens the program to the world: found and closed
	fw.others = append(fw.others, &fakeRule{name: "rv", display: "Revit Server", source: "Local", open: true, enabled: true, proto: "Any", ports: "Any", program: exe})
	a.Refresh()
	p, ok := ui.problem(FixCloseRule)
	if !ok || ui.view.Rows[3].State != OpenState {
		t.Fatalf("program rule: %+v", ui.view.Problems)
	}
	a.Fix(p)
	if fw.others[0].enabled || ui.view.Level != LevelGreen {
		t.Fatal("close program rule")
	}
	// a TCP rule on the UDP port does not matter; a UDP one does
	fw.others = append(fw.others, &fakeRule{name: "t", display: "TCP 1194", source: "Local", open: true, enabled: true, ports: "1194"})
	a.Refresh()
	if ui.view.Level != LevelGreen {
		t.Fatalf("tcp rule on udp port: %+v", ui.view.Problems)
	}
	fw.others = append(fw.others, &fakeRule{name: "u", display: "UDP 1194", source: "Local", open: true, enabled: true, ports: "1194", proto: "UDP"})
	a.Refresh()
	if ui.view.Level != LevelRed || ui.view.Rows[2].State != OpenState {
		t.Fatalf("udp rule: %+v", ui.view.Rows)
	}
	// removing the program removes its rules; its old rule comes back
	a.RemoveEntry(AppEntry(exe).Key())
	if len(fw.set(appID(exe))) != 0 || !fw.others[0].enabled {
		t.Fatal("remove program")
	}
	// the program folder copied elsewhere: entries come back from the rules
	c2 := newCore(t, fw)
	a2, _, _ := startApp(t, c2, lists)
	if fmt.Sprint(entryKeys(c2.LoadEntries())) != "[808 udp:53 udp:1194]" || fmt.Sprint(c2.LoadCountries()) != "[IR]" {
		t.Fatalf("recovered: %v %v", entryKeys(c2.LoadEntries()), c2.LoadCountries())
	}
	_ = a2
}

func TestMigrationFromV3(t *testing.T) {
	var addrs []string
	for i := 0; i < 900; i++ {
		addrs = append(addrs, fmt.Sprintf("5.%d.%d.0/24", i/250, i%250))
	}
	fw := &fakeFW{
		old:     []fakeOld{{name: "IranIPFilter-01", ports: []int{808, 22}, addrs: addrs[:400]}, {name: "IranIPFilter-02", ports: []int{808, 22}, addrs: addrs[400:800]}, {name: "IranIPFilter-03", ports: []int{808, 22}, addrs: addrs[800:]}},
		oldTask: true,
		oldDesc: ruleDesc + " [OK=2026-09-01T10:00:00Z,900] [LAST=2026-09-01T10:00:00Z,OK,task] [OFF=" + encodeOff([]OffRule{{Name: "wcf", Covers: []string{"808"}}}) + "]",
		others:  []*fakeRule{{name: "wcf", display: "Net.TCP", source: "Local", open: true, enabled: false}},
	}
	// version 3 left its ports file
	c := newCore(t, fw)
	os.WriteFile(c.portsPath(), []byte("22\r\n808\r\n"), 0o644)
	a, ui, _ := startApp(t, c, lists)
	if len(fw.old) != 0 || fw.oldTask {
		t.Fatal("old rules and task must be gone")
	}
	if fw.total("TCP") != len(Aggregate(addrs)) || fw.tcpPorts() != "[22 808]" || !fw.task {
		t.Fatalf("new rules: %d %s task=%v", fw.total("TCP"), fw.tcpPorts(), fw.task)
	}
	if fmt.Sprint(c.LoadCountries()) != "[IR]" || !strings.Contains(ui.lastTell(), "منتقل") {
		t.Fatalf("countries %v / %v", c.LoadCountries(), ui.told)
	}
	if ui.view.Level != LevelGreen {
		t.Fatalf("after migration: %+v", ui.view.Problems)
	}
	// the record of the rule version 3 switched off is kept
	a.TurnOff()
	if !fw.others[0].enabled {
		t.Fatal("the rule switched off by version 3 must come back")
	}
}

func TestMigrationFailsSafely(t *testing.T) {
	fw := &fakeFW{old: []fakeOld{{name: "IranIPFilter-01", ports: []int{808}, addrs: []string{"5.1.0.0/16"}}}, failApply: true}
	c := newCore(t, fw)
	a, ui, _ := startApp(t, c, lists)
	p, ok := ui.problem(FixMigrate)
	if len(fw.old) != 1 || !ok {
		t.Fatalf("old rules must stay and be reported: %+v", ui.view.Problems)
	}
	fw.failApply = false
	a.Fix(p)
	if len(fw.old) != 0 || fw.total("TCP") != 1 {
		t.Fatal("retry")
	}
}

func TestBroadRuleAndFirewall(t *testing.T) {
	fw := &fakeFW{fwOff: true, others: []*fakeRule{{name: "all", display: "Everything", source: "Local", open: true, enabled: true, ports: "Any"}}}
	a, ui, _ := newTestApp(t, fw)
	a.Main() // turn on: also switches the firewall on, in the same step
	if !fw.others[0].enabled {
		t.Fatal("broad rule must never be closed automatically")
	}
	if fw.fwOff || !strings.Contains(ui.asked[0], "Windows Firewall") {
		t.Fatal("turning on must switch the firewall on and say so")
	}
	// the "everything open" rule also lets RDP in, so no lock-out warning is needed here
	if strings.Contains(ui.asked[0], "هشدار") {
		t.Fatal("needless warning")
	}
	bp, ok := ui.problem(FixCloseBroad)
	if !ok || ui.view.Level != LevelRed || ui.view.Action != ActRefresh {
		t.Fatalf("problems: %+v", ui.view)
	}
	ui.answer = false
	a.Fix(bp)
	if !fw.others[0].enabled {
		t.Fatal("closed although the user said no")
	}
	ui.answer = true
	a.Fix(bp)
	if fw.others[0].enabled || ui.view.Level != LevelGreen {
		t.Fatalf("broad close: %v %+v", fw.others[0].enabled, ui.view.Problems)
	}
	a.TurnOff() // broad rule comes back
	if !fw.others[0].enabled {
		t.Fatal("turn off must reopen the broad rule")
	}
}

func TestManualList(t *testing.T) {
	fw := &fakeFW{}
	a, ui, c := newTestApp(t, fw)
	c.SaveCountries([]string{"DE", "IR"})
	offline(t, c)
	a.Main()
	if len(fw.ours) != 0 {
		t.Fatal("rules without a list")
	}
	p, ok := ui.problem(FixManualList)
	if !ok || ui.view.Level != LevelGrey {
		t.Fatalf("manual problem missing: %+v", ui.view)
	}
	// cancelled file choice: nothing changes
	a.Fix(p)
	if len(fw.ours) != 0 || ui.opened[0] != RipeURL("DE") {
		t.Fatal("cancel")
	}
	// wrong file for the second country
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("<html>"), 0o644)
	de := filepath.Join(dir, "de.json")
	os.WriteFile(de, []byte(lists["DE"]), 0o644)
	ir := filepath.Join(dir, "ir.json")
	os.WriteFile(ir, []byte(lists["IR"]), 0o644)
	ui.pick = []string{de, bad}
	a.Fix(p)
	if len(fw.ours) != 0 {
		t.Fatal("bad file accepted")
	}
	ui.pick = []string{de, ir}
	a.Fix(p)
	if fw.total("TCP") != 2666 || !ui.view.On || fmt.Sprint(parseTags(fw.desc).Countries) != "[DE IR]" {
		t.Fatalf("manual list not applied: %d", fw.total("TCP"))
	}
	if _, still := ui.problem(FixManualList); still {
		t.Fatal("manual problem must disappear")
	}
}

func TestManualListWhenOffAsksFirst(t *testing.T) {
	fw := &fakeFW{}
	a, ui, c := newTestApp(t, fw)
	offline(t, c)
	good := filepath.Join(t.TempDir(), "data.json")
	os.WriteFile(good, []byte(ripeJSON(900, 2)), 0o644)
	ui.pick = []string{good}
	ui.answers = []bool{false} // "turn protection on now?" -> No
	a.Fix(Problem{Kind: FixManualList})
	if len(fw.ours) != 0 {
		t.Fatal("must not turn on without asking")
	}
	if a.pending == nil || len(a.pending.Ranges) != 900 {
		t.Fatal("list must be kept for later")
	}
	// the kept list is only used for the same countries
	c.SaveCountries([]string{"DE", "IR"})
	a.Refresh()
	a.Main()
	if len(fw.ours) != 0 {
		t.Fatal("a list for other countries was used")
	}
	c.SaveCountries([]string{"IR"})
	a.Refresh()
	a.Main()
	if fw.total("TCP") != 900 {
		t.Fatal("kept list not used")
	}
}

func TestJalali(t *testing.T) {
	d := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	if got := jalali(d); got != ltr("1405/07/04") {
		t.Fatal(got)
	}
	if got := jalali(time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)); got != ltr("1405/01/01") {
		t.Fatal(got)
	}
}

func TestFirewallWarnsAboutServices(t *testing.T) {
	fw := &fakeFW{fwOff: true, listen: map[int]string{3389: "System", 1521: `C:\oracle\tnslsnr.exe`, 808: "System"}}
	a, ui, _ := newTestApp(t, fw)
	if !strings.Contains(ui.view.Desc, "Firewall") || ui.view.Level != LevelOrange || len(ui.view.Problems) != 0 {
		t.Fatalf("firewall off, protection off: %+v", ui.view)
	}
	ui.answer = false
	a.Main()
	q := ui.lastAsk()
	if !fw.fwOff || len(fw.ours) != 0 || !strings.Contains(q, "Remote Desktop") || !strings.Contains(q, "1521") || strings.Contains(q, "\u202A808  ") {
		t.Fatalf("must list the services that stop and respect No:\n%s", q)
	}
}

func TestRemoteDesktopNeverClosedSilently(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "rdp", display: "Remote Desktop - User Mode (TCP-In)", source: "Local", open: true, enabled: true, ports: "3389"}}}
	a, ui, _ := newTestApp(t, fw)
	ui.answers = []bool{true} // yes to the 3389 warning when adding
	a.AddPort("3389", "TCP")
	if !strings.Contains(ui.asked[0], "Remote Desktop") {
		t.Fatal("adding 3389 must warn even when protection is off")
	}
	ui.answers = []bool{true}
	a.AddPort("3389", "UDP")
	if !strings.Contains(ui.lastAsk(), "Remote Desktop") {
		t.Fatal("UDP 3389 is Remote Desktop too")
	}
	a.Main()
	if !strings.Contains(ui.lastAsk(), "هشدار") {
		t.Fatal("turn on must warn about remote-management ports")
	}
	if !fw.others[0].enabled {
		t.Fatal("RDP rule closed automatically")
	}
	if _, ok := ui.problem(FixCloseBroad); !ok || ui.view.Level != LevelRed {
		t.Fatalf("RDP rule must be a careful manual problem: %+v", ui.view.Problems)
	}
}

func TestOffWordingWhenClosed(t *testing.T) {
	_, ui, _ := newTestApp(t, &fakeFW{})
	if strings.Contains(ui.view.Desc, "همه‌ی دنیا") || ui.view.Rows[0].State != ClosedState {
		t.Fatalf("closed ports wording: %s / %v", ui.view.Desc, ui.view.Rows)
	}
}

func TestFailedDownloadTellsUser(t *testing.T) {
	fw := &fakeFW{}
	a, ui, c := newTestApp(t, fw)
	a.Main()
	offline(t, c)
	a.Fix(Problem{Kind: FixUpdateList})
	if _, ok := ui.problem(FixManualList); !ok {
		t.Fatal("failed download must offer the manual list")
	}
	if !strings.Contains(ui.lastTell(), "دانلود نشد") {
		t.Fatal("user must be told the list was not refreshed")
	}
	// fixing the rules does not need the internet
	for _, r := range fw.set("TCP") {
		r.ports = []int{9999}
	}
	a.Refresh()
	a.Fix(Problem{Kind: FixReapply})
	if fw.tcpPorts() != "[808]" || fw.total("TCP") != 1966 {
		t.Fatal("repair without download")
	}
}

func TestNoAdoptionOnFreshInstall(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "old", display: "Old Revit rule", source: "Local", open: true, enabled: false}}}
	a, _, _ := newTestApp(t, fw)
	a.Main() // on
	a.TurnOff()
	if fw.others[0].enabled {
		t.Fatal("a rule that was off before the program ran must stay off")
	}
}

func TestOldTaskRenewed(t *testing.T) {
	fw := &fakeFW{task: true, taskArgs: `C:\Tools\CountryIPFilter.exe --update`}
	a, ui, _ := newTestApp(t, fw)
	a.Main()
	fw.task, fw.taskArgs = true, `C:\Tools\CountryIPFilter.exe --update`
	c2 := newCore(t, fw)
	_, ui2, _ := startApp(t, c2, lists)
	if !strings.Contains(fw.taskArgs, "powershell.exe") || strings.Contains(fw.taskArgs, "CountryIPFilter.exe") {
		t.Fatalf("the task must run PowerShell only: %s", fw.taskArgs)
	}
	if _, ok := ui2.problem(FixAutoUpdate); ok {
		t.Fatal("renewed task still reported")
	}
	_ = ui
}

func TestOldTaskRemovedWhenOff(t *testing.T) {
	fw := &fakeFW{task: true, taskArgs: `C:\Users\Public\CountryIPFilter.exe --update`, oldTask: true}
	newTestApp(t, fw)
	if fw.task || fw.oldTask {
		t.Fatal("old tasks that run when protection is off must be removed")
	}
}

// ---------- every combination of states: the screen must always make sense ----------

func TestAssessInvariants(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	profiles := [][]Profile{
		{{"Domain", true, "Block", "True", "True"}, {"Public", true, "Block", "True", "True"}},
		{{"Domain", false, "Block", "True", "True"}, {"Public", true, "Block", "True", "True"}},
		{{"Public", true, "Allow", "True", "True"}},
		{{"Public", true, "Block", "False", "True"}},
		{{"Public", true, "Block", "True", "False"}},
	}
	tcp := func(enabled, wide bool, ports ...int) OurRule {
		return OurRule{Name: "CountryIPFilter-TCP-01", Set: "TCP", Index: 1, Enabled: enabled, Ports: ports, Count: 400, Wide: wide, Proto: "TCP"}
	}
	oursSets := [][]OurRule{
		nil,
		{tcp(true, false, 808)},
		{tcp(false, false, 808)},
		{tcp(true, true, 808)},
		{tcp(true, false, 3389, 808)},
		{tcp(true, false, 808), {Name: "CountryIPFilter-UDP-01", Set: "UDP", Index: 1, Enabled: true, Ports: []int{1194}, Count: 400, Proto: "UDP"}},
	}
	conflictSets := [][]Conflict{
		nil,
		{{Name: "a", Display: "A", Enabled: true, Open: true, Local: true, CanClose: true, Covers: []string{"808"}}},
		{{Name: "b", Display: "B", Enabled: true, Open: true, Local: true, Broad: true, Covers: []string{"808"}}},
		{{Name: "c", Display: "C", Enabled: true, Open: true, Local: false, Covers: []string{"808"}}},
		{{Name: "d", Display: "D", Enabled: true, Open: false, Local: true, Covers: []string{"808"}}},
		{{Name: "e", Display: "E", Enabled: false, Open: true, Local: true, Covers: []string{"808"}}},
		{{Name: "f", Display: "F", Enabled: true, Open: true, Local: true, CanClose: true, Covers: []string{"3389"}}},
		{{Name: "g", Display: "G", Enabled: true, Open: true, Local: true, CanClose: true, Covers: []string{"udp:1194"}}},
	}
	blockSets := [][]Conflict{
		nil,
		{{Name: "x", Display: "X", Enabled: true, Open: true, Local: true, Covers: []string{"808"}}},
		{{Name: "y", Display: "Y", Enabled: true, Open: true, Local: false, Covers: []string{"808"}}},
	}
	tagSets := []Tags{
		{},
		{ListDate: now.AddDate(0, 0, -3), ListCount: 400, LastWhen: now.AddDate(0, 0, -3), LastOK: true, Countries: []string{"IR"}},
		{ListDate: now.AddDate(0, -3, 0), ListCount: 400, Countries: []string{"IR"}},
		{ListDate: now.AddDate(0, 0, -30), ListCount: 400, LastWhen: now.AddDate(0, 0, -2), LastOK: false, LastWhy: "download", Countries: []string{"IR"}},
		{ListDate: now.AddDate(0, 0, -3), ListCount: 900, Countries: []string{"DE", "IR"}},
	}
	entrySets := [][]Entry{{TCP(808)}, {TCP(808), TCP(3389)}, {TCP(808), UDP(1194)}, {}}
	count := 0
	for _, pr := range profiles {
		for _, ours := range oursSets {
			for _, cs := range conflictSets {
				for _, bs := range blockSets {
					for _, task := range []int{0, 1, 2} {
						for _, ff := range []bool{false, true} {
							for _, tg := range tagSets {
								for _, entries := range entrySets {
									for _, codes := range [][]string{{"IR"}, {}} {
										st := Status{Profiles: pr, Ours: ours, Conflicts: cs, Blocks: bs, Tags: tg}
										switch task {
										case 1:
											st.Task, st.TaskArgs = true, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe `+TaskArguments()
										case 2:
											st.Task, st.TaskArgs = true, `C:\x\CountryIPFilter.exe --update`
										}
										in := ViewInput{St: st, Entries: entries, Countries: codes, FetchFailed: ff, Now: now}
										v := Assess(in)
										count++
										check := func(ok bool, what string) {
											if !ok {
												t.Fatalf("%s\nstate: %+v entries=%v\ninput: %+v\nview: %+v", what, st, entries, in, v)
											}
										}
										check(v.On == (len(ours) > 0), "On must match our rules")
										check(len(v.Rows) == len(entries), "one row per entry")
										check(v.Title != "" && v.Desc != "" && v.Main != "" && v.Info != "", "headline, button, info")
										fixable := false
										for _, p := range v.Problems {
											fixable = fixable || autoFixable(p.Kind)
										}
										if v.On {
											check(v.CanOff, "turn off must be offered while on")
											check((v.Action == ActFixAll) == fixable, "fix-all exactly when something can be fixed")
											check(v.Action == ActFixAll || v.Action == ActRefresh, "main action while on")
											if st.FirewallProblem() || len(st.Dangerous()) > 0 || len(bs) > 0 {
												check(v.Level == LevelRed, "anything that lets the world in (or shuts the countries out) must be red")
											}
										} else {
											check(!v.CanOff && v.Main == MainOn, "off: main turns on")
											check((v.Action == ActDisabled) == st.LocalRulesBlocked(), "disabled only under Group Policy")
											check((v.Level == LevelOrange) == (open0(v) && !st.LocalRulesBlocked() || st.FirewallProblem() && !st.LocalRulesBlocked() && (len(entries) == 0 || len(codes) == 0)) && (v.Level == LevelOrange || v.Level == LevelGrey), "off: orange exactly when something is open to the world")
											for _, p := range v.Problems {
												check(p.Kind != FixFirewall, "the firewall is switched on together with protection, not alone")
											}
										}
										if v.Level == LevelGreen {
											check(v.On && len(v.Problems) == 0, "green only when on and nothing to fix")
										}
										open, shut := false, false
										for _, r := range v.Rows {
											check(r.State != "" && r.Item != "" && r.Key != "", "every row has an item and a state")
											if v.Level == LevelGreen {
												check(r.State == GreenState && r.Level == LevelGreen, "green screen means every row is countries-only")
											}
											if v.On && r.Level == LevelRed {
												check(v.Level == LevelRed, "a red row means a red screen")
											}
											if r.State == GreenState {
												check(v.On && !st.FirewallProblem(), "countries-only claimed without protection")
											}
											open = open || r.State == OpenState || r.State == FwOpenState
											shut = shut || r.State == ShutState
										}
										if v.Level == LevelRed && v.On {
											if open {
												check(strings.Contains(v.Desc, "کشورهای دیگر"), "open: the headline must say other countries can connect")
											} else if shut {
												check(strings.Contains(v.Desc, "حتی برای کشورهای انتخاب‌شده"), "shut: the headline must say the countries are shut out")
											}
										}
										for _, p := range v.Problems {
											check((p.Kind == FixNone) == (p.Button == ""), "button iff fixable")
											check(!autoFixable(p.Kind) || p.Step != "", "fix-all step text")
											check(!(p.Kind == FixCloseRule && len(st.Sensitive(p.Rule.Covers)) > 0), "remote-management rules need the careful button")
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("checked %d combinations", count)
}

func open0(v View) bool {
	for _, r := range v.Rows {
		if r.State == OpenState || r.State == FwOpenState {
			return true
		}
	}
	return false
}

func TestFailures(t *testing.T) {
	// status cannot be read: red, unknown, main button re-reads, nothing else happens
	fw := &fakeFW{failStatus: true}
	a, ui, _ := newTestApp(t, fw)
	if !ui.view.Unknown || ui.view.Level != LevelRed || ui.view.Main != MainCheck {
		t.Fatalf("unknown view: %+v", ui.view)
	}
	a.Main()
	for _, s := range fw.scripts {
		if s == "apply" || s == "rules" {
			t.Fatal("must not change anything when the state is unknown")
		}
	}
	fw.failStatus = false
	a.Main() // now it reads fine
	if ui.view.Unknown {
		t.Fatal("recovery")
	}

	// writing rules fails: red message, protection stays off
	fw2 := &fakeFW{failApply: true}
	a2, ui2, _ := newTestApp(t, fw2)
	a2.Main()
	if ui2.view.On || !strings.Contains(ui2.lastTell(), "انجام نشد") {
		t.Fatal("apply failure")
	}

	// a rule that the program closed was deleted later: turning off still succeeds and forgets it
	fw3 := &fakeFW{others: []*fakeRule{{name: "wcf", display: "Net.TCP", source: "Local", open: true, enabled: true}}}
	a3, ui3, _ := newTestApp(t, fw3)
	a3.Main()
	fw3.others = nil // deleted by someone
	a3.TurnOff()
	if len(fw3.ours) != 0 || !strings.Contains(ui3.lastTell(), "خاموش شد") {
		t.Fatalf("turn off with a deleted rule: %v", ui3.told)
	}

	// switching old rules back on fails completely: nothing changes, user told
	fw4 := &fakeFW{others: []*fakeRule{{name: "wcf", display: "Net.TCP", source: "Local", open: true, enabled: true}}}
	a4, ui4, _ := newTestApp(t, fw4)
	a4.Main()
	fw4.failRules = true
	a4.TurnOff()
	if len(fw4.ours) == 0 || !ui4.view.On {
		t.Fatal("protection must stay on when the old rule could not be restored")
	}
}

func TestFixAllInOneStep(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "wcf", display: "Net.TCP", source: "Local", open: true, enabled: true}}}
	a, ui, _ := newTestApp(t, fw)
	a.Main() // on
	// later: firewall switched off, the old rule opened again, the task deleted
	fw.fwOff, fw.others[0].enabled, fw.task = true, true, false
	a.Refresh()
	if ui.view.Action != ActFixAll || ui.view.Main != MainFix || ui.view.Level != LevelRed {
		t.Fatalf("fix-all expected: %+v", ui.view)
	}
	asked := len(ui.asked)
	a.Main()
	if len(ui.asked) != asked+1 {
		t.Fatal("fix all must ask exactly once")
	}
	if fw.fwOff || fw.others[0].enabled || !fw.task || ui.view.Level != LevelGreen || ui.view.Action != ActRefresh {
		t.Fatalf("fix all: fw=%v rule=%v task=%v view=%+v", !fw.fwOff, fw.others[0].enabled, fw.task, ui.view)
	}
	a.TurnOff()
	if !fw.others[0].enabled {
		t.Fatal("rule closed by fix-all must come back on turn off")
	}
}

func TestRemovePortBringsItsRuleBack(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "web", display: "Web 9000", source: "Local", open: true, enabled: true, ports: "9000"}}}
	a, ui, c := newTestApp(t, fw)
	c.SaveEntries([]Entry{TCP(808), TCP(9000)})
	a.Main() // on: the 9000 rule is closed
	if fw.others[0].enabled {
		t.Fatal("rule for 9000 must be closed")
	}
	a.RemoveEntry("9000")
	if !strings.Contains(ui.lastAsk(), "Web 9000") {
		t.Fatal("the question must say which rule comes back")
	}
	if !fw.others[0].enabled || containsStr(offNames(fw.off()), "web") {
		t.Fatal("removing the port must switch its old rule on again")
	}
	if fw.tcpPorts() != "[808]" || ui.view.Level != LevelGreen {
		t.Fatalf("after remove: %v %+v", fw.tcpPorts(), ui.view)
	}
}

func TestBlockRule(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "blk", display: "Block 808", source: "Local", open: true, enabled: true, block: true}}}
	a, ui, _ := newTestApp(t, fw)
	if ui.view.Rows[0].State != ClosedState {
		t.Fatalf("off: %+v", ui.view.Rows)
	}
	a.Main()
	p, ok := ui.problem(FixBlockRule)
	if !ok || ui.view.Level != LevelRed || ui.view.Rows[0].State != ShutState || !strings.Contains(ui.view.Desc, "حتی برای کشورهای انتخاب‌شده") {
		t.Fatalf("block: %+v", ui.view)
	}
	a.Fix(p)
	if fw.others[0].enabled || ui.view.Level != LevelGreen {
		t.Fatal("block rule fix")
	}
	a.TurnOff()
	if !fw.others[0].enabled {
		t.Fatal("block rule must come back")
	}
}

func TestMonthlyUpdateResult(t *testing.T) {
	fw := &fakeFW{}
	a, ui, c := newTestApp(t, fw)
	a.Main()
	if ui.view.Level != LevelGreen {
		t.Fatalf("on: %+v", ui.view)
	}
	fw.updateFail = true
	c.RunUpdate() // what the scheduled task does
	a.Refresh()
	p, ok := ui.problem(FixUpdateList)
	if !ok || ui.view.Level != LevelOrange || !strings.Contains(p.Text, "دانلود نشد") {
		t.Fatalf("failed update must show: %+v", ui.view.Problems)
	}
	a.Fix(p)
	if ui.view.Level != LevelGreen {
		t.Fatalf("a good update clears it: %+v", ui.view.Problems)
	}
}

func TestStateSurvivesMovingTheProgram(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "web", display: "Web", source: "Local", open: true, enabled: true, ports: "443"}}}
	a, _, c := newTestApp(t, fw)
	c.SaveEntries([]Entry{TCP(808), TCP(443)})
	c.SaveCountries([]string{"DE", "IR"})
	a.Main()
	// the program is copied somewhere else without its data folder
	c2 := newCore(t, fw)
	a2, ui2, _ := startApp(t, c2, lists)
	if fmt.Sprint(entryKeys(c2.LoadEntries())) != "[443 808]" || fmt.Sprint(c2.LoadCountries()) != "[DE IR]" || ui2.view.Level != LevelGreen {
		t.Fatalf("ports must come from the rules: %v %+v", c2.LoadEntries(), ui2.view)
	}
	a2.TurnOff()
	if !fw.others[0].enabled {
		t.Fatal("the closed rule must still come back")
	}
}

func TestOffListKeptWhenSavingFails(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "wcf", display: "Net.TCP", source: "Local", open: true, enabled: true}}}
	a, ui, _ := newTestApp(t, fw)
	fw.failTags = true
	a.Main()
	if !fw.others[0].enabled {
		t.Fatal("a rule must never be closed when it cannot be remembered")
	}
	if _, ok := ui.problem(FixCloseRule); !ok {
		t.Fatal("it stays a problem")
	}
}

func TestInactiveProfileIgnored(t *testing.T) {
	st, _ := ParseStatus("ACTIVE|Public\nPROFILE|Domain|False|Block|False\nPROFILE|Public|True|Block|NotConfigured\nRULE|"+b64("x")+"|Local|True|TCP|808|Any|"+b64("Any")+"|"+b64("Any")+"|"+b64("X")+"|Any||Allow|Domain\nTASK|False\nIPF-OK\n", []Entry{TCP(808)})
	if st.FirewallProblem() || st.LocalRulesBlocked() || len(st.Conflicts) != 0 {
		t.Fatalf("inactive Domain profile must not matter: %+v", st)
	}
}

func TestUpdateScriptSize(t *testing.T) {
	if n := len(TaskArguments()); n > 30000 {
		t.Fatalf("task arguments too long: %d", n)
	}
}

func TestProgramRuleWithListener(t *testing.T) {
	// "all ports for RevitServer.exe", and Revit Server listens on 808: that rule opens 808
	fw := &fakeFW{listen: map[int]string{808: `C:\Revit\RevitServer.exe`},
		others: []*fakeRule{{name: "rv", display: "Revit Server", source: "Local", open: true, enabled: true, ports: "Any", program: `C:\Revit\RevitServer.exe`}}}
	a, ui, _ := newTestApp(t, fw)
	a.Main()
	if _, ok := ui.problem(FixCloseBroad); !ok || ui.view.Level != LevelRed {
		t.Fatalf("program rule must be found: %+v", ui.view)
	}
	fw.listen = nil // Revit Server stopped: its rule still matters (it opens 808 when Revit starts again)
	a.Refresh()
	if _, ok := ui.problem(FixCloseBroad); !ok {
		t.Fatalf("remembered program: %+v", ui.view.Problems)
	}
}

func TestGroupPolicyDisablesMain(t *testing.T) {
	st, _ := ParseStatus("PROFILE|Public|True|Block|False\nTASK|False\nIPF-OK\n", []Entry{TCP(808)})
	if v := Assess(ViewInput{St: st, Entries: []Entry{TCP(808)}, Countries: []string{"IR"}}); v.Action != ActDisabled {
		t.Fatal("main must be disabled under Group Policy")
	}
}

func TestTurnOffWarnsWhenPortShuts(t *testing.T) {
	fw := &fakeFW{}
	a, ui, _ := newTestApp(t, fw)
	a.Main()
	ui.answer = false
	a.TurnOff()
	if q := ui.lastAsk(); !strings.Contains(q, "حتی کشورهای انتخاب‌شده") || len(fw.ours) == 0 {
		t.Fatalf("turning off must say 808 will be shut for everyone:\n%s", q)
	}
}

func TestTurnOnWarnsWhenWidening(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "office", display: "Office only", source: "Local", open: false, enabled: true}}}
	a, ui, _ := newTestApp(t, fw)
	if ui.view.Rows[0].State != SomeIPsState {
		t.Fatalf("state: %+v", ui.view.Rows)
	}
	ui.answer = false
	a.Main()
	if !strings.Contains(ui.lastAsk(), "فقط برای چند IP مشخص") {
		t.Fatal("must warn that access widens")
	}
}

func TestEditedRuleNotGreen(t *testing.T) {
	fw := &fakeFW{}
	a, ui, _ := newTestApp(t, fw)
	a.Main()
	fw.oursBlock = true
	a.Refresh()
	p, ok := ui.problem(FixReapply)
	if !ok || ui.view.Level != LevelRed || ui.view.Rows[0].State != ShutState {
		t.Fatalf("our rule turned into Block: %+v", ui.view)
	}
	a.Fix(p)
	if fw.oursBlock || ui.view.Level != LevelGreen {
		t.Fatal("repair")
	}
	// a rule switched off by someone
	fw.ours["CountryIPFilter-TCP-03"].enabled = false
	a.Refresh()
	if ui.view.Level != LevelRed {
		t.Fatal("a rule switched off must be red")
	}
	a.Main()
	if ui.view.Level != LevelGreen {
		t.Fatal("fix all")
	}
}

func TestMissingFirstRule(t *testing.T) {
	fw := &fakeFW{}
	a, ui, _ := newTestApp(t, fw)
	a.Main()
	delete(fw.ours, "CountryIPFilter-TCP-01")
	a.Refresh()
	if ui.view.Level != LevelRed || a.last.Repairable() {
		t.Fatalf("a missing part must not look fine: %+v", ui.view)
	}
	a.Main() // fix all: rewrites the rules with a fresh list
	if len(fw.ours) != 5 || ui.view.Level != LevelGreen {
		t.Fatalf("rewrite: %d %+v", len(fw.ours), ui.view.Problems)
	}
	// a set deleted, another intact: repaired from the intact one, no download
	a.AddPort("53", "UDP")
	for _, r := range fw.set("UDP") {
		delete(fw.ours, "CountryIPFilter-UDP-"+fmt.Sprintf("%02d", r.index))
	}
	a.Refresh()
	if !a.last.Repairable() {
		t.Fatal("the TCP set can be copied")
	}
	offline(t, a.core)
	a.Main()
	if len(fw.set("UDP")) != 5 || ui.view.Level != LevelGreen {
		t.Fatalf("copy: %d %+v", len(fw.set("UDP")), ui.view.Problems)
	}
}

func TestSensitiveByListener(t *testing.T) {
	fw := &fakeFW{listen: map[int]string{2222: `C:\OpenSSH\sshd.exe`},
		others: []*fakeRule{{name: "ssh", display: "SSH on 2222", source: "Local", open: true, enabled: true, ports: "2222"}}}
	a, ui, c := newTestApp(t, fw)
	c.SaveEntries([]Entry{TCP(808), TCP(2222)})
	a.Refresh()
	a.Main()
	if !fw.others[0].enabled {
		t.Fatal("SSH on another port must not be closed automatically")
	}
	if !strings.Contains(ui.lastAsk(), "SSH") {
		t.Fatal("turn on must warn about SSH")
	}
	if _, ok := ui.problem(FixCloseBroad); !ok {
		t.Fatal("careful button expected")
	}
}

func TestFixAllRepairsAndUpdates(t *testing.T) {
	fw := &fakeFW{}
	a, ui, c := newTestApp(t, fw)
	a.Main()
	for _, r := range fw.ours {
		r.enabled = false
	}
	fw.updateFail = true
	c.RunUpdate()
	a.Refresh()
	_, ok1 := ui.problem(FixReapply)
	_, ok2 := ui.problem(FixUpdateList)
	if !ok1 || !ok2 {
		t.Fatalf("both problems expected: %+v", ui.view.Problems)
	}
	n := strings.Count(strings.Join(fw.scripts, " "), "apply")
	a.Main()
	m := strings.Count(strings.Join(fw.scripts, " "), "apply")
	if m != n+2 || ui.view.Level != LevelGreen {
		t.Fatalf("fix all must repair and refresh the list: %d %+v", m-n, ui.view.Problems)
	}
}

func TestFolderShared(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "CountryIPFilter.exe"), nil, 0o644)
	os.WriteFile(filepath.Join(d, "IranIPFilter.exe"), nil, 0o644)
	os.WriteFile(filepath.Join(d, "راهنما.html"), nil, 0o644)
	os.Mkdir(filepath.Join(d, "data"), 0o755)
	if FolderShared(d) {
		t.Fatal("own folder")
	}
	os.WriteFile(filepath.Join(d, "other.exe"), nil, 0o644)
	if !FolderShared(d) {
		t.Fatal("folder with other files")
	}
	for _, x := range []string{"/home/u/Desktop", `C:\`, ""} {
		if !FolderShared(x) {
			t.Fatal(x)
		}
	}
	v := Assess(ViewInput{Entries: []Entry{TCP(808)}, FolderShared: true})
	if len(v.Problems) != 1 || v.Problems[0].Button != "" || !strings.Contains(v.Problems[0].Text, "پوشه‌ی جدا") {
		t.Fatalf("shared folder note: %+v", v.Problems)
	}
}

func TestSwitchOffKeepsRecordOnError(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "wcf", display: "Net.TCP", source: "Local", open: true, enabled: true}}}
	a, _, _ := newTestApp(t, fw)
	fw.rulesLost = true // the rule is switched off, then the script is killed
	a.Main()
	if fw.others[0].enabled || !containsStr(offNames(fw.off()), "wcf") {
		t.Fatalf("a rule switched off must stay recorded: enabled=%v off=%v", fw.others[0].enabled, fw.off())
	}
	fw.rulesLost = false
	a.TurnOff()
	if !fw.others[0].enabled {
		t.Fatal("turn off must bring it back")
	}
}

func TestPortsRevertWhenRulesFail(t *testing.T) {
	fw := &fakeFW{}
	a, _, c := newTestApp(t, fw)
	a.Main()
	delete(fw.ours, "CountryIPFilter-TCP-01") // not repairable: needs a download
	a.Refresh()
	offline(t, c)
	if a.AddPort("9000", "TCP") {
		t.Fatal("must report failure")
	}
	if fmt.Sprint(entryKeys(c.LoadEntries())) != "[808]" {
		t.Fatalf("ports must go back: %v", c.LoadEntries())
	}
	if a.AddPort("abc", "TCP") || a.AddPort("808", "TCP") {
		t.Fatal("bad input must return false")
	}
}

func TestSmallerListRefused(t *testing.T) {
	fw := &fakeFW{}
	a, ui, c := newTestApp(t, fw)
	a.Main()
	c.HTTP = clientFor(withRipe(t, map[string]string{"IR": ripeJSON(900, 2)}, 200))
	ui.answers = []bool{false}
	a.Fix(Problem{Kind: FixUpdateList})
	if fw.total("TCP") != 1966 || !strings.Contains(ui.lastAsk(), "ناقص") {
		t.Fatalf("a much smaller list must need a yes: %d", fw.total("TCP"))
	}
	ui.answers = []bool{true}
	a.Fix(Problem{Kind: FixUpdateList})
	if fw.total("TCP") != 900 {
		t.Fatal("the user may accept it")
	}
}

func TestOurRuleOpenedToInternet(t *testing.T) {
	for _, extra := range []string{"Internet", "200.0.0.0/255.0.0.0", "5.0.0.0-6.0.0.0"} {
		fw := &fakeFW{}
		a, ui, _ := newTestApp(t, fw)
		a.Main()
		fw.oursAddr = extra
		a.Refresh()
		if ui.view.Level != LevelRed || ui.view.Rows[0].State != OpenState {
			t.Fatalf("%s in our rule must be red: %+v", extra, ui.view)
		}
		a.Main() // fix all: a fresh list (the addresses cannot be trusted)
		if ui.view.Level != LevelGreen || fw.oursAddr != "" {
			t.Fatalf("%s: %+v", extra, ui.view.Problems)
		}
	}
}

func TestBlockAllIncoming(t *testing.T) {
	fw := &fakeFW{}
	a, ui, _ := newTestApp(t, fw)
	a.Main()
	fw.inboundOff = true
	a.Refresh()
	p, ok := ui.problem(FixFirewall)
	if !ok || ui.view.Level != LevelRed || ui.view.Rows[0].State != ShutState {
		t.Fatalf("block all incoming: %+v", ui.view)
	}
	a.Fix(p)
	if fw.inboundOff || ui.view.Level != LevelGreen {
		t.Fatal("fix")
	}
}

func TestUnknownLayoutHasNoProblemSection(t *testing.T) {
	v := UnknownView([]Entry{TCP(808)}, []string{"IR"}, true)
	L := computeLayout(v, true, false, false, approxMeasure, 900)
	if L.NoProb.Visible() || L.ProbHead.Visible() || v.Info == "" {
		t.Fatal("unknown state must not say there are no problems")
	}
	// a very short screen still shows the first problem
	v2 := View{On: true, Problems: []Problem{{Text: "x"}, {Text: "y"}}, Rows: []PortRow{{Key: "808"}}}
	L2 := computeLayout(v2, true, false, false, approxMeasure, 300)
	if len(L2.Rows) != 1 || L2.Hidden != 1 {
		t.Fatalf("rows=%d hidden=%d", len(L2.Rows), L2.Hidden)
	}
	// on a 1024x768 screen (100% and 125%) the usual screens fit
	a, ui, _ := newTestApp(t, &fakeFW{})
	a.Main()
	for _, h := range []int{690, 560} {
		L3 := computeLayout(ui.view, true, false, false, approxMeasure, h)
		if L3.ClientH > h {
			t.Fatalf("too tall for %d: %d", h, L3.ClientH)
		}
	}
}

func TestPsQuoteCurly(t *testing.T) {
	if q := psQuote("a\u2019b"); q != "'a\u2019\u2019b'" {
		t.Fatal(q)
	}
}

func TestInboundWarningListsRules(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "smb", display: "File sharing", source: "Local", open: true, enabled: true, ports: "445"}}}
	a, ui, _ := newTestApp(t, fw)
	a.Main()
	fw.inboundOff = true
	a.Refresh()
	ui.answer = false
	a.Main() // fix all
	if q := ui.lastAsk(); !strings.Contains(q, "File sharing") || !fw.inboundOff {
		t.Fatalf("switching off block-all must name the rules that open again:\n%s", q)
	}
}

func TestWellKnown(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range wellKnown {
		key := fmt.Sprint(k.Kind, k.Port)
		if seen[key] || k.Port < 1 || k.Port > 65535 || (k.Kind != KindTCP && k.Kind != KindUDP) {
			t.Fatalf("bad entry %+v", k)
		}
		seen[key] = true
		// a line of the list is accepted as it is
		e, ok := ParseEntry(strings.Join(strings.Fields(knownLabel(k))[:2], " "))
		if !ok || e.Kind != k.Kind || e.Port != k.Port {
			t.Fatalf("label %q", knownLabel(k))
		}
	}
	a, _, c := newTestApp(t, &fakeFW{})
	a.AddPort("UDP 51820   WireGuard", "TCP")
	if !hasEntry(c.LoadEntries(), "udp:51820") {
		t.Fatal("a line of the list must be accepted")
	}
}
