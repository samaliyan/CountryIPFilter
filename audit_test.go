package main

// Tests for what the independent review found.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Version 3 rules stay because moving them failed; the user turns
// protection on again. The record of the rule version 3 switched off must
// still reach the new rules.
func TestMigrationAfterTurnOnKeepsRecords(t *testing.T) {
	fw := &fakeFW{
		old:       []fakeOld{{name: "IranIPFilter-01", ports: []int{808}, addrs: []string{"5.1.0.0/16"}}},
		oldDesc:   ruleDesc + " [OK=2026-09-01T10:00:00Z,1] [OFF=" + encodeOff([]OffRule{{Name: "wcf", Covers: []string{"808"}}}) + "] [FWON=1]",
		others:    []*fakeRule{{name: "wcf", display: "Net.TCP", source: "Local", open: true, enabled: false}},
		failApply: true,
	}
	c := newCore(t, fw)
	c.SaveCountries([]string{"IR"})
	c.SaveEntries([]Entry{TCP(808)})
	a, ui, _ := startApp(t, c, lists)
	if len(fw.old) != 1 || ui.view.Level == LevelGreen {
		t.Fatalf("old rules left over must not look fine: %+v", ui.view)
	}
	fw.failApply = false
	a.Main() // turn on: new rules, the old ones are still there
	if len(fw.ours) == 0 {
		t.Fatal("turn on")
	}
	// the program is started again
	a2, _, _ := startApp(t, c, lists)
	if len(fw.old) != 0 {
		t.Fatal("old rules must be removed once the new ones work")
	}
	if !containsStr(offNames(fw.off()), "wcf") || !parseTags(fw.desc).FwOn {
		t.Fatalf("records of version 3 lost: %s", fw.desc)
	}
	a2.TurnOff()
	if !fw.others[0].enabled {
		t.Fatal("the rule version 3 switched off must come back")
	}
}

func TestOldRulesAreSerious(t *testing.T) {
	// Germany chosen, but the Iran-only rules of version 3 are still there
	fw := &fakeFW{old: []fakeOld{{name: "IranIPFilter-01", ports: []int{808}, addrs: []string{"Any"}}}}
	c := newCore(t, fw)
	c.SaveCountries([]string{"DE"})
	c.SaveEntries([]Entry{TCP(808)})
	a, ui, _ := startApp(t, c, lists)
	if !strings.Contains(ui.lastTell(), "منتقل نشدند") {
		t.Fatalf("a refused move must be told: %v", ui.told)
	}
	if ui.view.Rows[0].State != OpenState || ui.view.Level != LevelOrange {
		t.Fatalf("an old rule open to everyone must show the port open: %+v", ui.view)
	}
	if p, ok := ui.problem(FixMigrate); !ok || !p.Severe {
		t.Fatal("old rules must be a severe problem")
	}
	// protection on for Germany: once the new rules are whole, the old rule goes
	a.Main()
	if len(fw.old) != 0 || ui.view.Level != LevelGreen {
		t.Fatalf("old rules after turning on: %d %+v", len(fw.old), ui.view.Problems)
	}
}

func TestRemoveRestoresRuleOfSeveralPorts(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "two", display: "808 and 809", source: "Local", open: true, enabled: true, ports: "808,809"}}}
	a, _, c := newTestApp(t, fw)
	c.SaveEntries([]Entry{TCP(443), TCP(808), TCP(809)})
	a.Main()
	if fw.others[0].enabled {
		t.Fatal("rule for our two ports must be closed")
	}
	a.RemoveEntry("808")
	if fw.others[0].enabled {
		t.Fatal("809 is still protected: the rule stays off")
	}
	a.RemoveEntry("809")
	if !fw.others[0].enabled {
		t.Fatal("none of its ports is protected any more: the rule must come back")
	}
}

func TestProgramPortsRemembered(t *testing.T) {
	exe := `C:\Program Files\Srv\srv.exe`
	fw := &fakeFW{listen: map[int]string{5000: exe}, others: []*fakeRule{{name: "p", display: "Port 5000", source: "Local", open: true, enabled: true, ports: "5000"}}}
	a, ui, c := newTestApp(t, fw)
	c.SaveEntries([]Entry{AppEntry(exe)})
	a.Refresh()
	a.Main()
	if fw.others[0].enabled || ui.view.Level != LevelGreen {
		t.Fatalf("port rule of the program: %+v", ui.view)
	}
	// the program is stopped and someone opens the port again
	fw.listen = nil
	fw.others[0].enabled = true
	a.Refresh()
	if ui.view.Level != LevelRed {
		t.Fatalf("a stopped program's port must still count: %+v", ui.view.Problems)
	}
}

func TestAddProgramSafety(t *testing.T) {
	a, ui, c := newTestApp(t, &fakeFW{})
	for _, bad := range []string{`\\server\share\app.exe`, `//server/share/app.exe`, `C:\Windows\System32\cmd.exe`, `C:\Python\python.exe`} {
		if a.AddProgram(bad) {
			t.Errorf("%s accepted", bad)
		}
	}
	// a program outside Program Files: a warning, and No keeps it out
	exe := filepath.Join(t.TempDir(), "app.exe")
	os.WriteFile(exe, nil, 0o644)
	ui.answers = []bool{false}
	if a.AddProgram(exe) || hasEntry(c.LoadEntries(), AppEntry(exe).Key()) {
		t.Fatal("must ask first")
	}
	if !strings.Contains(ui.lastAsk(), "هشدار") {
		t.Fatal("warning expected")
	}
	if protectedFolder(`C:\Windows\Temp\x.exe`) || !protectedFolder(`C:\Program Files\X\x.exe`) || protectedFolder(`C:\Tools\x.exe`) {
		t.Fatal("protected folders")
	}
}

func TestPersianOrder(t *testing.T) {
	names := []string{"ترکیه", "پاکستان", "چین", "حبشه", "ایران", "آلمان", "بریتانیا", "یمن", "کانادا", "گرجستان", "ونزوئلا"}
	sort.Slice(names, func(i, j int) bool { return lessName(names[i], names[j]) })
	want := "[آلمان ایران بریتانیا پاکستان ترکیه چین حبشه کانادا گرجستان ونزوئلا یمن]"
	if fmt.Sprint(names) != want {
		t.Fatalf("got %v", names)
	}
	if !lessName("albania", "Belgium") || lessName("Iran", "Iran") {
		t.Fatal("english")
	}
}

func TestDownloadMustBeTheList(t *testing.T) {
	fw := &fakeFW{}
	c := newCore(t, fw)
	c.SaveCountries([]string{"IR"})
	c.SaveEntries([]Entry{TCP(808)})
	// a proxy answers with its own page (which even holds an address range)
	a, ui, _ := startApp(t, c, map[string]string{"IR": "<html>Blocked. Ask 10.0.0.0/8 or 5.5.5.0/24</html>"})
	a.Main()
	if len(fw.ours) != 0 {
		t.Fatal("a proxy page must never become the list")
	}
	if _, ok := ui.problem(FixManualList); !ok {
		t.Fatal("manual list must be offered")
	}
	// the download through PowerShell works
	fw.psLists = map[string]string{"IR": lists["IR"]}
	a.Main()
	if fw.total("TCP") != 1966 {
		t.Fatalf("PowerShell download: %d", fw.total("TCP"))
	}
	if r, err := parseRIPE([]byte(`{"data":{"resources":{}}}`)); err == nil {
		t.Fatal(r)
	}
}

func TestCountryShrinkAsks(t *testing.T) {
	fw := &fakeFW{}
	a, ui, c := newTestApp(t, fw)
	c.SaveCountries([]string{"DE", "IR"})
	a.Main()
	if fw.total("TCP") != 2666 || !strings.Contains(fw.desc, fmt.Sprintf("[CCN=DE:%d,IR:%d]", 700*1024, 1966*1024)) {
		t.Fatalf("per-country record: %s", fw.desc)
	}
	// Germany's list shrinks to a third; the total still looks fine
	c.HTTP = clientFor(withRipe(t, map[string]string{"IR": lists["IR"], "DE": ripeJSON(250, 80)}, 200))
	ui.answers = []bool{false}
	a.Fix(Problem{Kind: FixUpdateList})
	if fw.total("TCP") != 2666 || !strings.Contains(ui.lastAsk(), CountryName("DE")) {
		t.Fatalf("must ask: %d\n%s", fw.total("TCP"), ui.lastAsk())
	}
}

func TestTaskMustRunWindowsPowerShell(t *testing.T) {
	st := Status{Task: true, TaskArgs: `C:\x\powershell.exe ` + TaskArguments()}
	if st.TaskCurrent() {
		t.Fatal("another powershell.exe must not count")
	}
	st.TaskArgs = `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe ` + TaskArguments()
	if st.TaskCurrent() {
		t.Fatal("without update.ps1 (or with a changed one) it does not count")
	}
	st.TaskFile = strings.ToLower(taskFileHash())
	if !st.TaskCurrent() {
		t.Fatal("the real one counts")
	}
}

func TestVPNAndAdapterRulesIgnored(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{
		{name: "vpn", display: "AnyConnect", source: "Local", open: true, enabled: true, ifType: "RemoteAccess"},
		{name: "wfd", display: "WFD Driver-only (TCP-In)", source: "Local", open: true, enabled: true, ports: "Any", ifAlias: "Wi-Fi Direct", group: "WFD"},
	}}
	a, ui, _ := newTestApp(t, fw)
	a.Main()
	if ui.view.Level != LevelGreen || !fw.others[0].enabled || !fw.others[1].enabled {
		t.Fatalf("VPN-only and one-adapter rules do not open the port: %+v", ui.view.Problems)
	}
}

func TestPolicyRulesNeverSwitched(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "g", display: "From policy", source: "GroupPolicy", open: true, enabled: true}}}
	a, ui, _ := newTestApp(t, fw)
	a.Main()
	if !fw.others[0].enabled || ui.view.Level != LevelRed {
		t.Fatal("a Group Policy rule cannot be switched here and must stay red")
	}
	for _, p := range ui.view.Problems {
		if p.Rule.Name == "g" && p.Button != "" {
			t.Fatal("no button for a policy rule")
		}
	}
}

// Version 3 rules left over while the rules of this version need repair:
// the new rules must never be overwritten with the Iran-only list.
func TestMigrationNeverOverwritesBrokenNewRules(t *testing.T) {
	fw := &fakeFW{others: []*fakeRule{{name: "v4", display: "closed by v4", source: "Local", open: true, enabled: true}}}
	a, _, c := newTestApp(t, fw)
	c.SaveCountries([]string{"DE"})
	a.Main() // Germany only; the "v4" rule is switched off and recorded
	if fw.others[0].enabled {
		t.Fatal("setup")
	}
	delete(fw.ours, "CountryIPFilter-TCP-02") // broken
	fw.old = []fakeOld{{name: "IranIPFilter-01", ports: []int{808}, addrs: []string{"5.1.0.0/16"}}}
	fw.oldDesc = ruleDesc + " [OFF=" + encodeOff([]OffRule{{Name: "v3", Covers: []string{"808"}}}) + "]"
	fw.others = append(fw.others, &fakeRule{name: "v3", display: "closed by v3", source: "Local", open: true, enabled: false})
	a2, ui2, _ := startApp(t, c, lists)
	if fmt.Sprint(parseTags(fw.desc).Countries) != "[DE]" || len(fw.old) != 1 {
		t.Fatalf("new rules overwritten or old ones removed too early: %s", fw.desc)
	}
	off := offNames(fw.off())
	if !containsStr(off, "v4") || !containsStr(off, "v3") {
		t.Fatalf("both records must be kept: %v", off)
	}
	a2.Main() // fix all: rewrite the new rules, then the old ones go
	if len(fw.old) != 0 || ui2.view.Level != LevelGreen || fw.total("TCP") != 700 {
		t.Fatalf("after fix all: old=%d %+v", len(fw.old), ui2.view.Problems)
	}
	a2.TurnOff()
	if !fw.others[0].enabled || !fw.others[1].enabled {
		t.Fatal("both old rules must come back")
	}
}

// Version 3 opened a port that is not in this version's list: ask before it closes.
func TestMigrationAsksAboutOtherPorts(t *testing.T) {
	for _, keep := range []bool{true, false} {
		fw := &fakeFW{}
		a, ui, c := newTestApp(t, fw)
		a.Main()
		fw.old = []fakeOld{{name: "IranIPFilter-01", ports: []int{808, 8080}, addrs: []string{"5.1.0.0/16"}}}
		_ = ui
		// the program is started again; the question comes at once
		ui2 := &fakeUI{answer: true, answers: []bool{keep}}
		c.Log = ui2.Log
		a2 := &App{core: c, ui: ui2}
		a2.Refresh()
		if keep {
			if !hasEntry(c.LoadEntries(), "8080") || len(fw.old) != 1 {
				t.Fatalf("yes: 8080 added, old rules kept until ours are written: %v", c.LoadEntries())
			}
			a2.Main() // fix all
			if len(fw.old) != 0 || fw.tcpPorts() != "[808 8080]" {
				t.Fatalf("after fix all: %d %s", len(fw.old), fw.tcpPorts())
			}
		} else if hasEntry(c.LoadEntries(), "8080") || len(fw.old) != 0 {
			t.Fatal("no: old rules removed, 8080 not added")
		}
	}
}

func TestLongPathPrefix(t *testing.T) {
	a, ui, c := newTestApp(t, &fakeFW{})
	dir := t.TempDir()
	exe := filepath.Join(dir, "a.exe")
	os.WriteFile(exe, nil, 0o644)
	ui.answers = []bool{true}
	if a.AddProgram(`\\?\UNC\server\share\a.exe`) || a.AddProgram(`\\.\pipe\x.exe`) {
		t.Fatal("device and UNC paths must be refused")
	}
	_ = c
}

// The monthly task cannot run (for example Group Policy forbids script
// files): the window says so instead of staying quiet.
func TestTaskFailureShown(t *testing.T) {
	out := "PROFILE|Public|True|Block|NotConfigured|True\nTASK|True\nTASKARGS|" + b64(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe `+TaskArguments()) +
		"\nTASKFILE|" + taskFileHash() + "\nTASKRESULT|1|2026-09-04T00:45:00Z\nIPF-OK\n"
	st, err := ParseStatus(out, []Entry{TCP(808)})
	if err != nil || !st.TaskCurrent() || !st.TaskFailed() {
		t.Fatalf("%v %+v", err, st)
	}
	st.Ours = []OurRule{{Name: "CountryIPFilter-TCP-01", Set: "TCP", Index: 1, Enabled: true, Ports: []int{808}, Count: 1, Proto: "TCP"}}
	v := Assess(ViewInput{St: st, Entries: []Entry{TCP(808)}, Countries: []string{"IR"}})
	found := false
	for _, p := range v.Problems {
		found = found || strings.Contains(p.Text, "0x1")
	}
	if !found {
		t.Fatalf("task failure must be shown: %+v", v.Problems)
	}
	// "has not run yet" (0x41303) is not a failure
	st.TaskCode = 0x41303
	if st.TaskFailed() {
		t.Fatal("not yet run")
	}
	if !strings.HasPrefix(taskDir, os.TempDir()) && !strings.Contains(taskDir, "Program Files") {
		t.Fatal(taskDir)
	}
}

// Uninstalling deletes only named files and empty folders, never a whole tree.
func TestUninstallDeletesOnlyNamedFiles(t *testing.T) {
	s := UninstallScript(`C:\Program Files\CountryIPFilter`, []string{`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Country IP Filter.lnk`})
	for _, bad := range []string{"-Recurse", "*", "$HOME"} {
		if strings.Contains(s, bad) {
			t.Fatalf("uninstall script contains %q", bad)
		}
	}
	if strings.Count(s, "DelFile '") < 8 || !strings.Contains(s, "ReparsePoint") {
		t.Fatal(s)
	}
	in := InstallScript(`C:\Program Files\CountryIPFilter\CountryIPFilter.exe`, []string{`C:\x\Country IP Filter.lnk`}, "4.0.2")
	for _, want := range []string{"UninstallString", `--uninstall`, "'DisplayVersion' -Value '4.0.2'", "CreateShortcut('C:\\x\\Country IP Filter.lnk')"} {
		if !strings.Contains(in, want) {
			t.Fatalf("install script lacks %s", want)
		}
	}
}

// The setup is one file: both guides are built in and are real pages.
func TestGuidesBuiltIn(t *testing.T) {
	g := guides()
	for _, n := range []string{"Guide.html", "Guide-fa.html"} {
		if !strings.Contains(string(g[n]), "</html>") {
			t.Errorf("%s not built in", n)
		}
	}
}

// A RIPEstat answer must carry a recent date.
func TestRIPEListDate(t *testing.T) {
	now := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return now }
	defer func() { timeNow = time.Now }()
	mk := func(qt string) []byte {
		return []byte(`{"data":{"query_time":"` + qt + `","resources":{"ipv4":["2.144.0.0/14"]}}}`)
	}
	for _, ok := range []string{"2026-10-01T00:00:00", "2026-09-06T08:00:01", "2026-10-01T00:00:00Z", "2026-10-06T00:00:00"} {
		if _, err := parseRIPE(mk(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"2026-08-01T00:00:00", "2026-10-09T00:00:00", "", "yesterday"} {
		if _, err := parseRIPE(mk(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := parseRIPE([]byte(`{"data":{"resources":{"ipv4":["2.144.0.0/14"]}}}`)); err == nil {
		t.Error("no date accepted")
	}
}
