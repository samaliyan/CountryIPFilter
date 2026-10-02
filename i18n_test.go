package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

var (
	reCall    = regexp.MustCompile(`(?:\bT\(|a\.log\(|a\.step\()\s*("(?:[^"\\\n]|\\.)*")`)
	reLiteral = regexp.MustCompile("\"(?:[^\"\\\\\\n]|\\\\.)*\"|`[^`]*`")
	reVerb    = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z%]`)
)

func persian(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Arabic, r) {
			return true
		}
	}
	return false
}

func sourceFiles(t *testing.T) map[string]string {
	files, _ := filepath.Glob("*.go")
	out := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "i18n.go" || f == "countries.go" || f == "collate.go" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[f] = string(b)
	}
	return out
}

// Every Persian text shown to the user has an English version with the
// same placeholders.
func TestEveryTextTranslated(t *testing.T) {
	for f, src := range sourceFiles(t) {
		for _, m := range reCall.FindAllStringSubmatch(src, -1) {
			fa, err := strconv.Unquote(m[1])
			if err != nil || !persian(fa) {
				continue
			}
			en, ok := english[fa]
			if !ok {
				t.Errorf("%s: no English for %q", f, fa)
				continue
			}
			if persian(en) {
				t.Errorf("%s: English text still has Persian: %q", f, en)
			}
			if a, b := reVerb.FindAllString(fa, -1), reVerb.FindAllString(en, -1); strings.Join(a, " ") != strings.Join(b, " ") {
				t.Errorf("%s: placeholders differ: %q vs %q", f, fa, en)
			}
		}
	}
	for _, k := range []string{MainOn, MainOff, MainFix, MainCheck, GreenState, OpenState, FwOpenState, ShutState, GPState, SomeIPsState, ClosedState, UnknownState, vpnNote, yesWord, support} {
		if _, ok := english[k]; !ok {
			t.Errorf("no English for %q", k)
		}
	}
}

// go test -run TestListMissing with MISSING=file writes the texts that have no English yet.
func TestListMissing(t *testing.T) {
	out := os.Getenv("MISSING")
	if out == "" {
		t.Skip()
	}
	used := map[string]bool{}
	var missing []string
	for _, src := range sourceFiles(t) {
		for _, m := range reCall.FindAllStringSubmatch(src, -1) {
			fa, err := strconv.Unquote(m[1])
			if err != nil || !persian(fa) {
				continue
			}
			used[fa] = true
			if _, ok := english[fa]; !ok && !containsStr(missing, fa) {
				missing = append(missing, fa)
			}
		}
	}
	for _, k := range []string{MainOn, MainOff, MainFix, MainCheck, GreenState, OpenState, FwOpenState, ShutState, GPState, SomeIPsState, ClosedState, UnknownState, vpnNote, yesWord, support} {
		used[k] = true
		if _, ok := english[k]; !ok && !containsStr(missing, k) {
			missing = append(missing, k)
		}
	}
	var unused []string
	for k := range english {
		if !used[k] {
			unused = append(unused, k)
		}
	}
	b, _ := json.MarshalIndent(map[string][]string{"missing": missing, "unused": unused}, "", " ")
	os.WriteFile(out, b, 0o644)
}

// No Persian text reaches the user without going through T().
func TestNoLoosePersian(t *testing.T) {
	ok := regexp.MustCompile(`(\bT\(|a\.log\(|a\.step\(|langName = |^\s*(MainOn|MainOff|MainFix|MainCheck|GreenState|OpenState|FwOpenState|ShutState|GPState|SomeIPsState|ClosedState|UnknownState|vpnNote|yesWord|support)\s*=)\s*$`)
	for f, src := range sourceFiles(t) {
		for _, loc := range reLiteral.FindAllStringIndex(src, -1) {
			lit := src[loc[0]:loc[1]]
			if !persian(lit) {
				continue
			}
			lineStart := strings.LastIndex(src[:loc[0]], "\n") + 1
			line := src[lineStart:]
			if i := strings.IndexByte(line, '\n'); i >= 0 {
				line = line[:i]
			}
			if ok.MatchString(src[lineStart:loc[0]]) || strings.Contains(line, "NewReplacer") || strings.HasPrefix(strings.TrimSpace(line), `"٠", "0"`) {
				continue
			}
			t.Errorf("%s:%d: Persian text without T(): %s", f, strings.Count(src[:loc[0]], "\n")+1, lit)
		}
	}
}

// Running the program in English never shows Persian.
func TestEnglishScreens(t *testing.T) {
	lang = "en"
	defer func() { lang = "fa" }()
	var seen []string
	check := func(where string, texts ...string) {
		for _, s := range texts {
			if persian(s) {
				t.Errorf("%s shows Persian: %q", where, s)
			}
			seen = append(seen, s)
		}
	}
	look := func(ui *fakeUI) {
		v := ui.view
		check("view", v.Title, v.Desc, v.Info, T(v.Main))
		for _, r := range v.Rows {
			check("row", T(r.State), r.Item, r.Service)
		}
		for _, c := range v.Countries {
			check("country", countryLabelPlain(c))
		}
		for _, p := range v.Problems {
			check("problem", p.Text, p.Button, p.Step)
		}
		check("ask", ui.asked...)
		check("tell", ui.told...)
		check("log", ui.logs...)
	}
	exe := filepath.Join(t.TempDir(), "srv.exe")
	os.WriteFile(exe, nil, 0o644)
	// a full day: an old version, off, on, problems, fixes, ports, countries, off again
	fw := &fakeFW{fwOff: true, listen: map[int]string{3389: "System"}, others: []*fakeRule{
		{name: "wcf", display: "Net.TCP", source: "Local", open: true, enabled: true},
		{name: "all", display: "Everything", source: "Local", open: true, enabled: true, ports: "Any"},
		{name: "g", display: "From policy", source: "GroupPolicy", open: true, enabled: true},
		{name: "b", display: "Block", source: "Local", open: true, enabled: true, block: true, ports: "808"},
	}}
	c := newCore(t, fw)
	a, ui, _ := startApp(t, c, lists)
	look(ui)
	a.Main()
	look(ui)
	a.AddCountry("IR")
	a.AddPort("808", "TCP")
	a.Main()
	look(ui)
	a.Details()
	look(ui)
	fw.updateFail = true
	c.RunUpdate()
	fw.inboundOff = true
	a.Refresh()
	look(ui)
	a.Main()
	look(ui)
	for _, p := range ui.view.Problems {
		a.Fix(p)
		look(ui)
	}
	a.AddPort("abc", "TCP")
	a.AddPort("22", "TCP")
	a.AddPort("9000", "UDP")
	a.AddProgram(exe)
	a.AddProgram(`C:\Windows\System32\svchost.exe`)
	a.RemoveEntry("udp:9000")
	a.RemoveEntry("808")
	a.AddCountry("DE")
	a.RemoveCountry("DE")
	a.RemoveCountry("IR")
	look(ui)
	offline(t, c)
	a.Fix(Problem{Kind: FixUpdateList})
	a.Fix(Problem{Kind: FixManualList})
	look(ui)
	a.TurnOff()
	look(ui)
	fw.failStatus = true
	a.Refresh()
	look(ui)
	// the old version moved over
	fw2 := &fakeFW{old: []fakeOld{{name: "IranIPFilter-01", ports: []int{808}, addrs: []string{"5.1.0.0/16"}}}, oldTask: true}
	_, ui2, _ := startApp(t, newCore(t, fw2), lists)
	look(ui2)
	if len(seen) < 80 {
		t.Fatalf("too few texts checked: %d", len(seen))
	}
}
